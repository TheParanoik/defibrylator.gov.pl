"""Testy 2FA (TOTP) w logowaniu e-mail + hasło – mcod.users.mfa."""

import falcon
import pytest
from django.conf import settings
from django.test import RequestFactory, override_settings
from django.urls import reverse

from mcod.users import mfa
from mcod.users.forms import AdminLoginForm
from mcod.users.models import RecoveryCode, UserTOTP

# RFC 6238, dodatek B: sekret ASCII "12345678901234567890" (SHA-1)
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _code(secret, offset=0):
    return mfa.hotp(secret, mfa.current_step() + offset)


def _enable(user):
    mfa.start_enrollment(user)
    secret = UserTOTP.objects.get(user=user).secret
    codes = mfa.confirm_enrollment(user, _code(secret, -1))
    return secret, codes


# ---------------------------------------------------------------------------
#  Algorytm
# ---------------------------------------------------------------------------


class TestTotpAlgorithm:
    @pytest.mark.parametrize(
        "unix_time, expected",
        [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")],
    )
    def test_rfc6238_vectors(self, unix_time, expected):
        assert mfa.hotp(RFC_SECRET, mfa.current_step(unix_time), digits=8) == expected

    def test_six_digit_code_and_window(self):
        now = 1111111109
        code = mfa.hotp(RFC_SECRET, mfa.current_step(now))
        assert len(code) == 6
        assert mfa.match_totp_step(RFC_SECRET, code, now=now) == mfa.current_step(now)
        assert mfa.match_totp_step(RFC_SECRET, code, now=now + 30) == mfa.current_step(now)  # +1 krok
        assert mfa.match_totp_step(RFC_SECRET, code, now=now + 90) is None  # poza oknem

    @pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", None])
    def test_rejects_malformed_codes(self, bad):
        assert mfa.match_totp_step(RFC_SECRET, bad) is None

    def test_code_with_spaces_is_accepted(self):
        now = 1234567890
        code = mfa.hotp(RFC_SECRET, mfa.current_step(now))
        assert mfa.match_totp_step(RFC_SECRET, f"{code[:3]} {code[3:]}", now=now) is not None

    def test_generated_secret_is_160_bits_base32(self):
        secret = mfa.generate_secret()
        assert len(secret) == 32 and secret.isalnum() and secret.upper() == secret
        assert mfa.generate_secret() != secret

    def test_provisioning_uri(self):
        uri = mfa.provisioning_uri("ABC", "jan@example.com", issuer="dane.gov.pl")
        assert uri.startswith("otpauth://totp/dane.gov.pl:jan@example.com?")
        assert "secret=ABC" in uri and "issuer=dane.gov.pl" in uri and "digits=6" in uri and "period=30" in uri

    def test_recovery_codes(self):
        codes = mfa.generate_recovery_codes()
        assert len(codes) == 10 and len(set(codes)) == 10
        assert all(len(c) == 11 and c[5] == "-" for c in codes)
        assert mfa.hash_recovery_code(codes[0].upper().replace("-", " ")) == mfa.hash_recovery_code(codes[0])


# ---------------------------------------------------------------------------
#  Konto (baza danych)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestMfaAccount:
    def test_account_without_mfa_logs_in_without_code(self, active_user):
        mfa.check_login(active_user, None)  # brak wyjątku

    def test_enrollment_requires_valid_code(self, active_user):
        setup = mfa.start_enrollment(active_user)
        assert setup["secret"] and setup["otpauth_uri"].startswith("otpauth://totp/")
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.confirm_enrollment(active_user, "000000" if _code(setup["secret"]) != "000000" else "111111")
        assert not mfa.is_enabled(active_user)

    def test_secret_is_encrypted_at_rest(self, active_user):
        from django.db import connection

        setup = mfa.start_enrollment(active_user)
        with connection.cursor() as cursor:
            cursor.execute("SELECT secret FROM user_totp WHERE user_id = %s", [active_user.id])
            raw = cursor.fetchone()[0]
        assert setup["secret"] not in str(raw)

    def test_login_requires_code_once_enabled(self, active_user):
        secret, _ = _enable(active_user)
        with pytest.raises(mfa.MfaRequired):
            mfa.check_login(active_user, None)
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.check_login(active_user, "12")
        mfa.check_login(active_user, _code(secret))

    def test_totp_code_cannot_be_replayed(self, active_user):
        secret, _ = _enable(active_user)
        code = _code(secret)
        mfa.check_login(active_user, code)
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.check_login(active_user, code)
        with pytest.raises(mfa.MfaInvalidCode):  # krok starszy niż ostatnio użyty
            mfa.check_login(active_user, _code(secret, -1))

    def test_recovery_code_works_once(self, active_user):
        _, codes = _enable(active_user)
        assert RecoveryCode.objects.filter(user=active_user).count() == 10
        assert codes[0] not in "".join(RecoveryCode.objects.values_list("code_hash", flat=True))
        mfa.check_login(active_user, codes[0].upper())
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.check_login(active_user, codes[0])
        assert mfa.status(active_user)["recovery_codes_left"] == 9

    def test_new_recovery_codes_invalidate_old_ones(self, active_user):
        _, old = _enable(active_user)
        mfa.replace_recovery_codes(active_user)
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.check_login(active_user, old[1])

    def test_required_without_app_needs_setup(self, active_user):
        active_user.mfa_required = True
        active_user.save()
        with pytest.raises(mfa.MfaSetupRequired):
            mfa.check_login(active_user, None)

    @override_settings(MFA_REQUIRED_FOR_SUPERUSERS=True)
    def test_superusers_can_be_required_globally(self, admin):
        assert mfa.is_required(admin)

    def test_cannot_disable_when_required(self, active_user):
        secret, _ = _enable(active_user)
        active_user.mfa_required = True
        active_user.save()
        with pytest.raises(mfa.MfaNotAllowed):
            mfa.disable(active_user, _code(secret))
        assert mfa.is_enabled(active_user)

    def test_disable_requires_valid_code(self, active_user):
        secret, _ = _enable(active_user)
        with pytest.raises(mfa.MfaInvalidCode):
            mfa.disable(active_user, "abc")
        mfa.disable(active_user, _code(secret))
        assert not mfa.is_enabled(active_user)
        assert not RecoveryCode.objects.filter(user=active_user).exists()

    def test_cannot_start_new_setup_while_enabled(self, active_user):
        _enable(active_user)
        with pytest.raises(mfa.MfaNotAllowed):
            mfa.start_enrollment(active_user)

    def test_admin_reset(self, active_user):
        _enable(active_user)
        assert mfa.admin_reset(active_user) is True
        assert not mfa.is_enabled(active_user)
        assert mfa.admin_reset(active_user) is False


# ---------------------------------------------------------------------------
#  API /auth/login i /auth/user/mfa
# ---------------------------------------------------------------------------


def _login_payload(email, password, otp_code=None):
    attrs = {"email": email, "password": password}
    if otp_code is not None:
        attrs["otp_code"] = otp_code
    return {"data": {"type": "user", "attributes": attrs}}


def _error_code(resp):
    return resp.json["errors"][0]["code"]


@pytest.mark.django_db
@pytest.mark.depends_on_component
@pytest.mark.component_api
class TestMfaLoginApi:
    def test_login_without_mfa_unchanged(self, client14, active_user, test_password):
        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password))
        assert resp.status == falcon.HTTP_201, resp.json
        assert resp.json["data"]["attributes"]["token"]

    def test_wrong_password_does_not_reveal_mfa(self, client14, active_user):
        _enable(active_user)
        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, "wrong-password-123!"))
        assert resp.status == falcon.HTTP_401

    def test_login_with_mfa(self, client14, active_user, test_password):
        secret, _ = _enable(active_user)

        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password))
        assert resp.status == falcon.HTTP_403
        assert _error_code(resp) == "mfa_required"
        assert "token" not in resp.text

        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password, "000000x"))
        assert resp.status == falcon.HTTP_403
        assert _error_code(resp) == "mfa_invalid_code"

        code = _code(secret)
        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password, code))
        assert resp.status == falcon.HTTP_201, resp.json
        assert resp.json["data"]["attributes"]["token"]

        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password, code))
        assert _error_code(resp) == "mfa_invalid_code"  # ten sam kod drugi raz

    def test_api_10_keeps_error_code(self, client, active_user, test_password):
        _enable(active_user)
        resp = client.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password))
        assert resp.status == falcon.HTTP_403
        assert resp.json["code"] == "mfa_required"

    def test_forced_setup_flow(self, client14, active_user, test_password):
        active_user.mfa_required = True
        active_user.save()

        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password))
        assert _error_code(resp) == "mfa_setup_required"

        resp = client14.simulate_post("/auth/login/mfa/setup", json=_login_payload(active_user.email, test_password))
        assert resp.status == falcon.HTTP_201, resp.json
        attrs = resp.json["data"]["attributes"]
        secret = attrs["secret"]
        assert attrs["otpauth_uri"].startswith("otpauth://totp/")
        assert attrs["required"] is True and attrs["enabled"] is False

        resp = client14.simulate_post(
            "/auth/login/mfa/confirm", json=_login_payload(active_user.email, test_password, _code(secret))
        )
        assert resp.status == falcon.HTTP_201, resp.json
        attrs = resp.json["data"]["attributes"]
        assert attrs["token"] and len(attrs["recovery_codes"]) == 10

        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password, _code(secret, 1)))
        assert resp.status == falcon.HTTP_201, resp.json

    def test_setup_before_login_only_for_required_accounts(self, client14, active_user, test_password):
        resp = client14.simulate_post("/auth/login/mfa/setup", json=_login_payload(active_user.email, test_password))
        assert resp.status == falcon.HTTP_403
        assert _error_code(resp) == "mfa_not_allowed"

    def test_setup_before_login_requires_password(self, client14, active_user):
        active_user.mfa_required = True
        active_user.save()
        resp = client14.simulate_post("/auth/login/mfa/setup", json=_login_payload(active_user.email, "bad-pass-123!"))
        assert resp.status == falcon.HTTP_401
        assert not UserTOTP.objects.filter(user=active_user).exists()

    def test_account_self_service(self, client14, active_user, test_password):
        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password))
        headers = {"Authorization": f"{settings.JWT_HEADER_PREFIX} {resp.json['data']['attributes']['token']}"}

        resp = client14.simulate_get("/auth/user/mfa", headers=headers)
        assert resp.status == falcon.HTTP_200, resp.json
        assert resp.json["data"]["attributes"]["enabled"] is False

        resp = client14.simulate_post("/auth/user/mfa/setup", headers=headers)
        assert resp.status == falcon.HTTP_201, resp.json
        secret = resp.json["data"]["attributes"]["secret"]

        body = {"data": {"type": "mfa", "attributes": {"otp_code": _code(secret)}}}
        resp = client14.simulate_post("/auth/user/mfa/confirm", headers=headers, json=body)
        assert resp.status == falcon.HTTP_201, resp.json
        assert resp.json["data"]["attributes"]["enabled"] is True
        codes = resp.json["data"]["attributes"]["recovery_codes"]

        body = {"data": {"type": "mfa", "attributes": {"otp_code": codes[0]}}}
        resp = client14.simulate_post("/auth/user/mfa/recovery-codes", headers=headers, json=body)
        assert resp.status == falcon.HTTP_201, resp.json
        new_codes = resp.json["data"]["attributes"]["recovery_codes"]
        assert set(new_codes).isdisjoint(codes)

        body = {"data": {"type": "mfa", "attributes": {"otp_code": new_codes[0], "password": "bad-pass-123!"}}}
        resp = client14.simulate_post("/auth/user/mfa/disable", headers=headers, json=body)
        assert resp.status == falcon.HTTP_422

        body = {"data": {"type": "mfa", "attributes": {"otp_code": new_codes[0], "password": test_password}}}
        resp = client14.simulate_post("/auth/user/mfa/disable", headers=headers, json=body)
        assert resp.status == falcon.HTTP_201, resp.json
        assert resp.json["data"]["attributes"]["enabled"] is False

    def test_required_account_cannot_disable(self, client14, active_user, test_password):
        secret, codes = _enable(active_user)
        active_user.mfa_required = True
        active_user.save()
        resp = client14.simulate_post("/auth/login", json=_login_payload(active_user.email, test_password, _code(secret)))
        headers = {"Authorization": f"{settings.JWT_HEADER_PREFIX} {resp.json['data']['attributes']['token']}"}
        body = {"data": {"type": "mfa", "attributes": {"otp_code": codes[0], "password": test_password}}}
        resp = client14.simulate_post("/auth/user/mfa/disable", headers=headers, json=body)
        assert resp.status == falcon.HTTP_403
        assert _error_code(resp) == "mfa_not_allowed"


# ---------------------------------------------------------------------------
#  Panel administracyjny
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAdminLoginMfa:
    def _form(self, user, password, otp_code=""):
        request = RequestFactory().post("/login/")
        request.session = {}
        return AdminLoginForm(request, data={"username": user.email, "password": password, "otp_code": otp_code})

    def test_admin_without_mfa(self, admin, test_password):
        assert self._form(admin, test_password).is_valid()

    def test_admin_with_mfa_needs_code(self, admin, test_password):
        secret, _ = _enable(admin)
        form = self._form(admin, test_password)
        assert not form.is_valid()
        assert form.non_field_errors().as_data()[0].code == "mfa_required"
        form = self._form(admin, test_password, "999999" if _code(secret) != "999999" else "888888")
        assert not form.is_valid()
        assert form.non_field_errors().as_data()[0].code == "mfa_invalid_code"
        form = self._form(admin, test_password, _code(secret))
        assert form.is_valid(), form.errors
        assert form.get_user() == admin

    def test_required_admin_without_app_is_blocked(self, admin, test_password):
        admin.mfa_required = True
        admin.save()
        form = self._form(admin, test_password)
        assert not form.is_valid()
        assert form.non_field_errors().as_data()[0].code == "mfa_setup_required"
        assert form.get_user() is None


@pytest.mark.django_db
class TestAdminActions:
    def test_require_and_reset(self, django_admin_client, active_user):
        url = reverse("admin:users_user_changelist")
        resp = django_admin_client.post(url, {"action": "require_mfa", "_selected_action": [active_user.pk]}, follow=True)
        assert resp.status_code == 200
        active_user.refresh_from_db()
        assert active_user.mfa_required is True

        _enable(active_user)
        django_admin_client.post(url, {"action": "reset_mfa", "_selected_action": [active_user.pk]})
        assert not mfa.is_enabled(active_user)
