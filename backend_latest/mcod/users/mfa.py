"""Uwierzytelnianie dwuskładnikowe (2FA) aplikacją typu authenticator – TOTP (RFC 6238).

Dotyczy wyłącznie natywnego logowania portalu (e-mail + hasło: API ``/auth/login`` i formularz panelu
administracyjnego). Logowanie przez login.gov.pl ma własne uwierzytelnianie wieloskładnikowe po stronie
Węzła Krajowego i nie jest tu obsługiwane.

Zasady (na podstawie projektu ``sql/auth.sql`` i wymagań JWT.md Dodatek A modułu AED):

* sekret: 160 bitów losowych (RFC 4226 §4), Base32, przechowywany zaszyfrowany (``EncryptedCharField``);
* kod: 6 cyfr, HMAC-SHA1, krok 30 s, tolerancja ±1 krok (rozjazd zegarów);
* jednorazowość: kod z kroku ≤ ostatnio użytego jest odrzucany (atomowy ``UPDATE``) – przechwycony kod
  nie zadziała drugi raz;
* kody zapasowe: 10 kodów jednorazowych, w bazie tylko SHA-256 (kody mają ≥ 50 bitów entropii, więc
  wolny hash nie jest potrzebny), nowa paczka unieważnia poprzednią;
* administrator może wymusić 2FA na koncie (``User.mfa_required``); konto z wymogiem bez skonfigurowanej
  aplikacji musi ją skonfigurować przy najbliższym logowaniu, zanim dostanie sesję.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import struct
import time
from typing import List, Optional
from urllib.parse import quote, urlencode

from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("mcod")

TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # akceptowane kroki: bieżący ±1
SECRET_BYTES = 20  # 160 bitów
RECOVERY_CODES_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # bez 0/o, 1/l/i – łatwiejsze przepisywanie


# ---------------------------------------------------------------------------
#  Algorytm (bez bazy danych)
# ---------------------------------------------------------------------------


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _secret_bytes(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def current_step(now: Optional[float] = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def hotp(secret: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    """RFC 4226 – kod dla licznika (w TOTP licznik = numer kroku czasu)."""
    digest = hmac.new(_secret_bytes(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def normalize_otp(code: Optional[str]) -> str:
    return "".join((code or "").split())


def is_totp_format(code: str) -> bool:
    return len(code) == TOTP_DIGITS and code.isdigit()


def match_totp_step(secret: str, code: str, now: Optional[float] = None, window: int = TOTP_WINDOW) -> Optional[int]:
    """Zwraca krok czasu, dla którego kod jest poprawny, albo None. Porównanie w stałym czasie."""
    code = normalize_otp(code)
    if not is_totp_format(code):
        return None
    step = current_step(now)
    matched = None
    for candidate in range(step - window, step + window + 1):
        if hmac.compare_digest(hotp(secret, candidate), code):
            matched = candidate
    return matched


def provisioning_uri(secret: str, account: str, issuer: Optional[str] = None) -> str:
    """URI ``otpauth://`` (format Key Uri) do kodu QR w aplikacji uwierzytelniającej."""
    issuer = issuer or getattr(settings, "MFA_TOTP_ISSUER", "dane.gov.pl")
    label = quote(f"{issuer}:{account}", safe="@:")
    params = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": TOTP_DIGITS, "period": TOTP_PERIOD})
    return f"otpauth://totp/{label}?{params}"


def qr_svg(data: str) -> Optional[str]:
    """Kod QR jako SVG (biblioteka segno). Brak biblioteki → None, klient pokazuje sekret do wpisania."""
    try:
        import segno
    except ImportError:  # pragma: no cover - zależność opcjonalna w środowiskach bez przebudowy
        logger.warning("segno not installed - MFA setup without QR code")
        return None
    return segno.make(data, error="m").svg_inline(scale=5, border=2)


def generate_recovery_codes(count: int = RECOVERY_CODES_COUNT) -> List[str]:
    """Kody w postaci ``xxxxx-xxxxx`` (10 znaków z 31 → ~49,5 bitu entropii)."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_recovery_code(code: Optional[str]) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii", "ignore")).hexdigest()


# ---------------------------------------------------------------------------
#  Wyjątki
# ---------------------------------------------------------------------------


class MfaError(Exception):
    """Błąd drugiego składnika. ``code`` trafia do odpowiedzi API (``errors[].code``)."""

    code = "mfa_error"


class MfaRequired(MfaError):
    code = "mfa_required"  # konto ma 2FA – podaj kod z aplikacji albo kod zapasowy


class MfaSetupRequired(MfaError):
    code = "mfa_setup_required"  # administrator wymusił 2FA, a konto nie ma skonfigurowanej aplikacji


class MfaInvalidCode(MfaError):
    code = "mfa_invalid_code"


class MfaNotAllowed(MfaError):
    code = "mfa_not_allowed"  # np. wyłączenie 2FA na koncie z wymogiem administratora


class MfaSetupNotStarted(MfaError):
    code = "mfa_setup_not_started"


# ---------------------------------------------------------------------------
#  Operacje na koncie
# ---------------------------------------------------------------------------


def _models():
    from mcod.users.models import RecoveryCode, UserTOTP

    return UserTOTP, RecoveryCode


def get_confirmed_totp(user):
    UserTOTP, _ = _models()
    return UserTOTP.objects.filter(user=user, confirmed_at__isnull=False).first()


def is_enabled(user) -> bool:
    return get_confirmed_totp(user) is not None


def recovery_codes_left(user) -> int:
    _, RecoveryCode = _models()
    return RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()


def start_enrollment(user) -> dict:
    """Nowy sekret (niepotwierdzony). Zastępuje poprzednią niedokończoną konfigurację.

    Dla konta z aktywnym 2FA → ``MfaNotAllowed`` (najpierw wyłączenie albo reset przez administratora).
    """
    UserTOTP, _ = _models()
    if is_enabled(user):
        raise MfaNotAllowed()
    secret = generate_secret()
    UserTOTP.objects.filter(user=user, confirmed_at__isnull=True).delete()
    UserTOTP.objects.create(user=user, secret=secret)
    uri = provisioning_uri(secret, user.email)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}


@transaction.atomic
def confirm_enrollment(user, code: str) -> List[str]:
    """Potwierdza konfigurację kodem z aplikacji. Zwraca nowe kody zapasowe (pokazywane raz)."""
    UserTOTP, _ = _models()
    totp = UserTOTP.objects.select_for_update().filter(user=user, confirmed_at__isnull=True).first()
    if totp is None:
        raise MfaSetupNotStarted()
    step = match_totp_step(totp.secret, code)
    if step is None:
        raise MfaInvalidCode()
    totp.confirmed_at = timezone.now()
    totp.last_used_step = step
    totp.save(update_fields=["confirmed_at", "last_used_step"])
    codes = replace_recovery_codes(user)
    logger.info("MFA enabled for user id=%s", user.pk)
    return codes


def replace_recovery_codes(user) -> List[str]:
    _, RecoveryCode = _models()
    codes = generate_recovery_codes()
    with transaction.atomic():
        RecoveryCode.objects.filter(user=user).delete()
        RecoveryCode.objects.bulk_create([RecoveryCode(user=user, code_hash=hash_recovery_code(c)) for c in codes])
    return codes


def _use_totp(user, code: str) -> bool:
    UserTOTP, _ = _models()
    totp = get_confirmed_totp(user)
    if totp is None:
        return False
    step = match_totp_step(totp.secret, code)
    if step is None:
        return False
    # jednorazowość: tylko krok nowszy niż ostatnio użyty; atomowo, bez wyścigu dwóch równoległych logowań
    from django.db.models import Q

    updated = (
        UserTOTP.objects.filter(pk=totp.pk)
        .filter(Q(last_used_step__isnull=True) | Q(last_used_step__lt=step))
        .update(last_used_step=step)
    )
    return updated == 1


def _use_recovery_code(user, code: str) -> bool:
    _, RecoveryCode = _models()
    normalized = normalize_recovery_code(code)
    if len(normalized) != 10:
        return False
    updated = RecoveryCode.objects.filter(user=user, code_hash=hash_recovery_code(normalized), used_at__isnull=True).update(
        used_at=timezone.now()
    )
    if updated:
        logger.info("MFA recovery code used by user id=%s", user.pk)
    return updated == 1


def verify_second_factor(user, code: Optional[str]) -> bool:
    """Kod z aplikacji albo kod zapasowy. Każdy działa jeden raz."""
    code = (code or "").strip()
    if not code:
        return False
    normalized = normalize_otp(code)
    if is_totp_format(normalized):
        return _use_totp(user, normalized)
    return _use_recovery_code(user, code)


def check_login(user, code: Optional[str]) -> None:
    """Drugi składnik przy logowaniu hasłem – wywołać PO poprawnym haśle, PRZED utworzeniem sesji.

    * konto z 2FA bez kodu → ``MfaRequired``; ze złym kodem → ``MfaInvalidCode``;
    * konto z wymogiem administratora bez skonfigurowanej aplikacji → ``MfaSetupRequired``;
    * pozostałe konta – bez zmian.
    """
    if is_enabled(user):
        if not (code or "").strip():
            raise MfaRequired()
        if not verify_second_factor(user, code):
            raise MfaInvalidCode()
        return
    if is_required(user):
        raise MfaSetupRequired()


def is_required(user) -> bool:
    return bool(getattr(user, "mfa_required", False)) or (
        bool(getattr(settings, "MFA_REQUIRED_FOR_SUPERUSERS", False)) and bool(getattr(user, "is_superuser", False))
    )


@transaction.atomic
def disable(user, code: str) -> None:
    """Wyłączenie przez użytkownika – wymaga ważnego drugiego składnika; niedozwolone przy wymogu."""
    if is_required(user):
        raise MfaNotAllowed()
    if not is_enabled(user):
        return
    if not verify_second_factor(user, code):
        raise MfaInvalidCode()
    _delete_all(user)
    logger.info("MFA disabled by user id=%s", user.pk)


def admin_reset(user) -> bool:
    """Reset przez administratora (utrata telefonu). Przy wymogu konto skonfiguruje 2FA przy logowaniu.

    Zwraca True, gdy było co usunąć.
    """
    deleted = _delete_all(user)
    if deleted:
        logger.info("MFA reset by administrator for user id=%s", user.pk)
    return deleted


def _delete_all(user) -> bool:
    UserTOTP, RecoveryCode = _models()
    totp_deleted, _ = UserTOTP.objects.filter(user=user).delete()
    codes_deleted, _ = RecoveryCode.objects.filter(user=user).delete()
    return bool(totp_deleted or codes_deleted)


def status(user) -> dict:
    totp = get_confirmed_totp(user)
    return {
        "enabled": totp is not None,
        "required": is_required(user),
        "confirmed_at": totp.confirmed_at if totp else None,
        "recovery_codes_left": recovery_codes_left(user) if totp else 0,
    }
