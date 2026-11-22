import pytest
from django.db import connection
from django.test import Client
from django.utils import timezone

from mcod.aed.context import aed_user_id
from mcod.core.tests.fixtures import *  # noqa
from mcod.lib.jwt import get_auth_header
from mcod.users.factories import UserFactory
from mcod.users.models import UserTOTP

ORG_A = "00000000-0000-0000-0000-00000000000a"
ORG_B = "00000000-0000-0000-0000-00000000000b"
SITE_A1 = "00000000-0000-0000-0000-0000000000a1"
SITE_A2 = "00000000-0000-0000-0000-0000000000a2"


@pytest.fixture
def aed(test_password):
    """Podmioty A i B (aktywne) z administratorami; w A lokalizacje A1, A2 i edytor ograniczony do A1.

    Dane startowe z wyłączonymi triggerami (SET LOCAL session_replication_role = replica) – reguły
    rejestracji i nadawania ról mają własne testy po stronie SQL.
    """
    mc = UserFactory.create(email="mc@aed.test", password=test_password, state="active")
    admin_a = UserFactory.create(email="a@aed.test", password=test_password, state="active", is_gov_auth=True)
    admin_b = UserFactory.create(email="b@aed.test", password=test_password, state="active", is_gov_auth=True)
    editor_a = UserFactory.create(email="ed@aed.test", password=test_password, state="active")
    for user in (admin_a, admin_b):  # org_admin: 2FA (auth.has_mfa) i sesja login.gov.pl (JWT.md §9.2)
        UserTOTP.objects.create(user=user, secret="JBSWY3DPEHPK3PXP", confirmed_at=timezone.now())
        user.last_logged_method = "WK"
        user.save(update_fields=["last_logged_method"])
    users = {"mc": mc, "a": admin_a, "b": admin_b, "ed": editor_a}
    links = {key: aed_user_id(user) for key, user in users.items()}

    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL session_replication_role = replica")
        cursor.execute(
            "INSERT INTO org.organization (id, name, type, nip, status, verified_by, approved_by, approved_at) VALUES "
            "(%s, 'Podmiot A', 'public_unit', '1234563218', 'active', %s, %s, now()),"
            "(%s, 'Podmiot B', 'public_unit', '5260250274', 'active', %s, %s, now())",
            [ORG_A, links["a"], links["mc"], ORG_B, links["b"], links["mc"]],
        )
        cursor.execute(
            "INSERT INTO org.site (id, organization_id, name) VALUES (%s, %s, 'Szkoła 1'), (%s, %s, 'Szkoła 2')",
            [SITE_A1, ORG_A, SITE_A2, ORG_A],
        )
        cursor.execute(
            "INSERT INTO org.responsibility_statement (kind, version, body, valid_from) VALUES "
            "('registration', '1', 'reg', now() - interval '1 day'),"
            "('change_confirmation', '1', 'conf', now() - interval '1 day')"
        )
        cursor.execute(
            "INSERT INTO org.statement_acceptance (organization_id, statement_id, user_id) "
            "SELECT v.o, s.id, v.u FROM org.responsibility_statement s, "
            "(VALUES (%s::uuid, %s::uuid), (%s::uuid, %s::uuid)) v(o, u) WHERE s.kind = 'registration'",
            [ORG_A, links["a"], ORG_B, links["b"]],
        )
        cursor.execute(
            "INSERT INTO org.membership (user_id, organization_id, role, all_sites, granted_by) VALUES "
            "(%s, %s, 'org_admin', true, %s), (%s, %s, 'org_admin', true, %s), (%s, %s, 'org_editor', false, %s) "
            "RETURNING id, user_id",
            [links["a"], ORG_A, links["mc"], links["b"], ORG_B, links["mc"], links["ed"], ORG_A, links["a"]],
        )
        editor_membership = [row[0] for row in cursor.fetchall() if row[1] == links["ed"]][0]
        cursor.execute(
            "INSERT INTO org.membership_site (membership_id, organization_id, site_id) VALUES (%s, %s, %s)",
            [editor_membership, ORG_A, SITE_A1],
        )
        cursor.execute("SELECT id FROM org.responsibility_statement WHERE kind = 'change_confirmation'")
        statement_id = cursor.fetchone()[0]
        cursor.execute("SET LOCAL session_replication_role = origin")
    return {"users": users, "links": links, "statement_id": statement_id, "editor_membership": editor_membership}


@pytest.fixture
def auth_header():
    """Nagłówek Authorization z sesją portalu (Redis) dla użytkownika."""

    def make(user):
        client = Client()
        client.force_login(user)
        return get_auth_header(user, client.session.session_key)

    return make
