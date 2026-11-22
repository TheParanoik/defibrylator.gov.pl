"""Kontekst podmiotu i izolacja podmiotów w API modułu AED (JWT.md §6–§8, ROLES.md §8).

Zasady:
  * podmiot pochodzi WYŁĄCZNIE z kontekstu sesji (``POST /auth/aed/context``), nigdy z parametrów żądania;
  * kontekst = klucze w sesji Django (Redis) + wiersz w ``auth.session``. Triggery bazy odwołują ten wiersz
    przy każdej zmianie członkostwa, ról MC i statusu podmiotu (``auth.revoke_user_sessions``), więc
    odwołanie dostępu działa natychmiast – to zastępuje „epokę uprawnień” z JWT.md §8;
  * każde żądanie ponownie sprawdza w bazie: wiersz kontekstu, aktywne członkostwo (``org.member_role``),
    status podmiotu i bezczynność (30 min);
  * obiekty innego podmiotu → 404, brak kontekstu → 401 ``aed_context_required``, brak roli → 403.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import List, Optional
from uuid import UUID

import falcon
from django.conf import settings
from django.db import connection
from django.utils import timezone

from mcod.aed.api.errors import AedError, context_required
from mcod.aed.context import aed_user_id
from mcod.aed.models import Device, MembershipSite
from mcod.core.api.hooks import login_required
from mcod.users.models import LoggingMethod

SESSION_ID_KEY = "aed.session_id"
ORG_ID_KEY = "aed.org_id"
LAST_SEEN_KEY = "aed.last_seen"

IDLE_TIMEOUT = timedelta(minutes=getattr(settings, "AED_CONTEXT_IDLE_MINUTES", 30))
# JWT.md §9.2: org_admin działa tylko w sesji zalogowanej przez login.gov.pl
ROLE_LOGIN_METHOD = {"org_admin": "login_gov_pl"}


@dataclass
class AedRequestContext:
    user: object
    user_link_id: UUID
    organization_id: UUID
    org_role: str
    session_id: UUID
    all_sites: bool = True
    site_ids: List[UUID] = field(default_factory=list)

    @property
    def is_admin(self) -> bool:
        return self.org_role == "org_admin"

    def devices(self):
        """AED widoczne dla użytkownika: tylko bieżący podmiot, a dla edytora z zakresem – tylko jego lokalizacje."""
        qs = Device.objects.filter(owner_organization_id=self.organization_id)
        if not self.all_sites:
            qs = qs.filter(site_id__in=self.site_ids)
        return qs


def login_method(user) -> str:
    """Metoda logowania. Portal zapisuje ją na koncie, nie w sesji (zgłoszenie P1-2) – przybliżenie."""
    return "login_gov_pl" if user.last_logged_method == LoggingMethod.WK.value else "password"


def member_role(user_link_id: UUID, organization_id: UUID) -> Optional[str]:
    with connection.cursor() as cursor:
        cursor.execute("SELECT org.member_role(%s, %s)", [user_link_id, organization_id])
        return cursor.fetchone()[0]


def organization_status(organization_id: UUID) -> Optional[str]:
    with connection.cursor() as cursor:
        cursor.execute("SELECT status FROM org.organization WHERE id = %s", [organization_id])
        row = cursor.fetchone()
    return row[0] if row else None


def has_mfa(user_link_id: UUID) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT auth.has_mfa(%s, false)", [user_link_id])
        return bool(cursor.fetchone()[0])


def _now_iso() -> str:
    return datetime.now(dt_timezone.utc).isoformat()


def select_context(req, organization_id: Optional[UUID]) -> Optional[str]:
    """``POST /auth/aed/context``: sprawdza członkostwo i zapisuje kontekst. Zwraca rolę albo None (bez podmiotu)."""
    user = req.user
    link = aed_user_id(user)
    _revoke_current(req, "context_change")
    for key in (SESSION_ID_KEY, ORG_ID_KEY, LAST_SEEN_KEY):
        req.session.pop(key, None)
    if organization_id is None:
        req.session.save()
        return None

    role = member_role(link, organization_id)
    if role is None:
        req.session.save()
        raise AedError(403, "forbidden")
    if organization_status(organization_id) != "active":
        req.session.save()
        raise AedError(403, "organization_inactive")
    required = ROLE_LOGIN_METHOD.get(role)
    if required and login_method(user) != required:
        req.session.save()
        raise AedError(403, "login_method_required", meta={"login_method_required": required})

    aal = 2 if (login_method(user) == "login_gov_pl" or has_mfa(link)) else 1
    expires = timezone.now() + timedelta(seconds=int(settings.SESSION_COOKIE_AGE))
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO auth.session (user_id, portal_session_key, aal, absolute_expires_at, organization_id, org_role) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            [link, req.session.session_key, aal, expires, organization_id, role],
        )
        session_id = cursor.fetchone()[0]
    req.session[SESSION_ID_KEY] = str(session_id)
    req.session[ORG_ID_KEY] = str(organization_id)
    req.session[LAST_SEEN_KEY] = _now_iso()
    req.session.save()
    return role


def _revoke_current(req, reason: str) -> None:
    session_id = req.session.get(SESSION_ID_KEY)
    if session_id:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE auth.session SET revoked_at = now(), revoke_reason = %s WHERE id = %s AND revoked_at IS NULL",
                [reason, session_id],
            )


def load_context(req) -> Optional[AedRequestContext]:
    """Kontekst z sesji po weryfikacji w bazie albo None (nieważny / brak). Odświeża ``last_seen``."""
    session_id, org_id, last_seen = (req.session.get(k) for k in (SESSION_ID_KEY, ORG_ID_KEY, LAST_SEEN_KEY))
    if not (session_id and org_id and last_seen):
        return None
    try:
        if datetime.now(dt_timezone.utc) - datetime.fromisoformat(last_seen) > IDLE_TIMEOUT:
            return None
        session_id, org_id = UUID(session_id), UUID(org_id)
    except (TypeError, ValueError):
        return None

    link = aed_user_id(req.user)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT s.org_role FROM auth.session s "
            "WHERE s.id = %s AND s.user_id = %s AND s.organization_id = %s AND s.portal_session_key = %s "
            "AND s.revoked_at IS NULL AND s.absolute_expires_at > now()",
            [session_id, link, org_id, req.session.session_key],
        )
        row = cursor.fetchone()
    if row is None:
        return None
    role = member_role(link, org_id)
    if role is None or role != row[0] or organization_status(org_id) != "active":
        return None
    required = ROLE_LOGIN_METHOD.get(role)
    if required and login_method(req.user) != required:
        return None

    membership = req.user.aed_link.memberships.filter(organization_id=org_id, revoked_at__isnull=True).first()
    all_sites = True if membership is None else membership.all_sites
    site_ids = []
    if not all_sites:
        site_ids = list(MembershipSite.objects.filter(membership=membership).values_list("site_id", flat=True))

    req.session[LAST_SEEN_KEY] = _now_iso()
    req.session.save()
    return AedRequestContext(req.user, link, org_id, role, session_id, all_sites, site_ids)


def aed_context_required(req, resp, resource, params, admin=False):
    """Hook Falcon: logowanie portalu → kontekst podmiotu → (opcjonalnie) rola org_admin."""
    login_required(req, resp, resource, params)
    ctx = load_context(req)
    if ctx is None:
        raise context_required()
    if admin and not ctx.is_admin:
        raise AedError(403, "forbidden")
    req.context.aed = ctx
    resp.set_header("Cache-Control", "no-store")


def aed_login_required(req, resp, resource, params):
    """Hook Falcon: sesja portalu bez wymogu kontekstu (``/auth/aed/me``, ``/auth/aed/context``)."""
    login_required(req, resp, resource, params)
    resp.set_header("Cache-Control", "no-store")


def require_json_api(req):
    content_type = (req.content_type or "").split(";")[0].strip()
    if content_type not in ("application/vnd.api+json", "application/json"):
        raise AedError(415, "unsupported_media_type")


__all__ = ["AedRequestContext", "aed_context_required", "aed_login_required", "select_context", "falcon"]
