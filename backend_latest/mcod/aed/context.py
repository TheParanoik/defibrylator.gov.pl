"""Kontekst transakcji modułu AED.

Triggery i funkcje bazy (``sql/aed.sql``) ustalają autora, podmiot i uprawnienia z ustawień transakcji
``app.user_id``, ``app.org_id``, ``app.session_id``, ``app.actor_role``, ``app.client_ip`` (zawsze LOCAL –
JWT.md §7). Każdy zapis do modułu musi więc iść w ``aed_context``::

    with aed_context(request.user, organization_id=org.id, client_ip=ip) as user_link_id:
        DeviceVersion.objects.create(...)

Ustawienia LOCAL znikają z końcem transakcji, więc kontekst nie „wycieka” na kolejne żądania
korzystające z tego samego połączenia.
"""

from contextlib import contextmanager
from typing import Optional
from uuid import UUID

from django.db import connection, transaction


def aed_user_id(user) -> UUID:
    """UUID użytkownika w module (auth.user_link) dla konta portalu; tworzy powiązanie przy pierwszym użyciu."""
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO auth.user_link (portal_user_id) VALUES (%s) ON CONFLICT (portal_user_id) DO NOTHING",
            [user.pk],
        )
        cursor.execute("SELECT id FROM auth.user_link WHERE portal_user_id = %s", [user.pk])
        return cursor.fetchone()[0]


def set_context(
    user_link_id: Optional[UUID],
    organization_id: Optional[UUID] = None,
    session_id: Optional[UUID] = None,
    actor_role: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> None:
    """SET LOCAL kontekstu w bieżącej transakcji (wymaga otwartej transakcji)."""
    if connection.get_autocommit():
        raise RuntimeError("AED context requires a transaction (use aed_context or transaction.atomic)")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('app.user_id', %s, true), set_config('app.org_id', %s, true), "
            "set_config('app.session_id', %s, true), set_config('app.actor_role', %s, true), "
            "set_config('app.client_ip', %s, true)",
            [
                str(user_link_id) if user_link_id else "",
                str(organization_id) if organization_id else "",
                str(session_id) if session_id else "",
                actor_role or "",
                client_ip or "",
            ],
        )


@contextmanager
def aed_context(
    user,
    organization_id: Optional[UUID] = None,
    session_id: Optional[UUID] = None,
    actor_role: Optional[str] = None,
    client_ip: Optional[str] = None,
):
    """Transakcja z kontekstem użytkownika portalu (i opcjonalnie podmiotu). Zwraca UUID użytkownika w module."""
    with transaction.atomic():
        user_link_id = aed_user_id(user) if user is not None else None
        set_context(user_link_id, organization_id, session_id, actor_role, client_ip)
        yield user_link_id
