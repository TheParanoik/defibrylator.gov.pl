"""Operacje modułu AED na bazie – cienka warstwa nad triggerami i funkcjami SQL.

Wszystkie funkcje wymagają kontekstu (``mcod.aed.context.aed_context``) – reguły uprawnień, autora,
łańcucha skrótów i deduplikacji egzekwuje baza; błąd reguły to ``django.db.Error`` z kodem SQLSTATE
(np. 42501 – brak uprawnień, 23505 – duplikat, 22023 – niedozwolona operacja).
"""

from typing import List, Optional
from uuid import UUID

from django.db import connection
from django.utils import timezone

from mcod.aed.models import Device, DeviceVersion, ResponsibilityStatement


def current_statement(kind: str) -> ResponsibilityStatement:
    """Aktualna treść oświadczenia (ROLES.md §13) – najnowsza z valid_from ≤ teraz."""
    return ResponsibilityStatement.objects.filter(kind=kind, valid_from__lte=timezone.now()).latest("valid_from")


def save_device_version(
    feature: dict,
    user_link_id: UUID,
    organization_id: UUID,
    device_id: Optional[str] = None,
    site_id: Optional[UUID] = None,
    import_batch_id: Optional[int] = None,
    statement: Optional[ResponsibilityStatement] = None,
) -> Device:
    """Nowa wersja danych AED (utworzenie, gdy ``device_id`` jest None). Zwraca bieżący stan AED.

    Autor, rola, numer wersji, skróty i stan ``Device`` / ``DeviceKey`` ustala trigger aed.apply_version().
    """
    statement = statement or current_statement("change_confirmation")
    version = DeviceVersion(
        device_id=device_id,
        site_id=site_id,
        data=feature,
        author_user_id=user_link_id,
        author_organization_id=organization_id,
        confirmation_statement=statement,
        confirmed_at=timezone.now(),
        import_batch_id=import_batch_id,
    )
    version.save()
    version = DeviceVersion.objects.get(pk=version.pk)
    return Device.objects.get(pk=version.device_id)


def match_device_keys(manufacturer: Optional[str], serial: Optional[str], external_id: Optional[str]) -> List[dict]:
    """Kontrola duplikatów przed zapisem (DEDUPLIKACJA.md §2.1) – id AED tylko z bieżącego podmiotu."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT key, device_id, same_owner, in_service FROM aed.match_device_keys(%s, %s, %s)",
            [manufacturer, serial, external_id],
        )
        columns = [c[0] for c in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def call(function: str, *args):
    """Wywołanie funkcji SQL modułu, np. ``call("aed.decide_transfer", transfer_id, True)``.

    Nazwa funkcji musi pochodzić z kodu (nie z danych użytkownika) – jest wstawiana do SQL dosłownie.
    """
    if not all(part.isidentifier() for part in function.split(".")) or function.count(".") != 1:
        raise ValueError(f"invalid SQL function name: {function!r}")
    placeholders = ", ".join(["%s"] * len(args))
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {function}({placeholders})", list(args))
        row = cursor.fetchone()
    return row[0] if row else None
