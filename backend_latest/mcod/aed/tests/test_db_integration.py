"""Integracja specyfikacji sql/aed.sql z ORM portalu (mcod.aed).

Scenariusze z sql/tests/dedup_smoke.sql (deduplikacja E1–E2) przeniesione na modele i kontekst Django,
plus reguły integracji: kontekst transakcji, modele tylko do odczytu, wersje tylko do dopisywania, audyt.
Izolacji podmiotów (RLS w specyfikacji) baza portalu nie egzekwuje – to zadanie warstwy API.
"""

import hashlib
from datetime import timedelta

import pytest
from django.db import DatabaseError, transaction
from django.utils import timezone

from mcod.aed import services
from mcod.aed.context import aed_context
from mcod.aed.models import (
    AedOrganization,
    AuditEvent,
    Device,
    DeviceKey,
    DeviceTransfer,
    DeviceVersion,
    ImportBatch,
    ReadOnlyModelError,
    UserLink,
)
from mcod.aed.tests.conftest import ORG_A, ORG_B


def feature(**props):
    return {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [21.0, 52.2]},
        "properties": {"location_pl": "Hol główny przy portierni", "access": "public", **props},
    }


def sql_error(exc_info):
    cause = exc_info.value.__cause__
    return cause.pgcode, cause.diag.constraint_name, cause.diag.message_detail


def save(aed, who, org, props, device_id=None, batch=None):
    with aed_context(aed["users"][who], organization_id=org) as link:
        return services.save_device_version(feature(**props), link, org, device_id=device_id, import_batch_id=batch)


@pytest.mark.django_db
class TestAedSchemaIntegration:
    def test_device_created_through_version(self, aed):
        device = save(aed, "a", ORG_A, {"manufacturer": "Philips", "serial_number": "AB-12 34", "external_id": "INW-1"})
        assert device.id.startswith("aed-") and device.owner_organization_id.hex == ORG_A.replace("-", "")
        version = DeviceVersion.objects.get(device=device)
        assert version.version_no == 1 and version.author_role == "org_admin" and len(bytes(version.sha256)) == 32
        assert version.author_user_id == aed["links"]["a"]
        key = DeviceKey.objects.get(device=device)
        assert (key.manufacturer_norm, key.serial_norm, key.external_id) == ("PHILIPS", "AB1234", "INW-1")
        assert UserLink.objects.get(portal_user=aed["users"]["a"]).id == aed["links"]["a"]

    def test_write_without_context_is_rejected(self, aed):
        with pytest.raises(DatabaseError) as exc, transaction.atomic():
            DeviceVersion.objects.create(
                data=feature(),
                author_user_id=aed["links"]["a"],
                author_organization_id=ORG_A,
                confirmation_statement=services.current_statement("change_confirmation"),
                confirmed_at=timezone.now(),
            )
        assert sql_error(exc)[0] == "42501"

    def test_serial_duplicate_same_owner(self, aed):
        first = save(aed, "a", ORG_A, {"manufacturer": "Philips", "serial_number": "AB-12 34"})
        with pytest.raises(DatabaseError) as exc:
            save(aed, "a", ORG_A, {"manufacturer": "PHILIPS", "serial_number": "ab1234"})
        assert sql_error(exc) == ("23505", "device_key_serial_uk", first.id)

    def test_serial_duplicate_other_owner_hides_device(self, aed):
        save(aed, "a", ORG_A, {"manufacturer": "Philips", "serial_number": "AB-12 34"})
        with pytest.raises(DatabaseError) as exc:
            save(aed, "b", ORG_B, {"manufacturer": "philips", "serial_number": "AB1234"})
        assert sql_error(exc) == ("23505", "device_key_serial_uk", "other_owner")
        with aed_context(aed["users"]["b"], organization_id=ORG_B):
            match = services.match_device_keys("Philips", "ab 12 34", None)
        assert match == [{"key": "serial_number", "device_id": None, "same_owner": False, "in_service": True}]

    def test_external_id_unique_per_owner(self, aed):
        save(aed, "a", ORG_A, {"external_id": "INW-1"})
        with pytest.raises(DatabaseError) as exc:
            save(aed, "a", ORG_A, {"external_id": " INW-1 "})
        assert sql_error(exc)[:2] == ("23505", "device_key_external_uk")
        assert save(aed, "b", ORG_B, {"external_id": "INW-1"}).id.startswith("aed-")

    def test_serial_requires_manufacturer(self, aed):
        with pytest.raises(DatabaseError) as exc:
            save(aed, "a", ORG_A, {"serial_number": "X1"})
        assert sql_error(exc)[:2] == ("23514", "device_key_serial_manufacturer_ck")

    def test_removed_device_frees_serial(self, aed):
        device = save(aed, "a", ORG_A, {"manufacturer": "Philips", "serial_number": "AB1234"})
        save(aed, "a", ORG_A, {"status": "removed", "manufacturer": "Philips", "serial_number": "AB1234"}, device.id)
        assert Device.objects.get(pk=device.pk).status == "removed"
        assert save(aed, "b", ORG_B, {"manufacturer": "Philips", "serial_number": "AB1234"}).id != device.id

    def test_import_modes_and_duplicate_content(self, aed):
        existing = save(aed, "a", ORG_A, {"external_id": "INW-1"})
        with aed_context(aed["users"]["a"], organization_id=ORG_A) as link:
            batch = ImportBatch.objects.create(
                organization_id=ORG_A,
                imported_by_id=link,
                schema_version="1.3.0",
                mode="create",
                content_sha256=hashlib.sha256(b"plik-1").digest(),
                feature_count=1,
                created_count=1,
                updated_count=0,
                imported_at=timezone.now(),
            )
        with pytest.raises(DatabaseError) as exc:
            save(aed, "a", ORG_A, {"external_id": "INW-1"}, device_id=existing.id, batch=batch.id)
        assert sql_error(exc)[0] == "22023"

        with pytest.raises(DatabaseError) as exc, aed_context(aed["users"]["a"], organization_id=ORG_A) as link:
            ImportBatch.objects.create(
                organization_id=ORG_A,
                imported_by_id=link,
                schema_version="1.3.0",
                mode="upsert",
                content_sha256=hashlib.sha256(b"plik-1").digest(),
                feature_count=1,
                created_count=1,
                updated_count=0,
                imported_at=timezone.now(),
            )
        assert sql_error(exc)[:2] == ("23505", "import_content_uk")

        with aed_context(aed["users"]["a"], organization_id=ORG_A) as link:
            upsert = ImportBatch.objects.create(
                organization_id=ORG_A,
                imported_by_id=link,
                schema_version="1.3.0",
                mode="upsert",
                content_sha256=hashlib.sha256(b"plik-2").digest(),
                feature_count=1,
                created_count=0,
                updated_count=1,
                imported_at=timezone.now(),
            )
        updated = save(aed, "a", ORG_A, {"external_id": "INW-1", "access": "customers"}, existing.id, upsert.id)
        assert updated.access == "customers" and updated.current_version.version_no == 2

    def test_transfer_moves_keys_and_clears_external_id(self, aed):
        device = save(aed, "a", ORG_A, {"external_id": "INW-2"})
        with aed_context(aed["users"]["a"], organization_id=ORG_A) as link:
            DeviceTransfer.objects.create(
                id="00000000-0000-0000-0000-0000000000f1",
                device=device,
                from_organization_id=ORG_A,
                to_organization_id=ORG_B,
                basis="agreement",
                status="pending",
                initiated_by_id=link,
                created_at=timezone.now(),
                expires_at=timezone.now() + timedelta(days=30),
            )
        with aed_context(aed["users"]["b"], organization_id=ORG_B):
            services.call("aed.decide_transfer", "00000000-0000-0000-0000-0000000000f1", True)
        key = DeviceKey.objects.get(device=device)
        assert key.owner_organization_id.hex == ORG_B.replace("-", "") and key.external_id is None
        assert Device.objects.get(pk=device.pk).owner_organization_id.hex == ORG_B.replace("-", "")

    def test_orm_guards(self, aed):
        device = save(aed, "a", ORG_A, {})
        with pytest.raises(ReadOnlyModelError):
            device.save()
        with pytest.raises(ReadOnlyModelError):
            DeviceKey.objects.get(device=device).delete()
        version = DeviceVersion.objects.get(device=device)
        with pytest.raises(ReadOnlyModelError):
            version.save()
        with pytest.raises(DatabaseError), transaction.atomic():  # baza też blokuje zmianę historii
            DeviceVersion.objects.filter(pk=version.pk).update(confirmed_at=timezone.now())
        with pytest.raises(DatabaseError), transaction.atomic():  # i fizyczne usunięcie AED
            Device.objects.filter(pk=device.pk).delete()

    def test_audit_chain(self, aed):
        save(aed, "a", ORG_A, {})
        events = list(AuditEvent.objects.all())
        assert events, "audit.capture powinien zapisać zdarzenia"
        assert [e.chain_seq for e in events] == list(range(events[0].chain_seq, events[0].chain_seq + len(events)))
        for prev, cur in zip(events, events[1:]):
            assert bytes(cur.prev_sha256) == bytes(prev.sha256)
        assert AedOrganization.objects.get(pk=ORG_A).name == "Podmiot A"
