"""Modele modułu „Misja AED” (rejestr defibrylatorów) – mapowanie schematów org, aed, audit, auth.

Tabele, ograniczenia, triggery i funkcje tworzy migracja 0001 z plików ``mcod/aed/sql/*.sql``
(specyfikacja ``sql/aed.sql`` przeniesiona skryptem ``scripts/port_aed_sql.py``). Dlatego modele są
``managed = False`` – Django ich nie tworzy ani nie zmienia; zmiana schematu = nowa migracja RunSQL.

Zasady zapisu (egzekwowane przez bazę, tu tylko odzwierciedlone):
  * zapis zawsze w kontekście ``mcod.aed.context.aed_context`` (SET LOCAL app.user_id / app.org_id),
    bo triggery ustalają autora i uprawnienia z kontekstu transakcji;
  * dane AED zmienia się WYŁĄCZNIE dopisaniem ``DeviceVersion`` – ``Device``, ``DeviceKey``, telefony
    i zdjęcia wylicza trigger, więc te modele są tylko do odczytu;
  * wersje i dziennik audytu są tylko do dopisywania (``AppendOnlyModel`` / ``ReadOnlyModel``);
  * izolację podmiotów (w specyfikacji: RLS) egzekwuje warstwa API portalu (ROLES.md §8, §11).
"""

from django.conf import settings
from django.contrib.postgres.fields import ArrayField, CIEmailField, JSONField
from django.db import models

# ---------------------------------------------------------------------------
#  Wartości typów wyliczeniowych PostgreSQL (CREATE TYPE … AS ENUM)
# ---------------------------------------------------------------------------

ORGANIZATION_TYPES = [
    (v, v) for v in ("company", "association", "local_government", "public_unit", "healthcare", "sole_trader", "other")
]
ORGANIZATION_STATUSES = [(v, v) for v in ("pending", "active", "orphaned", "suspended", "dissolved")]
ORG_ROLES = [(v, v) for v in ("org_admin", "org_editor")]
STATEMENT_KINDS = [(v, v) for v in ("registration", "change_confirmation")]
REPRESENTATION_BASES = [(v, v) for v in ("register", "power_of_attorney")]
REQUEST_STATUSES = [(v, v) for v in ("submitted", "verified", "approved", "rejected")]
DOCUMENT_TYPES = [(v, v) for v in ("power_of_attorney", "register_extract", "succession", "other")]
SIGNATURE_TYPES = [(v, v) for v in ("qualified", "trusted_profile", "personal", "none")]
REVIEW_SCOPES = [(v, v) for v in ("mc", "organization")]
REVIEW_DECISIONS = [(v, v) for v in ("keep", "revoke", "change_scope")]
OSM_ELEMENT_TYPES = [(v, v) for v in ("node", "way", "relation")]
DEVICE_STATUSES = [(v, v) for v in ("active", "planned", "removed")]
ACCESS_LEVELS = [(v, v) for v in ("public", "customers", "on_request", "private", "no", "unknown")]
DEVICE_CONDITIONS = [(v, v) for v in ("working", "faulty", "unknown")]
VISIBILITIES = [(v, v) for v in ("published", "flagged", "hidden")]
INTERVENTION_TYPES = [(v, v) for v in ("flag", "hide", "unhide")]
TRANSFER_STATUSES = [(v, v) for v in ("pending", "accepted", "rejected", "expired", "cancelled")]
TRANSFER_BASES = [(v, v) for v in ("agreement", "succession")]
IMPORT_MODES = [(v, v) for v in ("create", "upsert")]
MC_ROLE_NAMES = [(v, v) for v in ("mc_admin", "mc_operator", "mc_auditor")]


class ReadOnlyModelError(Exception):
    pass


class ReadOnlyModel(models.Model):
    """Tabela wypełniana przez triggery / funkcje bazy – ORM tylko czyta."""

    def save(self, *args, **kwargs):
        raise ReadOnlyModelError(f"{type(self).__name__} is maintained by the database (mcod.aed)")

    def delete(self, *args, **kwargs):
        raise ReadOnlyModelError(f"{type(self).__name__} is maintained by the database (mcod.aed)")

    class Meta:
        abstract = True


class AppendOnlyModel(models.Model):
    """Tylko dopisywanie (baza i tak blokuje UPDATE/DELETE triggerem)."""

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ReadOnlyModelError(f"{type(self).__name__} is append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ReadOnlyModelError(f"{type(self).__name__} is append-only")

    class Meta:
        abstract = True


# ---------------------------------------------------------------------------
#  auth – konta portalu i role MC (mcod/aed/sql/0001_portal_auth.sql)
# ---------------------------------------------------------------------------


class UserLink(models.Model):
    """UUID użytkownika w module AED ↔ konto portalu."""

    id = models.UUIDField(primary_key=True)
    portal_user = models.OneToOneField(
        settings.AUTH_USER_MODEL, models.DO_NOTHING, db_column="portal_user_id", related_name="aed_link"
    )
    created_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth"."user_link'


class McRole(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="mc_roles")
    role = models.TextField(choices=MC_ROLE_NAMES)
    reason = models.TextField()
    granted_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="granted_by", related_name="+")
    granted_at = models.DateTimeField()
    approved_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="approved_by", blank=True, null=True, related_name="+")
    approved_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(blank=True, null=True)
    revoked_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="revoked_by", blank=True, null=True, related_name="+")
    revoke_reason = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'auth"."mc_role'


class AuthSession(ReadOnlyModel):
    id = models.UUIDField(primary_key=True)
    user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="+")
    portal_session_key = models.TextField(blank=True, null=True)
    aal = models.SmallIntegerField()
    created_at = models.DateTimeField()
    absolute_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(blank=True, null=True)
    revoke_reason = models.TextField(blank=True, null=True)
    organization = models.ForeignKey("AedOrganization", models.DO_NOTHING, blank=True, null=True, related_name="+")
    org_role = models.TextField(choices=ORG_ROLES, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'auth"."session'


# ---------------------------------------------------------------------------
#  org – podmioty odpowiedzialne za AED (nie mylić z organizations.Organization portalu)
# ---------------------------------------------------------------------------


class AedOrganization(models.Model):
    """Podmiot odpowiedzialny za AED (ROLES.md §5, §12). Tworzony funkcją org.submit_registration()."""

    id = models.UUIDField(primary_key=True)
    name = models.TextField()
    type = models.TextField(choices=ORGANIZATION_TYPES)
    nip = models.TextField(unique=True, blank=True, null=True)
    regon = models.TextField(unique=True, blank=True, null=True)
    krs = models.TextField(unique=True, blank=True, null=True)
    teryt = models.TextField(blank=True, null=True)
    healthcare_register_no = models.TextField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    contact_email = CIEmailField(blank=True, null=True)
    contact_phone = models.TextField(blank=True, null=True)
    status = models.TextField(choices=ORGANIZATION_STATUSES)
    status_reason = models.TextField(blank=True, null=True)
    status_changed_at = models.DateTimeField(blank=True, null=True)
    status_changed_by = models.ForeignKey(
        UserLink, models.DO_NOTHING, db_column="status_changed_by", blank=True, null=True, related_name="+"
    )
    successor = models.ForeignKey("self", models.DO_NOTHING, blank=True, null=True, related_name="+")
    verified_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="verified_by", blank=True, null=True, related_name="+")
    approved_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="approved_by", blank=True, null=True, related_name="+")
    approved_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'org"."organization'

    def __str__(self):
        return self.name


class Site(models.Model):
    id = models.UUIDField(primary_key=True)
    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="sites")
    name = models.TextField()
    address = models.TextField(blank=True, null=True)
    is_active = models.BooleanField()
    created_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'org"."site'


class Membership(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="memberships")
    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="memberships")
    role = models.TextField(choices=ORG_ROLES)
    all_sites = models.BooleanField()
    granted_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="granted_by", related_name="+")
    granted_at = models.DateTimeField()
    expires_at = models.DateTimeField(blank=True, null=True)
    revoked_at = models.DateTimeField(blank=True, null=True)
    revoked_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="revoked_by", blank=True, null=True, related_name="+")
    revoke_reason = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'org"."membership'


class MembershipSite(AppendOnlyModel):
    """Klucz złożony (membership_id, site_id) – ``membership`` udaje PK; tylko INSERT (DELETE – SQL)."""

    membership = models.ForeignKey(Membership, models.DO_NOTHING, primary_key=True, related_name="+")
    organization_id = models.UUIDField()
    site = models.ForeignKey(Site, models.DO_NOTHING, related_name="+")

    class Meta:
        managed = False
        db_table = 'org"."membership_site'


class ResponsibilityStatement(models.Model):
    id = models.AutoField(primary_key=True)
    kind = models.TextField(choices=STATEMENT_KINDS)
    version = models.TextField()
    body = models.TextField()
    text_sha256 = models.BinaryField(blank=True, null=True, editable=False)  # kolumna generowana
    valid_from = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'org"."responsibility_statement'

    def save(self, *args, **kwargs):
        # text_sha256 jest GENERATED ALWAYS – nie może trafić do INSERT/UPDATE
        if self._state.adding:
            obj = type(self).objects.raw(
                "INSERT INTO org.responsibility_statement (kind, version, body, valid_from) "
                "VALUES (%s, %s, %s, %s) RETURNING *",
                [self.kind, self.version, self.body, self.valid_from],
            )[0]
            self.id, self.text_sha256 = obj.id, obj.text_sha256
            self._state.adding = False
            return
        raise ReadOnlyModelError("ResponsibilityStatement is versioned - add a new version instead")


class StatementAcceptance(AppendOnlyModel):
    """Klucz złożony (organization_id, statement_id, user_id) – ``organization`` udaje PK; tylko INSERT."""

    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, primary_key=True, related_name="+")
    statement = models.ForeignKey(ResponsibilityStatement, models.DO_NOTHING, related_name="+")
    user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="+")
    accepted_at = models.DateTimeField()
    ip = models.GenericIPAddressField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'org"."statement_acceptance'


class RegistrationRequest(ReadOnlyModel):
    """Zmieniany funkcjami org.submit_registration / verify / approve / reject_registration."""

    id = models.UUIDField(primary_key=True)
    organization = models.OneToOneField(AedOrganization, models.DO_NOTHING, related_name="+")
    applicant = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="+")
    representation_basis = models.TextField(choices=REPRESENTATION_BASES)
    statement = models.ForeignKey(ResponsibilityStatement, models.DO_NOTHING, related_name="+")
    status = models.TextField(choices=REQUEST_STATUSES)
    submitted_at = models.DateTimeField()
    verified_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="verified_by", blank=True, null=True, related_name="+")
    verified_at = models.DateTimeField(blank=True, null=True)
    approved_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="approved_by", blank=True, null=True, related_name="+")
    approved_at = models.DateTimeField(blank=True, null=True)
    decision_reason = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'org"."registration_request'


class Document(AppendOnlyModel):
    id = models.UUIDField(primary_key=True)
    request = models.ForeignKey(RegistrationRequest, models.DO_NOTHING, related_name="documents")
    type = models.TextField(choices=DOCUMENT_TYPES)
    storage_ref = models.TextField()
    sha256 = models.BinaryField()
    signature_type = models.TextField(choices=SIGNATURE_TYPES)
    uploaded_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="uploaded_by", related_name="+")
    uploaded_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'org"."document'


class AccessReview(AppendOnlyModel):
    id = models.BigAutoField(primary_key=True)
    scope = models.TextField(choices=REVIEW_SCOPES)
    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, blank=True, null=True, related_name="+")
    performed_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="performed_by", related_name="+")
    performed_at = models.DateTimeField()
    subject_user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="+")
    role = models.TextField()
    decision = models.TextField(choices=REVIEW_DECISIONS)
    note = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'org"."access_review'


class Invitation(models.Model):
    id = models.UUIDField(primary_key=True)
    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="invitations")
    email = CIEmailField()
    role = models.TextField(choices=ORG_ROLES)
    all_sites = models.BooleanField()
    site_ids = ArrayField(models.UUIDField())
    token_hash = models.BinaryField(unique=True)
    invited_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="invited_by", related_name="+")
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(blank=True, null=True)
    accepted_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="accepted_by", blank=True, null=True, related_name="+")
    revoked_at = models.DateTimeField(blank=True, null=True)
    revoked_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="revoked_by", blank=True, null=True, related_name="+")

    class Meta:
        managed = False
        db_table = 'org"."invitation'


# ---------------------------------------------------------------------------
#  aed – dane AED
# ---------------------------------------------------------------------------


class ImportBatch(AppendOnlyModel):
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="import_batches")
    imported_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="imported_by", related_name="+")
    schema_version = models.TextField()
    source = models.TextField(blank=True, null=True)
    mode = models.TextField(choices=IMPORT_MODES)
    content_sha256 = models.BinaryField()
    feature_count = models.IntegerField()
    created_count = models.IntegerField()
    updated_count = models.IntegerField()
    imported_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'aed"."import_batch'


class Device(ReadOnlyModel):
    """Bieżący stan AED wyliczany z ostatniej wersji (aed.apply_version). Zmiana = nowa DeviceVersion."""

    id = models.TextField(primary_key=True)
    owner_organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="devices")
    site = models.ForeignKey(Site, models.DO_NOTHING, blank=True, null=True, related_name="devices")
    status = models.TextField(choices=DEVICE_STATUSES)
    visibility = models.TextField(choices=VISIBILITIES)
    current_version = models.ForeignKey("DeviceVersion", models.DO_NOTHING, related_name="+")
    last_confirmed_at = models.DateTimeField()
    osm_id = models.BigIntegerField(blank=True, null=True)
    osm_type = models.TextField(choices=OSM_ELEMENT_TYPES, blank=True, null=True)
    osm_version = models.IntegerField(blank=True, null=True)
    lon = models.DecimalField(max_digits=9, decimal_places=6)
    lat = models.DecimalField(max_digits=8, decimal_places=6)
    access = models.TextField(choices=ACCESS_LEVELS)
    opening_hours = models.TextField(blank=True, null=True)
    is_24_7 = models.NullBooleanField()
    seasonal = models.BooleanField()
    access_note = models.TextField(blank=True, null=True)
    locked = models.NullBooleanField()
    indoor = models.NullBooleanField()
    level = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    location_pl = models.TextField()
    location_en = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    description_en = models.TextField(blank=True, null=True)
    vehicle_mounted = models.BooleanField()
    portable = models.BooleanField()
    device_count = models.SmallIntegerField()
    address = models.TextField(blank=True, null=True)
    addr_street_type = models.TextField(blank=True, null=True)
    addr_street = models.TextField(blank=True, null=True)
    addr_housenumber = models.TextField(blank=True, null=True)
    addr_unit = models.TextField(blank=True, null=True)
    addr_postcode = models.TextField(blank=True, null=True)
    addr_city = models.TextField(blank=True, null=True)
    teryt_terc = models.TextField(blank=True, null=True)
    teryt_simc = models.TextField(blank=True, null=True)
    teryt_ulic = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    operator = models.TextField(blank=True, null=True)
    operator_short = models.TextField(blank=True, null=True)
    email = models.TextField(blank=True, null=True)
    website = models.TextField(blank=True, null=True)
    manufacturer = models.TextField(blank=True, null=True)
    model = models.TextField(blank=True, null=True)
    condition = models.TextField(choices=DEVICE_CONDITIONS)
    condition_checked_at = models.DateField(blank=True, null=True)
    check_date = models.TextField(blank=True, null=True)
    check_date_from = models.DateField(blank=True, null=True)  # kolumna generowana
    needs_verification = models.BooleanField()
    fixme = models.TextField(blank=True, null=True)
    source = models.TextField(blank=True, null=True)
    import_batch = models.ForeignKey(ImportBatch, models.DO_NOTHING, blank=True, null=True, related_name="+")
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'aed"."device'

    def __str__(self):
        return self.id


class DeviceVersion(AppendOnlyModel):
    """Jedyna droga utworzenia lub zmiany AED. Autora, numer wersji i skróty uzupełnia trigger."""

    id = models.BigAutoField(primary_key=True)
    device = models.ForeignKey(Device, models.DO_NOTHING, blank=True, null=True, related_name="versions")
    version_no = models.IntegerField(blank=True, null=True)
    site_id = models.UUIDField(blank=True, null=True)
    data = JSONField()
    author_user = models.ForeignKey(UserLink, models.DO_NOTHING, related_name="+")
    author_organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="+")
    author_role = models.TextField(choices=ORG_ROLES, blank=True, null=True)
    confirmation_statement = models.ForeignKey(ResponsibilityStatement, models.DO_NOTHING, related_name="+")
    confirmed_at = models.DateTimeField()
    import_batch = models.ForeignKey(ImportBatch, models.DO_NOTHING, blank=True, null=True, related_name="+")
    created_at = models.DateTimeField(blank=True, null=True)
    prev_sha256 = models.BinaryField(blank=True, null=True)
    sha256 = models.BinaryField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'aed"."device_version'


class ManufacturerAlias(models.Model):
    alias_norm = models.TextField(primary_key=True)
    canonical = models.TextField()

    class Meta:
        managed = False
        db_table = 'aed"."manufacturer_alias'


class DeviceKey(ReadOnlyModel):
    """Niepubliczne klucze AED (DEDUPLIKACJA.md §2.1) – tylko dla właściciela i MC (API)."""

    device = models.OneToOneField(Device, models.DO_NOTHING, primary_key=True, related_name="key")
    owner_organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="+")
    in_service = models.BooleanField()
    manufacturer_norm = models.TextField(blank=True, null=True)
    serial_number = models.TextField(blank=True, null=True)
    serial_norm = models.TextField(blank=True, null=True)
    external_id = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'aed"."device_key'


class DevicePhone(ReadOnlyModel):
    """Klucz złożony (device_id, position) – ``device`` udaje PK; tylko odczyt."""

    device = models.ForeignKey(Device, models.DO_NOTHING, primary_key=True, related_name="phones")
    position = models.SmallIntegerField()
    phone = models.TextField()

    class Meta:
        managed = False
        db_table = 'aed"."device_phone'
        ordering = ["position"]


class DeviceImage(ReadOnlyModel):
    """Klucz złożony (device_id, position) – ``device`` udaje PK; tylko odczyt."""

    device = models.ForeignKey(Device, models.DO_NOTHING, primary_key=True, related_name="images")
    position = models.SmallIntegerField()
    url = models.TextField()

    class Meta:
        managed = False
        db_table = 'aed"."device_image'
        ordering = ["position"]


class DeviceTransfer(models.Model):
    """Wniosek tworzy się INSERT-em (trigger transfer_guard), decyzja – funkcją aed.decide_transfer()."""

    id = models.UUIDField(primary_key=True)
    device = models.ForeignKey(Device, models.DO_NOTHING, related_name="transfers")
    from_organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="+")
    to_organization = models.ForeignKey(AedOrganization, models.DO_NOTHING, related_name="+")
    basis = models.TextField(choices=TRANSFER_BASES)
    status = models.TextField(choices=TRANSFER_STATUSES)
    initiated_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="initiated_by", related_name="+")
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    decided_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="decided_by", blank=True, null=True, related_name="+")
    decided_at = models.DateTimeField(blank=True, null=True)
    succession_document = models.ForeignKey(Document, models.DO_NOTHING, blank=True, null=True, related_name="+")

    class Meta:
        managed = False
        db_table = 'aed"."device_transfer'


class McIntervention(models.Model):
    id = models.BigAutoField(primary_key=True)
    device = models.ForeignKey(Device, models.DO_NOTHING, related_name="interventions")
    type = models.TextField(choices=INTERVENTION_TYPES)
    reason = models.TextField()
    created_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="created_by", related_name="+")
    created_at = models.DateTimeField()
    approved_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="approved_by", blank=True, null=True, related_name="+")
    approved_at = models.DateTimeField(blank=True, null=True)
    organization_response = models.TextField(blank=True, null=True)
    responded_by = models.ForeignKey(
        UserLink, models.DO_NOTHING, db_column="responded_by", blank=True, null=True, related_name="+"
    )
    responded_at = models.DateTimeField(blank=True, null=True)
    resolved_by = models.ForeignKey(UserLink, models.DO_NOTHING, db_column="resolved_by", blank=True, null=True, related_name="+")
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolution = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'aed"."mc_intervention'


class SearchOutbox(ReadOnlyModel):
    """Kolejka zmian do Elasticsearch – obsługa funkcjami aed.search_outbox_claim/ack/fail."""

    id = models.BigAutoField(primary_key=True)
    doc = models.ForeignKey(Device, models.DO_NOTHING, db_constraint=False, related_name="+")
    enqueued_at = models.DateTimeField()
    claimed_at = models.DateTimeField(blank=True, null=True)
    attempts = models.SmallIntegerField()
    processed_at = models.DateTimeField(blank=True, null=True)
    last_error = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'aed"."search_outbox'


# ---------------------------------------------------------------------------
#  audit – dziennik zdarzeń z łańcuchem skrótów (zapis: triggery i audit.write())
# ---------------------------------------------------------------------------


class AuditEvent(ReadOnlyModel):
    id = models.BigAutoField(primary_key=True)
    chain_seq = models.BigIntegerField(unique=True)
    occurred_at = models.DateTimeField()
    actor_user_id = models.UUIDField(blank=True, null=True)
    actor_role = models.TextField(blank=True, null=True)
    organization_context_id = models.UUIDField(blank=True, null=True)
    action = models.TextField()
    object_type = models.TextField()
    object_id = models.TextField(blank=True, null=True)
    result = models.TextField()
    reason = models.TextField(blank=True, null=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    session_id = models.UUIDField(blank=True, null=True)
    details = JSONField()
    prev_sha256 = models.BinaryField(blank=True, null=True)
    sha256 = models.BinaryField()

    class Meta:
        managed = False
        db_table = 'audit"."event'
        ordering = ["chain_seq"]
