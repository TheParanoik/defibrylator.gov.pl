-- =============================================================================
--  WYGENEROWANE przez scripts/port_aed_sql.py z sql/aed.sql (repozytorium notatek modułu AED)
--  SHA-256 źródła: fcdb492b1af141e991d81d453805fc1c27ed1552dd3465c619ac35a10be09ed9
--  Bez ról bazodanowych, GRANT/REVOKE i RLS (ROLES.md §11); klucze obce kont → auth.user_link.
--  Plik jest częścią migracji 0001 – nie edytować; zmiany specyfikacji = nowa migracja.
-- =============================================================================

-- =============================================================================
--  Baza danych „Misja AED” – rejestr defibrylatorów AED w Polsce
--  Operator systemu: Ministerstwo Cyfryzacji RP (MC)
--
--  Zgodność (dokumentacja w katalogu docs/): SCHEMA.md 1.3.0 (format danych AED), DEDUPLIKACJA.md E1–E2,
--            JWT.md 1.4 (uwierzytelnianie), ROLES.md 2.0 (role, podmioty, odpowiedzialność za dane),
--            DANEGOVPL_STACK.md (stack portalu dane.gov.pl: PostgreSQL 17, Elasticsearch 6.8, ELK).
--  Skrypt tworzy wyłącznie strukturę – nie zawiera i nie ładuje żadnych danych.
--  Danych przykładowych ani zewnętrznych (OSM, dane.gov.pl) nie wolno importować do prawdziwej bazy.
--
--  KONTEKST (ARCHITEKTURA.md): rejestr jest modułem portalu dane.gov.pl. W portalu ten plik jest
--  SPECYFIKACJĄ dla modeli i migracji Django (RunSQL dla triggerów i funkcji), a nie skryptem wdrożeniowym.
--  Dostosowanie do stacku portalu:
--    * baza portalu to czysty obraz postgres:17 – BEZ PostGIS. Położenie AED trzymamy w kolumnach lon/lat,
--      a zapytania przestrzenne (bbox, najbliższe, kafelki) obsługuje Elasticsearch (sekcja 15).
--      Zapasowe wyszukiwanie najbliższych w bazie: rozszerzenia contrib cube + earthdistance;
--    * indeks Elasticsearch „aed” zasila transakcyjna kolejka zmian aed.search_outbox (sekcja 15),
--      bo dane AED zmieniają triggery w bazie (wersje, interwencje MC), których nie widzą sygnały Django;
--    * dziennik audytu trafia do ELK przez Logstash (wejście JDBC) z widoku audit.event_export (sekcja 16).
--
--  Wymagania: PostgreSQL 13+ (portal: 17), rozszerzenia pgcrypto, citext, cube, earthdistance
--  (wszystkie z pakietu contrib – dostępne w oficjalnym obrazie postgres).
--  KOLEJNOŚĆ: najpierw sql/auth.sql (konta, logowanie, sesje, role MC), potem ten plik.
--  Całość instaluje sql/install.sql (jako właściciel bazy, NIE jako aed_api / aed_auth):
--      psql -d <baza> -v ON_ERROR_STOP=1 -f sql/install.sql
--
--  Schematy:
--    auth  – konta, logowanie, MFA, sesje, role MC – sql/auth.sql (JWT.md §8–§10, ROLES.md §3.1)
--            ten plik dodaje tylko kontekst podmiotu w auth.session
--    org   – podmioty, lokalizacje, członkostwa, zaproszenia,
--            wnioski                                             (ROLES.md §5, §6, §12, §13)
--    aed   – urządzenia AED, historia wersji, przekazania,
--            interwencje MC                                     (SCHEMA.md, ROLES.md §12–§15)
--    audit – niezmienialny dziennik zdarzeń                     (ROLES.md §10)
--
--  Role bazodanowe (tworzone jako NOLOGIN; konta logowania nadaje administrator bazy):
--    aed_auth        – serwis uwierzytelniania (JWT.md)
--    aed_api         – API aplikacji; podlega Row-Level Security
--    aed_indexer     – zadanie indeksujące do Elasticsearch (Celery); tylko kolejka i dokumenty publiczne
--    aed_log_shipper – Logstash (wejście JDBC); tylko odczyt widoku eksportu audytu
--
--  Kontekst RLS: API na początku każdej transakcji ustawia (zawsze LOCAL, JWT.md §7):
--    app.user_id, app.org_id, app.session_id, app.actor_role, app.client_ip
--
--  Zasady wymuszane przez bazę (a nie tylko przez aplikację):
--    * dane AED zmienia się wyłącznie przez dopisanie wersji (aed.device_version);
--      wiersz aed.device to bieżący stan wyliczany z ostatniej wersji,
--    * wersje danych i dziennik audytu są tylko do dopisywania, z łańcuchem skrótów SHA-256,
--    * izolacja podmiotów przez RLS, zakaz fizycznego usuwania AED,
--    * MC nie może zmienić treści danych podmiotu – tylko oznaczyć lub ukryć wpis,
--    * każda zmiana ról / członkostwa unieważnia sesje użytkownika.
-- =============================================================================


CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS cube;           -- wymagane przez earthdistance
CREATE EXTENSION IF NOT EXISTS earthdistance;  -- zapasowe „najbliższe AED” bez PostGIS


CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS org;
CREATE SCHEMA IF NOT EXISTS aed;
CREATE SCHEMA IF NOT EXISTS audit;

COMMENT ON SCHEMA org   IS 'Podmioty zgłaszające AED, lokalizacje, członkostwa i wnioski (ROLES.md).';
COMMENT ON SCHEMA aed   IS 'Defibrylatory AED w Polsce. Format danych: SCHEMA.md 1.3.0.';
COMMENT ON SCHEMA audit IS 'Niezmienialny dziennik zdarzeń z łańcuchem skrótów (ROLES.md §10).';

-- =============================================================================
--  1. Typy wyliczeniowe
-- =============================================================================


CREATE TYPE org.organization_type AS ENUM (
    'company',              -- spółka (KRS)
    'association',          -- fundacja, stowarzyszenie, OSP (KRS)
    'local_government',     -- jednostka samorządu terytorialnego (TERYT)
    'public_unit',          -- jednostka organizacyjna JST lub państwa (szkoła, urząd)
    'healthcare',           -- podmiot leczniczy
    'sole_trader',          -- przedsiębiorca z CEIDG
    'other'
);
CREATE TYPE org.organization_status AS ENUM ('pending', 'active', 'orphaned', 'suspended', 'dissolved');
CREATE TYPE org.org_role              AS ENUM ('org_admin', 'org_editor');
CREATE TYPE org.statement_kind        AS ENUM ('registration', 'change_confirmation');
CREATE TYPE org.representation_basis  AS ENUM ('register', 'power_of_attorney');
CREATE TYPE org.request_status        AS ENUM ('submitted', 'verified', 'approved', 'rejected');
CREATE TYPE org.document_type         AS ENUM ('power_of_attorney', 'register_extract', 'succession', 'other');
CREATE TYPE org.signature_type        AS ENUM ('qualified', 'trusted_profile', 'personal', 'none');
CREATE TYPE org.review_scope          AS ENUM ('mc', 'organization');
CREATE TYPE org.review_decision       AS ENUM ('keep', 'revoke', 'change_scope');

CREATE TYPE aed.osm_element_type AS ENUM ('node', 'way', 'relation');
CREATE TYPE aed.device_status    AS ENUM (
    'active',    -- zwykły, działający AED
    'planned',   -- planowany / w trakcie montażu
    'removed'    -- wycofany (zamiast fizycznego usunięcia)
);
CREATE TYPE aed.access_level AS ENUM (
    'public', 'customers', 'on_request', 'private', 'no', 'unknown'
);
CREATE TYPE aed.device_condition AS ENUM (
    'working',   -- sprawny (AED Sync: „Sprawny”)
    'faulty',    -- niesprawny, np. w serwisie, przeterminowane elektrody (AED Sync: „Niesprawny”)
    'unknown'    -- stan nieznany (AED Sync: „Nieznany”)
);                                                     -- SCHEMA.md 1.3.0
CREATE TYPE aed.visibility         AS ENUM ('published', 'flagged', 'hidden');
CREATE TYPE aed.intervention_type  AS ENUM ('flag', 'hide', 'unhide');
CREATE TYPE aed.transfer_status    AS ENUM ('pending', 'accepted', 'rejected', 'expired', 'cancelled');
CREATE TYPE aed.transfer_basis     AS ENUM ('agreement', 'succession');
CREATE TYPE aed.import_mode        AS ENUM (
    'create',    -- każdy obiekt tworzy nowe AED (DEDUPLIKACJA.md §2.2)
    'upsert'     -- obiekt z external_id istniejącym u podmiotu aktualizuje AED, pozostałe tworzą nowe
);

-- =============================================================================
--  2. Funkcje walidujące identyfikatory (używane w CHECK)
-- =============================================================================

CREATE FUNCTION org.is_valid_nip(p text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    w int[] := ARRAY[6, 5, 7, 2, 3, 4, 5, 6, 7];
    s int := 0;
BEGIN
    IF p !~ '^\d{10}$' THEN
        RETURN false;
    END IF;
    FOR i IN 1..9 LOOP
        s := s + w[i] * substr(p, i, 1)::int;
    END LOOP;
    RETURN s % 11 <> 10 AND s % 11 = substr(p, 10, 1)::int;
END
$$;

CREATE FUNCTION org.is_valid_regon(p text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    w int[];
    n int;
    s int := 0;
    c int;
BEGIN
    IF p ~ '^\d{9}$' THEN
        w := ARRAY[8, 9, 2, 3, 4, 5, 6, 7];
        n := 8;
    ELSIF p ~ '^\d{14}$' THEN
        w := ARRAY[2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8];
        n := 13;
    ELSE
        RETURN false;
    END IF;
    FOR i IN 1..n LOOP
        s := s + w[i] * substr(p, i, 1)::int;
    END LOOP;
    c := s % 11;
    IF c = 10 THEN
        c := 0;
    END IF;
    RETURN c = substr(p, n + 1, 1)::int;
END
$$;

-- =============================================================================
--  3. Tabele: org (konta użytkowników i role MC: sql/auth.sql)
-- =============================================================================

CREATE TABLE org.organization (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     text  NOT NULL CHECK (length(btrim(name)) > 0),
    type                     org.organization_type NOT NULL,
    nip                      text  UNIQUE CHECK (org.is_valid_nip(nip)),
    regon                    text  UNIQUE CHECK (org.is_valid_regon(regon)),
    krs                      text  UNIQUE CHECK (krs ~ '^\d{10}$'),
    teryt                    text  CHECK (teryt ~ '^\d{2}(\d{2}(\d{3})?)?$'),
    healthcare_register_no   text,
    address                  text,
    contact_email            citext CHECK (contact_email ~ '^[^@\s]+@[^@\s]+$'),
    contact_phone            text   CHECK (contact_phone ~ '^\+[1-9]\d{7,14}$'),
    status                   org.organization_status NOT NULL DEFAULT 'pending',
    status_reason            text,
    status_changed_at        timestamptz,
    status_changed_by        uuid REFERENCES auth.user_link (id),
    successor_id             uuid REFERENCES org.organization (id),
    verified_by              uuid REFERENCES auth.user_link (id),
    approved_by              uuid REFERENCES auth.user_link (id),
    approved_at              timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT organization_identifier_ck CHECK (nip IS NOT NULL OR regon IS NOT NULL),
    CONSTRAINT organization_krs_ck        CHECK (type NOT IN ('company', 'association') OR krs IS NOT NULL),
    CONSTRAINT organization_teryt_ck      CHECK (type <> 'local_government' OR teryt IS NOT NULL),
    CONSTRAINT organization_health_ck     CHECK (type <> 'healthcare' OR healthcare_register_no IS NOT NULL),
    CONSTRAINT organization_approval_ck   CHECK ((status = 'pending') = (approved_at IS NULL)),
    CONSTRAINT organization_four_eyes_ck  CHECK (approved_at IS NULL OR (verified_by IS NOT NULL
                                                 AND approved_by IS NOT NULL AND verified_by <> approved_by)),
    CONSTRAINT organization_reason_ck     CHECK (status NOT IN ('suspended', 'dissolved', 'orphaned') OR status_reason IS NOT NULL),
    CONSTRAINT organization_successor_ck  CHECK (successor_id IS NULL OR (status = 'dissolved' AND successor_id <> id))
);

COMMENT ON TABLE org.organization IS
    'Podmioty zgłaszające AED (ROLES.md §5.1). Wiersz powstaje przy złożeniu wniosku ze statusem pending.';

CREATE TABLE org.site (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES org.organization (id),
    name             text NOT NULL CHECK (length(btrim(name)) > 0),
    address          text,
    is_active        boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT site_org_uk  UNIQUE (id, organization_id),
    CONSTRAINT site_name_uk UNIQUE (organization_id, name)
);

COMMENT ON TABLE org.site IS 'Lokalizacje / oddziały podmiotu (ROLES.md §12.2).';

CREATE TABLE org.membership (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id          uuid         NOT NULL REFERENCES auth.user_link (id),
    organization_id  uuid         NOT NULL REFERENCES org.organization (id),
    role             org.org_role NOT NULL,
    all_sites        boolean      NOT NULL DEFAULT true,
    granted_by       uuid         NOT NULL REFERENCES auth.user_link (id),
    granted_at       timestamptz  NOT NULL DEFAULT now(),
    expires_at       timestamptz,
    revoked_at       timestamptz,
    revoked_by       uuid         REFERENCES auth.user_link (id),
    revoke_reason    text,

    CONSTRAINT membership_org_uk     UNIQUE (id, organization_id),
    CONSTRAINT membership_not_self_ck CHECK (granted_by <> user_id),
    CONSTRAINT membership_admin_ck   CHECK (role <> 'org_admin' OR all_sites),
    CONSTRAINT membership_expiry_ck  CHECK (expires_at IS NULL OR expires_at > granted_at),
    CONSTRAINT membership_revoke_ck  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
                                            AND (revoked_at IS NULL OR revoke_reason IS NOT NULL))
);

CREATE UNIQUE INDEX membership_active_uk ON org.membership (user_id, organization_id) WHERE revoked_at IS NULL;
CREATE INDEX membership_org_ix ON org.membership (organization_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE org.membership IS
    'Członkostwo użytkownika w podmiocie z rolą (ROLES.md §3.2, §5.3). Zmiana roli = odwołanie i nowy wiersz.';

CREATE TABLE org.membership_site (
    membership_id    bigint NOT NULL,
    organization_id  uuid   NOT NULL,
    site_id          uuid   NOT NULL,
    PRIMARY KEY (membership_id, site_id),
    FOREIGN KEY (membership_id, organization_id) REFERENCES org.membership (id, organization_id),
    FOREIGN KEY (site_id, organization_id)       REFERENCES org.site (id, organization_id)
);

COMMENT ON TABLE org.membership_site IS 'Zawężony zakres lokalizacji członkostwa (gdy all_sites = false).';

CREATE TABLE org.responsibility_statement (
    id           integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind         org.statement_kind NOT NULL,
    version      text        NOT NULL,
    body         text        NOT NULL,
    text_sha256  bytea       GENERATED ALWAYS AS (digest(body, 'sha256')) STORED,
    valid_from   timestamptz NOT NULL,
    UNIQUE (kind, version)
);

COMMENT ON TABLE org.responsibility_statement IS
    'Wersjonowane treści oświadczeń: przy rejestracji (§13.1) i potwierdzenia zmiany danych (§13.2).';

CREATE TABLE org.statement_acceptance (
    organization_id  uuid        NOT NULL REFERENCES org.organization (id),
    statement_id     integer     NOT NULL REFERENCES org.responsibility_statement (id),
    user_id          uuid        NOT NULL REFERENCES auth.user_link (id),
    accepted_at      timestamptz NOT NULL DEFAULT now(),
    ip               inet,
    PRIMARY KEY (organization_id, statement_id, user_id)
);

CREATE TABLE org.registration_request (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       uuid NOT NULL REFERENCES org.organization (id),
    applicant_id          uuid NOT NULL REFERENCES auth.user_link (id),
    representation_basis  org.representation_basis NOT NULL,
    statement_id          integer NOT NULL REFERENCES org.responsibility_statement (id),
    status                org.request_status NOT NULL DEFAULT 'submitted',
    submitted_at          timestamptz NOT NULL DEFAULT now(),
    verified_by           uuid REFERENCES auth.user_link (id),
    verified_at           timestamptz,
    approved_by           uuid REFERENCES auth.user_link (id),
    approved_at           timestamptz,
    decision_reason       text,

    CONSTRAINT request_verifier_ck  CHECK (verified_by IS NULL OR verified_by <> applicant_id),
    CONSTRAINT request_approver_ck  CHECK (approved_by IS NULL OR (approved_by <> applicant_id AND approved_by <> verified_by)),
    CONSTRAINT request_verified_ck  CHECK (status NOT IN ('verified', 'approved') OR verified_by IS NOT NULL),
    CONSTRAINT request_approved_ck  CHECK (status <> 'approved' OR approved_by IS NOT NULL),
    CONSTRAINT request_rejected_ck  CHECK (status <> 'rejected' OR decision_reason IS NOT NULL)
);

CREATE UNIQUE INDEX request_open_uk ON org.registration_request (organization_id)
    WHERE status IN ('submitted', 'verified');

COMMENT ON TABLE org.registration_request IS
    'Wniosek o rejestrację podmiotu albo o nowego org_admin dla podmiotu bez administratora (ROLES.md §5.1, §6.3).';

CREATE TABLE org.document (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      uuid NOT NULL REFERENCES org.registration_request (id),
    type            org.document_type  NOT NULL,
    storage_ref     text               NOT NULL,   -- treść poza bazą, w magazynie z kontrolą dostępu
    sha256          bytea              NOT NULL CHECK (octet_length(sha256) = 32),
    signature_type  org.signature_type NOT NULL,
    uploaded_by     uuid               NOT NULL REFERENCES auth.user_link (id),
    uploaded_at     timestamptz        NOT NULL DEFAULT now()
);

CREATE TABLE org.access_review (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope            org.review_scope    NOT NULL,
    organization_id  uuid REFERENCES org.organization (id),
    performed_by     uuid NOT NULL REFERENCES auth.user_link (id),
    performed_at     timestamptz NOT NULL DEFAULT now(),
    subject_user_id  uuid NOT NULL REFERENCES auth.user_link (id),
    role             text NOT NULL,
    decision         org.review_decision NOT NULL,
    note             text,

    CONSTRAINT review_scope_ck CHECK ((scope = 'organization') = (organization_id IS NOT NULL)),
    CONSTRAINT review_self_ck  CHECK (performed_by <> subject_user_id)
);

COMMENT ON TABLE org.access_review IS 'Wyniki przeglądów uprawnień (ROLES.md §6.2).';

-- Zaproszenie pracownika do podmiotu (ROLES.md §5.3). Token jednorazowy: w bazie tylko SHA-256.
CREATE TABLE org.invitation (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid         NOT NULL REFERENCES org.organization (id),
    email            citext       NOT NULL CHECK (email ~ '^[^@\s]+@[^@\s]+$'),
    role             org.org_role NOT NULL,
    all_sites        boolean      NOT NULL DEFAULT true,
    site_ids         uuid[]       NOT NULL DEFAULT '{}',
    token_hash       bytea        NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_by       uuid         NOT NULL REFERENCES auth.user_link (id),
    created_at       timestamptz  NOT NULL DEFAULT now(),
    expires_at       timestamptz  NOT NULL DEFAULT now() + interval '7 days',
    accepted_at      timestamptz,
    accepted_by      uuid         REFERENCES auth.user_link (id),
    revoked_at       timestamptz,
    revoked_by       uuid         REFERENCES auth.user_link (id),

    CONSTRAINT invitation_expiry_ck   CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
    CONSTRAINT invitation_admin_ck    CHECK (role <> 'org_admin' OR all_sites),
    CONSTRAINT invitation_sites_ck    CHECK (all_sites = (cardinality(site_ids) = 0)),
    CONSTRAINT invitation_accept_ck   CHECK ((accepted_at IS NULL) = (accepted_by IS NULL)),
    CONSTRAINT invitation_revoke_ck   CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT invitation_final_ck    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE UNIQUE INDEX invitation_open_uk ON org.invitation (organization_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

COMMENT ON TABLE org.invitation IS
    'Imienne zaproszenia do podmiotu wysyłane przez org_admin (ROLES.md §5.3); ważne maks. 7 dni, jednorazowe.';

-- =============================================================================
--  4. Kontekst podmiotu w sesji (tabela auth.session pochodzi z sql/auth.sql)
-- =============================================================================

ALTER TABLE auth.session
    ADD COLUMN organization_id uuid REFERENCES org.organization (id),   -- claim org_id
    ADD COLUMN org_role        org.org_role,                            -- claim org_role
    ADD CONSTRAINT session_org_ck CHECK ((organization_id IS NULL) = (org_role IS NULL)),
    -- org_admin: MFA (AAL2+) i maks. 12 h sesji (docs/JWT.md §2, §9)
    ADD CONSTRAINT session_org_admin_ck CHECK (org_role IS DISTINCT FROM 'org_admin'
        OR (aal >= 2 AND absolute_expires_at <= created_at + interval '12 hours'));

CREATE INDEX session_org_active_ix ON auth.session (organization_id) WHERE revoked_at IS NULL;

-- =============================================================================
--  5. Tabele: aed
-- =============================================================================

CREATE TABLE aed.import_batch (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id  uuid        NOT NULL REFERENCES org.organization (id),
    imported_by      uuid        NOT NULL REFERENCES auth.user_link (id),
    schema_version   text        NOT NULL CHECK (schema_version ~ '^\d+\.\d+\.\d+$'),
    source           text,
    mode             aed.import_mode NOT NULL DEFAULT 'create',
    content_sha256   bytea       NOT NULL CHECK (octet_length(content_sha256) = 32),
    feature_count    integer     NOT NULL CHECK (feature_count >= 0),
    created_count    integer     NOT NULL CHECK (created_count >= 0),
    updated_count    integer     NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
    imported_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT import_counts_ck      CHECK (created_count + updated_count = feature_count),
    CONSTRAINT import_create_mode_ck CHECK (mode = 'upsert' OR updated_count = 0),
    -- ten sam plik drugi raz → 409 duplicate_import, niezależnie od Idempotency-Key i czasu (DEDUPLIKACJA.md §2.2)
    CONSTRAINT import_content_uk     UNIQUE (organization_id, content_sha256)
);

COMMENT ON TABLE aed.import_batch IS 'Import zbiorczy danych AED wykonany przez org_admin (ROLES.md §4, §13.2).';
COMMENT ON COLUMN aed.import_batch.content_sha256 IS
    'SHA-256 tablicy features w postaci kanonicznej JSON (RFC 8785, JCS), liczony przez backend przed zapisem. '
    'Import odrzucony (wszystko albo nic) nie zostawia wiersza, więc można go ponowić.';

CREATE TABLE aed.device (
    -- Identyfikacja i własność
    id                     text PRIMARY KEY,
    owner_organization_id  uuid NOT NULL REFERENCES org.organization (id),
    site_id                uuid,
    status                 aed.device_status NOT NULL DEFAULT 'active',
    visibility             aed.visibility    NOT NULL DEFAULT 'published',
    current_version_id     bigint            NOT NULL,
    last_confirmed_at      timestamptz       NOT NULL,

    -- Opcjonalne powiązanie z OpenStreetMap (tylko jako odnośnik, nie źródło danych)
    osm_id                 bigint CHECK (osm_id > 0),
    osm_type               aed.osm_element_type,
    osm_version            integer CHECK (osm_version >= 1),

    -- Położenie (WGS84, 6 miejsc po przecinku ≈ 0,1 m). Bez PostGIS – zapytania geo w Elasticsearch.
    lon                    numeric(9, 6) NOT NULL,
    lat                    numeric(8, 6) NOT NULL,

    -- Dostępność
    access                 aed.access_level NOT NULL DEFAULT 'unknown',
    opening_hours          text,
    is_24_7                boolean,
    seasonal               boolean NOT NULL DEFAULT false,
    access_note            text,
    locked                 boolean,

    -- Położenie urządzenia
    indoor                 boolean,
    level                  numeric(5, 2),
    location_pl            text NOT NULL,
    location_en            text,
    description            text,
    description_en         text,
    vehicle_mounted        boolean  NOT NULL DEFAULT false,
    portable               boolean  NOT NULL DEFAULT false,
    device_count           smallint NOT NULL DEFAULT 1 CHECK (device_count >= 1),
    address                text,      -- do wyświetlenia; składany z addr_*, gdy są (SCHEMA.md 1.1.0)

    -- Adres w częściach i kody TERYT (SCHEMA.md 1.1.0) – tekst, zera wiodące są istotne
    addr_street_type       text,
    addr_street            text,
    addr_housenumber       text,
    addr_unit              text,
    addr_postcode          text,
    addr_city              text,
    teryt_terc             text,
    teryt_simc             text,
    teryt_ulic             text,

    -- Operator i kontakt
    name                   text,
    operator               text,
    operator_short         text,
    email                  text,
    website                text,

    -- Urządzenie
    manufacturer           text,
    model                  text,

    -- Stan urządzenia (SCHEMA.md 1.3.0)
    condition              aed.device_condition NOT NULL DEFAULT 'unknown',
    condition_checked_at   date,

    -- Jakość danych
    check_date             text,
    check_date_from        date GENERATED ALWAYS AS (
                               CASE WHEN check_date IS NULL THEN NULL
                               ELSE make_date(
                                   substr(check_date, 1, 4)::integer,
                                   COALESCE(NULLIF(substr(check_date, 6, 2), '')::integer, 1),
                                   COALESCE(NULLIF(substr(check_date, 9, 2), '')::integer, 1))
                               END
                           ) STORED,
    needs_verification     boolean NOT NULL DEFAULT false,
    fixme                  text,
    source                 text,

    -- Techniczne
    import_batch_id        bigint REFERENCES aed.import_batch (id),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT device_id_format_ck  CHECK (id ~ '^aed-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    CONSTRAINT device_site_fk       FOREIGN KEY (site_id, owner_organization_id)
                                    REFERENCES org.site (id, organization_id),
    CONSTRAINT device_osm_ck        CHECK ((osm_id IS NULL) = (osm_type IS NULL)
                                           AND (osm_id IS NOT NULL OR osm_version IS NULL)),
    CONSTRAINT device_osm_uk        UNIQUE (osm_type, osm_id),
    -- przybliżenie: prostokąt otaczający Polskę, nie dokładna granica (ROLES.md §15)
    CONSTRAINT device_in_poland_ck  CHECK (lon BETWEEN 14.07 AND 24.16
                                           AND lat BETWEEN 49.00 AND 54.84),
    CONSTRAINT device_check_date_ck CHECK (check_date ~ '^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?)?$'),
    CONSTRAINT device_level_ck      CHECK (level BETWEEN -20 AND 200),
    CONSTRAINT device_email_ck      CHECK (email ~ '^[^@\s]+@[^@\s]+$'),
    CONSTRAINT device_website_ck    CHECK (website ~* '^https?://'),
    CONSTRAINT device_24_7_ck       CHECK (is_24_7 IS NOT TRUE OR opening_hours = '24/7'),
    CONSTRAINT device_postcode_ck   CHECK (addr_postcode ~ '^\d{2}-\d{3}$'),
    CONSTRAINT device_housenumber_ck CHECK (addr_housenumber ~ '^\d' AND length(addr_housenumber) <= 20),
    CONSTRAINT device_street_type_ck CHECK (addr_street_type IS NULL
                                            OR (length(addr_street_type) <= 10 AND addr_street IS NOT NULL)),
    CONSTRAINT device_unit_ck       CHECK (addr_unit IS NULL OR addr_housenumber IS NOT NULL),
    CONSTRAINT device_addr_city_ck  CHECK (addr_city IS NOT NULL OR num_nonnulls(addr_street_type, addr_street,
                                           addr_housenumber, addr_unit, addr_postcode) = 0),
    CONSTRAINT device_terc_ck       CHECK (teryt_terc ~ '^\d{7}$'),
    CONSTRAINT device_simc_ck       CHECK (teryt_simc ~ '^\d{7}$'),
    CONSTRAINT device_ulic_ck       CHECK (teryt_ulic IS NULL OR (teryt_ulic ~ '^\d{5}$' AND teryt_simc IS NOT NULL)),
    -- data sprawdzenia jest wymagana przy znanym stanie i niedozwolona przy nieznanym (SCHEMA.md 1.3.0);
    -- „nie z przyszłości” sprawdza walidacja zapisu (API.md §6.3) – CHECK nie może zależeć od bieżącej daty
    CONSTRAINT device_condition_ck  CHECK ((condition = 'unknown') = (condition_checked_at IS NULL))
);

COMMENT ON TABLE  aed.device IS
    'Bieżący stan AED wyliczany z ostatniej wersji (aed.device_version). API nie ma prawa zapisu do tej tabeli.';
COMMENT ON COLUMN aed.device.id                    IS 'Identyfikator aed-<uuid>, nadawany przy pierwszej wersji.';
COMMENT ON COLUMN aed.device.owner_organization_id IS 'Podmiot odpowiedzialny za dane (ROLES.md §12.1).';
COMMENT ON COLUMN aed.device.visibility            IS 'published / flagged („do wyjaśnienia”) / hidden (ukryty przez MC, ROLES.md §14).';
COMMENT ON COLUMN aed.device.last_confirmed_at     IS 'Ostatnie potwierdzenie aktualności danych przez podmiot (ROLES.md §13.4).';
COMMENT ON COLUMN aed.device.lon                   IS 'Długość geograficzna WGS84 (EPSG:4326). W Elasticsearch: pole location (geo_point).';
COMMENT ON COLUMN aed.device.lat                   IS 'Szerokość geograficzna WGS84 (EPSG:4326). W Elasticsearch: pole location (geo_point).';
COMMENT ON COLUMN aed.device.device_count          IS 'Liczba urządzeń w punkcie (pole "count" w GeoJSON).';
COMMENT ON COLUMN aed.device.check_date_from       IS 'check_date jako DATE (brakujący miesiąc/dzień = 01).';
COMMENT ON COLUMN aed.device.address               IS 'Adres do wyświetlenia. Gdy podano addr_*, składany z nich przez aed.compose_address() (SCHEMA.md 1.1.0).';
COMMENT ON COLUMN aed.device.teryt_terc            IS 'Kod gminy TERYT TERC (7 cyfr, WWPPGGR). Tekst – zera wiodące.';
COMMENT ON COLUMN aed.device.teryt_simc            IS 'Identyfikator miejscowości TERYT SIMC (7 cyfr).';
COMMENT ON COLUMN aed.device.teryt_ulic            IS 'Identyfikator ulicy TERYT ULIC (5 cyfr).';
COMMENT ON COLUMN aed.device.condition             IS 'Stan techniczny urządzenia według podmiotu (SCHEMA.md 1.3.0). faulty nie zmienia status – AED nadal wisi w tym miejscu.';
COMMENT ON COLUMN aed.device.condition_checked_at  IS 'Data ostatniego sprawdzenia stanu urządzenia; NULL wtedy i tylko wtedy, gdy condition = unknown.';

CREATE INDEX device_terc_ix          ON aed.device (teryt_terc) WHERE teryt_terc IS NOT NULL;

-- Główne zapytania przestrzenne obsługuje Elasticsearch. Indeks B-tree wystarcza do prostokąta (bbox)
-- w panelu MC i do zapasowych zapytań. Celowo bez indeksu wyrażeniowego na ll_to_earth(): funkcje
-- earthdistance w indeksach bywają problemem przy pg_dump/pg_restore (search_path rozszerzenia).
CREATE INDEX device_latlon_ix        ON aed.device (lat, lon);
CREATE INDEX device_public_latlon_ix ON aed.device (lat, lon) WHERE status = 'active' AND visibility <> 'hidden';
CREATE INDEX device_owner_ix         ON aed.device (owner_organization_id);
CREATE INDEX device_access_ix        ON aed.device (access) WHERE status = 'active';
CREATE INDEX device_confirmed_ix     ON aed.device (last_confirmed_at);

-- Klucze niepubliczne AED do wykrywania duplikatów (DEDUPLIKACJA.md §2.1, SCHEMA.md 1.2.0).
-- Osobna tabela, bo aed.device jest czytelna dla wszystkich wpisów nieukrytych (mapa publiczna),
-- a numer seryjny i identyfikator w systemie podmiotu widzi tylko właściciel i MC.
-- Stan wyliczany z ostatniej wersji przez aed.store_device_keys(); API ma tylko odczyt.
CREATE TABLE aed.manufacturer_alias (
    alias_norm  text PRIMARY KEY CHECK (alias_norm ~ '^[0-9A-Z]+$'),
    canonical   text NOT NULL    CHECK (canonical ~ '^[0-9A-Z]+$')
);

COMMENT ON TABLE aed.manufacturer_alias IS
    'Słownik wariantów nazw producentów → klucz kanoniczny, np. PHILIPSHEALTHCARE → PHILIPS, LIFEPAK → PHYSIOCONTROL. '
    'Utrzymywany migracjami modułu; bez wpisu kluczem jest znormalizowana nazwa (aed.norm_key).';

CREATE TABLE aed.device_key (
    device_id              text PRIMARY KEY REFERENCES aed.device (id),
    owner_organization_id  uuid NOT NULL REFERENCES org.organization (id),
    in_service             boolean NOT NULL,       -- status <> 'removed'
    manufacturer_norm      text,
    serial_number          text CHECK (length(serial_number) <= 50),
    serial_norm            text,
    external_id            text CHECK (length(external_id) BETWEEN 1 AND 100),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT device_key_serial_norm_ck         CHECK ((serial_number IS NULL) = (serial_norm IS NULL)),
    CONSTRAINT device_key_serial_manufacturer_ck CHECK (serial_norm IS NULL OR manufacturer_norm IS NOT NULL)
);

-- Ten sam numer seryjny producenta tylko raz wśród AED w użyciu – w całym rejestrze, niezależnie od podmiotu.
-- TODO(E4): dodać „AND duplicate_of IS NULL”, gdy powstanie aed.device.duplicate_of (DEDUPLIKACJA.md §2.5).
CREATE UNIQUE INDEX device_key_serial_uk   ON aed.device_key (manufacturer_norm, serial_norm)
    WHERE serial_norm IS NOT NULL AND in_service;
-- external_id jest unikalny w obrębie podmiotu (gminy numerują od 1); obejmuje też wpisy wycofane,
-- żeby import w trybie upsert trafiał w ten sam wpis zamiast tworzyć nowy.
CREATE UNIQUE INDEX device_key_external_uk ON aed.device_key (owner_organization_id, external_id)
    WHERE external_id IS NOT NULL;

COMMENT ON TABLE  aed.device_key IS
    'Niepubliczne klucze AED (numer seryjny, identyfikator podmiotu) – deduplikacja, DEDUPLIKACJA.md §2.1.';
COMMENT ON COLUMN aed.device_key.serial_norm IS 'Numer seryjny po aed.norm_key(): wielkie litery, tylko [0-9A-Z].';
COMMENT ON COLUMN aed.device_key.external_id IS
    'Identyfikator AED w systemie właściciela (numer inwentarzowy itp.). Czyszczony przy przekazaniu AED.';

CREATE TABLE aed.device_phone (
    device_id  text     NOT NULL REFERENCES aed.device (id) ON DELETE CASCADE,
    position   smallint NOT NULL CHECK (position >= 0),
    phone      text     NOT NULL CHECK (phone ~ '^\+[1-9]\d{7,14}$'
                                        AND phone NOT IN ('+48112', '+48999', '+48998', '+48997')),
    PRIMARY KEY (device_id, position),
    UNIQUE (device_id, phone)
);

CREATE TABLE aed.device_image (
    device_id  text     NOT NULL REFERENCES aed.device (id) ON DELETE CASCADE,
    position   smallint NOT NULL CHECK (position >= 0),
    url        text     NOT NULL CHECK (url ~* '^https?://'),
    PRIMARY KEY (device_id, position),
    UNIQUE (device_id, url)
);

CREATE TABLE aed.device_version (
    id                         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id                  text        NOT NULL REFERENCES aed.device (id),
    version_no                 integer     NOT NULL CHECK (version_no >= 1),
    site_id                    uuid,
    data                       jsonb       NOT NULL,   -- pełny Feature w formacie SCHEMA.md
    author_user_id             uuid        NOT NULL REFERENCES auth.user_link (id),
    author_organization_id     uuid        NOT NULL REFERENCES org.organization (id),
    author_role                org.org_role NOT NULL,
    confirmation_statement_id  integer     NOT NULL REFERENCES org.responsibility_statement (id),
    confirmed_at               timestamptz NOT NULL,
    import_batch_id            bigint      REFERENCES aed.import_batch (id),
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    prev_sha256                bytea       CHECK (octet_length(prev_sha256) = 32),
    sha256                     bytea       NOT NULL CHECK (octet_length(sha256) = 32),

    CONSTRAINT version_no_uk        UNIQUE (device_id, version_no),
    CONSTRAINT version_feature_ck   CHECK (data ->> 'type' = 'Feature'
                                           AND data #>> '{geometry,type}' = 'Point'
                                           AND jsonb_typeof(data -> 'properties') = 'object'),
    CONSTRAINT version_required_ck  CHECK (data #>> '{properties,location_pl}' IS NOT NULL
                                           AND data #>> '{properties,access}' IS NOT NULL),
    CONSTRAINT version_chain_ck     CHECK ((version_no = 1) = (prev_sha256 IS NULL))
);

CREATE INDEX device_version_author_org_ix ON aed.device_version (author_organization_id);

COMMENT ON TABLE aed.device_version IS
    'Niezmienialna historia danych AED z autorem i potwierdzeniem (ROLES.md §13). '
    'Dopisanie wersji jest JEDYNYM sposobem utworzenia lub zmiany AED.';

ALTER TABLE aed.device
    ADD CONSTRAINT device_current_version_fk FOREIGN KEY (current_version_id)
        REFERENCES aed.device_version (id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aed.device_transfer (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id             text NOT NULL REFERENCES aed.device (id),
    from_organization_id  uuid NOT NULL REFERENCES org.organization (id),
    to_organization_id    uuid NOT NULL REFERENCES org.organization (id),
    basis                 aed.transfer_basis  NOT NULL,
    status                aed.transfer_status NOT NULL DEFAULT 'pending',
    initiated_by          uuid NOT NULL REFERENCES auth.user_link (id),
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL DEFAULT now() + interval '30 days',
    decided_by            uuid REFERENCES auth.user_link (id),
    decided_at            timestamptz,
    succession_document_id uuid REFERENCES org.document (id),

    CONSTRAINT transfer_orgs_ck       CHECK (from_organization_id <> to_organization_id),
    CONSTRAINT transfer_decision_ck   CHECK ((status IN ('pending', 'expired')) = (decided_by IS NULL)),
    CONSTRAINT transfer_four_eyes_ck  CHECK (decided_by IS NULL OR decided_by <> initiated_by),
    CONSTRAINT transfer_succession_ck CHECK (basis <> 'succession' OR succession_document_id IS NOT NULL)
);

CREATE UNIQUE INDEX transfer_open_uk ON aed.device_transfer (device_id) WHERE status = 'pending';

COMMENT ON TABLE aed.device_transfer IS
    'Przekazanie AED innemu podmiotowi (ROLES.md §12.3) lub w ramach sukcesji (§6.4).';

CREATE TABLE aed.mc_intervention (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id              text NOT NULL REFERENCES aed.device (id),
    type                   aed.intervention_type NOT NULL,
    reason                 text NOT NULL CHECK (length(btrim(reason)) >= 10),
    created_by             uuid NOT NULL REFERENCES auth.user_link (id),
    created_at             timestamptz NOT NULL DEFAULT now(),
    approved_by            uuid REFERENCES auth.user_link (id),   -- druga osoba przy 'hide'
    approved_at            timestamptz,
    organization_response  text,
    responded_by           uuid REFERENCES auth.user_link (id),
    responded_at           timestamptz,
    resolved_by            uuid REFERENCES auth.user_link (id),
    resolved_at            timestamptz,
    resolution             text,

    CONSTRAINT intervention_approval_ck  CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT intervention_four_eyes_ck CHECK (approved_by IS NULL OR (type = 'hide' AND approved_by <> created_by)),
    CONSTRAINT intervention_response_ck  CHECK ((responded_by IS NULL) = (responded_at IS NULL)
                                                AND (responded_at IS NULL OR organization_response IS NOT NULL)),
    CONSTRAINT intervention_resolve_ck   CHECK ((resolved_by IS NULL) = (resolved_at IS NULL)
                                                AND (resolved_at IS NULL OR resolution IS NOT NULL))
);

CREATE INDEX mc_intervention_device_ix ON aed.mc_intervention (device_id);

COMMENT ON TABLE aed.mc_intervention IS
    'Interwencje MC: oznaczenie, ukrycie (zasada czterech oczu), przywrócenie (ROLES.md §14). MC nie zmienia treści danych.';

-- =============================================================================
--  6. Tabele: audit
-- =============================================================================

CREATE TABLE audit.event (
    id                       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    chain_seq                bigint      NOT NULL UNIQUE,
    occurred_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor_user_id            uuid,
    actor_role               text,
    organization_context_id  uuid,
    action                   text        NOT NULL,
    object_type              text        NOT NULL,
    object_id                text,
    result                   text        NOT NULL CHECK (result IN ('success', 'denied', 'error')),
    reason                   text,
    ip                       inet,
    session_id               uuid,
    details                  jsonb       NOT NULL DEFAULT '{}',
    prev_sha256              bytea       CHECK (octet_length(prev_sha256) = 32),
    sha256                   bytea       NOT NULL CHECK (octet_length(sha256) = 32)
);

CREATE INDEX audit_event_org_ix    ON audit.event (organization_context_id, occurred_at);
CREATE INDEX audit_event_object_ix ON audit.event (object_type, object_id);

COMMENT ON TABLE audit.event IS
    'Dziennik audytu tylko do dopisywania, łańcuch skrótów po chain_seq (ROLES.md §10). '
    'Kopiowany na bieżąco do magazynu WORM poza bazą. Okres przechowywania: ROLES.md §16 – do tego czasu bez usuwania.';

-- =============================================================================
--  7. Funkcje kontekstu i uprawnień (używane przez RLS)
-- =============================================================================

-- auth.current_user_id(), auth.current_org_id(), auth.has_mc_role(), auth.has_mfa()
-- i auth.has_verified_identity() są zdefiniowane w sql/auth.sql.

-- Aktywna rola w podmiocie. org_admin bez skonfigurowanego MFA nie ma roli (ROLES.md §3.2).
CREATE FUNCTION org.member_role(p_user uuid, p_org uuid) RETURNS org.org_role
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.role
    FROM org.membership m
    JOIN auth.user_account u ON u.id = m.user_id
    WHERE m.user_id = p_user
      AND m.organization_id = p_org
      AND m.revoked_at IS NULL
      AND (m.expires_at IS NULL OR m.expires_at > now())
      AND u.is_active
      AND (m.role <> 'org_admin' OR auth.has_mfa(m.user_id, false))
$$;

-- Wiersz należy do aktywnego podmiotu sesji, a użytkownik naprawdę jest jego członkiem
CREATE FUNCTION org.in_current_org(p_org uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT p_org IS NOT NULL
       AND p_org = auth.current_org_id()
       AND org.member_role(auth.current_user_id(), p_org) IS NOT NULL
$$;

CREATE FUNCTION org.is_current_org_admin(p_org uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT p_org IS NOT NULL
       AND p_org = auth.current_org_id()
       AND org.member_role(auth.current_user_id(), p_org) = 'org_admin'
$$;

-- Czy bieżący użytkownik może zmieniać dane AED w danym podmiocie i lokalizacji (ROLES.md §12)
CREATE FUNCTION org.can_edit_device(p_org uuid, p_site uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_org IS NOT NULL
       AND p_org = auth.current_org_id()
       AND EXISTS (SELECT 1 FROM org.organization o WHERE o.id = p_org AND o.status = 'active')
       AND EXISTS (
           SELECT 1
           FROM org.membership m
           JOIN auth.user_account u ON u.id = m.user_id
           WHERE m.user_id = auth.current_user_id()
             AND m.organization_id = p_org
             AND m.revoked_at IS NULL
             AND (m.expires_at IS NULL OR m.expires_at > now())
             AND u.is_active
             AND (m.role <> 'org_admin' OR auth.has_mfa(m.user_id, false))
             AND (m.role = 'org_admin'
                  OR m.all_sites
                  OR (p_site IS NOT NULL AND EXISTS (
                         SELECT 1 FROM org.membership_site s
                         WHERE s.membership_id = m.id AND s.site_id = p_site)))
       )
$$;

-- =============================================================================
--  8. Audyt: zapis, łańcuch skrótów, niezmienialność
-- =============================================================================

-- Kanoniczny zapis czasu do skrótów: UTC, mikrosekundy, niezależny od TimeZone i DateStyle sesji.
-- Ten sam format eksportuje widok audit.event_export, więc łańcuch można zweryfikować poza bazą (ELK).
CREATE FUNCTION audit.canonical_ts(p timestamptz) RETURNS text
LANGUAGE sql STABLE STRICT SET search_path = pg_catalog AS $$
    SELECT to_char(p AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

-- Tekst wejściowy skrótu zdarzenia audytu (jedna definicja dla zapisu i weryfikacji).
-- Tablica JSON zamiast łączenia separatorem: jednoznacznie koduje NULL i znaki „|” w treści,
-- więc przesunięcie wartości między polami zmienia skrót.
CREATE FUNCTION audit.event_hash_input(e audit.event) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_build_array(
        e.chain_seq, audit.canonical_ts(e.occurred_at), e.actor_user_id, e.actor_role,
        e.organization_context_id, e.action, e.object_type, e.object_id,
        e.result, e.reason, host(e.ip), e.session_id, e.details)::text
$$;

CREATE FUNCTION audit.chain_event() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    v_seq  bigint;
    v_prev bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit.event.chain'));
    SELECT e.chain_seq, e.sha256 INTO v_seq, v_prev
    FROM audit.event e ORDER BY e.chain_seq DESC LIMIT 1;

    NEW.chain_seq   := COALESCE(v_seq, 0) + 1;
    NEW.occurred_at := clock_timestamp();
    NEW.prev_sha256 := v_prev;
    NEW.sha256 := digest(COALESCE(v_prev, ''::bytea) || convert_to(audit.event_hash_input(NEW), 'UTF8'), 'sha256');
    RETURN NEW;
END
$$;

CREATE TRIGGER event_chain BEFORE INSERT ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.chain_event();

CREATE FUNCTION audit.forbid_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Tabela %.% jest tylko do dopisywania (operacja %)', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = '42501';
END
$$;

CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.forbid_change();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event
    FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_change();

-- Zapis zdarzenia z kontekstu sesji. Używane przez triggery i przez API
-- (np. logowanie, odczyt logów przez MC – ROLES.md §10).
CREATE FUNCTION audit.write(
    p_action       text,
    p_object_type  text,
    p_object_id    text,
    p_result       text  DEFAULT 'success',
    p_reason       text  DEFAULT NULL,
    p_details      jsonb DEFAULT '{}',
    p_org          uuid  DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO audit.event (chain_seq, actor_user_id, actor_role, organization_context_id, action,
                             object_type, object_id, result, reason, ip, session_id, details, sha256)
    VALUES (0,   -- nadpisywane przez trigger
            auth.current_user_id(),
            NULLIF(current_setting('app.actor_role', true), ''),
            COALESCE(p_org, auth.current_org_id()),
            p_action, p_object_type, p_object_id, p_result, p_reason,
            NULLIF(current_setting('app.client_ip', true), '')::inet,
            NULLIF(current_setting('app.session_id', true), '')::uuid,
            COALESCE(p_details, '{}'),
            '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);  -- nadpisywane
END
$$;

-- Ogólny trigger audytowy dla tabel ról, podmiotów i danych AED
CREATE FUNCTION audit.capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_old jsonb;
    v_new jsonb;
    v_row jsonb;
    v_org uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN v_old := to_jsonb(OLD) - 'data' - 'body'; END IF;
    IF TG_OP <> 'DELETE' THEN v_new := to_jsonb(NEW) - 'data' - 'body'; END IF;
    v_row := COALESCE(v_new, v_old);
    v_org := COALESCE(CASE WHEN TG_TABLE_NAME = 'organization' THEN v_row ->> 'id' END,
                      v_row ->> 'organization_id', v_row ->> 'author_organization_id',
                      v_row ->> 'owner_organization_id', v_row ->> 'from_organization_id')::uuid;
    PERFORM audit.write(
        lower(TG_OP),
        TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        COALESCE(v_row ->> 'id', v_row ->> 'device_id', v_row ->> 'membership_id'),
        'success', NULL,
        jsonb_strip_nulls(jsonb_build_object('old', v_old, 'new', v_new)),
        v_org);
    RETURN NULL;
END
$$;

-- =============================================================================
--  9. Reguły ról i członkostw (ROLES.md §3.4, §5, §6)
-- =============================================================================

-- Rola MC nie może współistnieć z rolą w podmiocie (ROLES.md §3.4).
-- Reguły samej tabeli auth.mc_role (zasada czterech oczu, min. dwóch mc_admin) są w sql/auth.sql.
CREATE FUNCTION org.mc_role_exclusive() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM org.membership m WHERE m.user_id = NEW.user_id AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Użytkownik ma aktywne członkostwo w podmiocie – nie może dostać roli MC'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER mc_role_exclusive BEFORE INSERT ON auth.mc_role
    FOR EACH ROW EXECUTE FUNCTION org.mc_role_exclusive();
CREATE TRIGGER mc_role_audit AFTER INSERT OR UPDATE ON auth.mc_role
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

CREATE FUNCTION org.membership_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_status org.organization_status;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF EXISTS (SELECT 1 FROM auth.mc_role r WHERE r.user_id = NEW.user_id AND r.revoked_at IS NULL) THEN
            RAISE EXCEPTION 'Pracownik MC nie może mieć roli w podmiocie (ROLES.md §3.4)' USING ERRCODE = '42501';
        END IF;
        IF NEW.role = 'org_admin' AND NOT auth.has_verified_identity(NEW.user_id, 'login_gov_pl') THEN
            RAISE EXCEPTION 'org_admin musi mieć tożsamość potwierdzoną przez login.gov.pl (ROLES.md §5.3)'
                USING ERRCODE = '42501';
        END IF;
        SELECT status INTO v_status FROM org.organization WHERE id = NEW.organization_id;
        IF v_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'Podmiot nie jest aktywny (status %)', v_status USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    -- UPDATE: niezmienne pola członkostwa
    IF NEW.user_id <> OLD.user_id OR NEW.organization_id <> OLD.organization_id OR NEW.role <> OLD.role
       OR NEW.granted_by <> OLD.granted_by OR NEW.granted_at <> OLD.granted_at THEN
        RAISE EXCEPTION 'Zmiana roli = odwołanie członkostwa i nadanie nowego' USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'Odwołanego członkostwa nie można zmieniać' USING ERRCODE = '42501';
    END IF;
    IF NEW.revoked_at IS NOT NULL AND auth.current_user_id() IS NOT NULL
       AND NEW.revoked_by IS DISTINCT FROM auth.current_user_id() THEN
        RAISE EXCEPTION 'revoked_by musi być bieżącym użytkownikiem' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER membership_guard BEFORE INSERT OR UPDATE ON org.membership
    FOR EACH ROW EXECUTE FUNCTION org.membership_guard();

-- Po zmianie członkostwa: unieważnienie sesji; utrata ostatniego org_admin → status orphaned (ROLES.md §6.3)
CREATE FUNCTION org.membership_after() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM auth.revoke_user_sessions(NEW.user_id, 'membership_change');

    IF TG_OP = 'UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND OLD.role = 'org_admin'
       AND NOT EXISTS (SELECT 1 FROM org.membership m
                       WHERE m.organization_id = NEW.organization_id AND m.role = 'org_admin'
                         AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at > now())) THEN
        UPDATE org.organization
           SET status = 'orphaned', status_reason = 'Brak aktywnego administratora podmiotu',
               status_changed_at = now(), status_changed_by = auth.current_user_id(), updated_at = now()
         WHERE id = NEW.organization_id AND status = 'active';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER membership_after AFTER INSERT OR UPDATE ON org.membership
    FOR EACH ROW EXECUTE FUNCTION org.membership_after();
CREATE TRIGGER membership_audit AFTER INSERT OR UPDATE ON org.membership
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

CREATE FUNCTION org.membership_site_after() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_row org.membership_site;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := OLD;
    ELSE
        v_row := NEW;
    END IF;
    PERFORM auth.revoke_user_sessions(m.user_id, 'site_scope_change')
    FROM org.membership m WHERE m.id = v_row.membership_id;
    RETURN NULL;
END
$$;

CREATE TRIGGER membership_site_after AFTER INSERT OR DELETE ON org.membership_site
    FOR EACH ROW EXECUTE FUNCTION org.membership_site_after();
CREATE TRIGGER membership_site_audit AFTER INSERT OR DELETE ON org.membership_site
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

CREATE FUNCTION org.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;

CREATE TRIGGER organization_touch BEFORE UPDATE ON org.organization
    FOR EACH ROW EXECUTE FUNCTION org.touch_updated_at();
CREATE TRIGGER device_touch BEFORE UPDATE ON aed.device
    FOR EACH ROW EXECUTE FUNCTION org.touch_updated_at();

CREATE TRIGGER organization_audit AFTER INSERT OR UPDATE ON org.organization
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER site_audit AFTER INSERT OR UPDATE ON org.site
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER registration_audit AFTER INSERT OR UPDATE ON org.registration_request
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER document_audit AFTER INSERT ON org.document
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER acceptance_audit AFTER INSERT ON org.statement_acceptance
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER access_review_audit AFTER INSERT ON org.access_review
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER invitation_audit AFTER INSERT OR UPDATE ON org.invitation
    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER import_batch_audit AFTER INSERT ON aed.import_batch
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

-- =============================================================================
--  10. Rejestracja i cykl życia podmiotów (ROLES.md §5.1, §6.3, §6.4)
-- =============================================================================

-- Złożenie wniosku przez osobę zalogowaną przez login.gov.pl
CREATE FUNCTION org.submit_registration(
    p_name text, p_type org.organization_type,
    p_nip text, p_regon text, p_krs text, p_teryt text, p_healthcare_no text,
    p_address text, p_contact_email text,
    p_basis org.representation_basis, p_statement_id integer
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_user uuid := auth.current_user_id();
    v_org  uuid;
    v_req  uuid;
BEGIN
    IF NOT auth.has_verified_identity(v_user, 'login_gov_pl') THEN
        RAISE EXCEPTION 'Wniosek wymaga tożsamości potwierdzonej przez login.gov.pl' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM auth.mc_role r WHERE r.user_id = v_user AND r.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Pracownik MC nie może składać wniosku w imieniu podmiotu' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM org.responsibility_statement s
                   WHERE s.id = p_statement_id AND s.kind = 'registration' AND s.valid_from <= now()) THEN
        RAISE EXCEPTION 'Nieprawidłowe oświadczenie o odpowiedzialności' USING ERRCODE = '22023';
    END IF;

    INSERT INTO org.organization (name, type, nip, regon, krs, teryt, healthcare_register_no,
                                  address, contact_email, status)
    VALUES (p_name, p_type, NULLIF(p_nip, ''), NULLIF(p_regon, ''), NULLIF(p_krs, ''),
            NULLIF(p_teryt, ''), NULLIF(p_healthcare_no, ''), p_address, p_contact_email, 'pending')
    RETURNING id INTO v_org;

    INSERT INTO org.registration_request (organization_id, applicant_id, representation_basis, statement_id)
    VALUES (v_org, v_user, p_basis, p_statement_id)
    RETURNING id INTO v_req;

    INSERT INTO org.statement_acceptance (organization_id, statement_id, user_id, ip)
    VALUES (v_org, p_statement_id, v_user, NULLIF(current_setting('app.client_ip', true), '')::inet);

    RETURN v_req;
END
$$;

-- Wniosek o nowego org_admin dla podmiotu bez administratora (ROLES.md §6.3)
CREATE FUNCTION org.submit_admin_request(p_org uuid, p_basis org.representation_basis, p_statement_id integer)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_user uuid := auth.current_user_id();
    v_req  uuid;
BEGIN
    IF NOT auth.has_verified_identity(v_user, 'login_gov_pl') THEN
        RAISE EXCEPTION 'Wniosek wymaga tożsamości potwierdzonej przez login.gov.pl' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM org.organization o WHERE o.id = p_org AND o.status = 'orphaned') THEN
        RAISE EXCEPTION 'Podmiot nie ma statusu orphaned' USING ERRCODE = '22023';
    END IF;
    INSERT INTO org.registration_request (organization_id, applicant_id, representation_basis, statement_id)
    VALUES (p_org, v_user, p_basis, p_statement_id)
    RETURNING id INTO v_req;
    RETURN v_req;
END
$$;

CREATE FUNCTION org.verify_registration(p_request uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT auth.has_mc_role('mc_operator') THEN
        RAISE EXCEPTION 'Wymagana rola mc_operator' USING ERRCODE = '42501';
    END IF;
    UPDATE org.registration_request
       SET status = 'verified', verified_by = auth.current_user_id(), verified_at = now()
     WHERE id = p_request AND status = 'submitted';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wniosek nie istnieje lub nie ma statusu submitted' USING ERRCODE = '22023';
    END IF;
END
$$;

-- Zatwierdzenie (druga osoba): podmiot → active, wnioskodawca → org_admin
CREATE FUNCTION org.approve_registration(p_request uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_me  uuid := auth.current_user_id();
    v_req org.registration_request;
BEGIN
    IF NOT auth.has_mc_role('mc_operator') THEN
        RAISE EXCEPTION 'Wymagana rola mc_operator' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_req FROM org.registration_request WHERE id = p_request FOR UPDATE;
    IF NOT FOUND OR v_req.status <> 'verified' THEN
        RAISE EXCEPTION 'Wniosek nie istnieje lub nie ma statusu verified' USING ERRCODE = '22023';
    END IF;
    IF v_me = v_req.verified_by THEN
        RAISE EXCEPTION 'Zatwierdza inna osoba niż weryfikująca (zasada czterech oczu)' USING ERRCODE = '42501';
    END IF;

    UPDATE org.registration_request
       SET status = 'approved', approved_by = v_me, approved_at = now()
     WHERE id = p_request;

    UPDATE org.organization
       SET status = 'active', status_reason = NULL, status_changed_at = now(), status_changed_by = v_me,
           verified_by = COALESCE(verified_by, v_req.verified_by),
           approved_by = COALESCE(approved_by, v_me),
           approved_at = COALESCE(approved_at, now())
     WHERE id = v_req.organization_id AND status IN ('pending', 'orphaned');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Podmiot nie ma statusu pending ani orphaned' USING ERRCODE = '22023';
    END IF;

    INSERT INTO org.membership (user_id, organization_id, role, all_sites, granted_by)
    VALUES (v_req.applicant_id, v_req.organization_id, 'org_admin', true, v_me);
END
$$;

CREATE FUNCTION org.reject_registration(p_request uuid, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_org uuid;
BEGIN
    IF NOT auth.has_mc_role('mc_operator') THEN
        RAISE EXCEPTION 'Wymagana rola mc_operator' USING ERRCODE = '42501';
    END IF;
    UPDATE org.registration_request
       SET status = 'rejected', decision_reason = p_reason,
           verified_by = COALESCE(verified_by, auth.current_user_id()),
           verified_at = COALESCE(verified_at, now())
     WHERE id = p_request AND status IN ('submitted', 'verified')
    RETURNING organization_id INTO v_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wniosek nie istnieje lub został już rozpatrzony' USING ERRCODE = '22023';
    END IF;
END
$$;

-- Zaproszenie: walidacja przy utworzeniu (zapraszający = bieżący org_admin, lokalizacje z tego podmiotu)
CREATE FUNCTION org.invitation_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.invited_by IS DISTINCT FROM auth.current_user_id()
           OR NOT org.is_current_org_admin(NEW.organization_id) THEN
            RAISE EXCEPTION 'Zaprasza org_admin podmiotu jako bieżący użytkownik' USING ERRCODE = '42501';
        END IF;
        IF NEW.accepted_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'Nowe zaproszenie nie może być przyjęte ani odwołane' USING ERRCODE = '22023';
        END IF;
        IF EXISTS (SELECT 1 FROM unnest(NEW.site_ids) AS s(id)
                   WHERE NOT EXISTS (SELECT 1 FROM org.site t
                                     WHERE t.id = s.id AND t.organization_id = NEW.organization_id)) THEN
            RAISE EXCEPTION 'Lokalizacja spoza podmiotu' USING ERRCODE = '22023';
        END IF;
        RETURN NEW;
    END IF;
    -- UPDATE przez API: wyłącznie odwołanie otwartego zaproszenia
    IF OLD.accepted_at IS NOT NULL OR OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Zaproszenie zostało już rozpatrzone' USING ERRCODE = '22023';
    END IF;
    IF NEW.revoked_at IS NOT NULL AND auth.current_user_id() IS NOT NULL
       AND NEW.revoked_by IS DISTINCT FROM auth.current_user_id() THEN
        RAISE EXCEPTION 'revoked_by musi być bieżącym użytkownikiem' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invitation_guard BEFORE INSERT OR UPDATE ON org.invitation
    FOR EACH ROW EXECUTE FUNCTION org.invitation_guard();

-- Przyjęcie zaproszenia przez zalogowanego użytkownika o tym samym, potwierdzonym adresie e-mail.
-- p_token_hash = SHA-256 tokenu z linku (token nigdy nie trafia do bazy w postaci jawnej).
CREATE FUNCTION org.accept_invitation(p_token_hash bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_user uuid := auth.current_user_id();
    i      org.invitation;
    v_mid  bigint;
BEGIN
    SELECT * INTO i FROM org.invitation WHERE token_hash = p_token_hash FOR UPDATE;
    -- jeden ogólny komunikat dla wszystkich przypadków (bez ujawniania, który warunek zawiódł)
    IF NOT FOUND OR i.accepted_at IS NOT NULL OR i.revoked_at IS NOT NULL OR i.expires_at <= now()
       OR NOT EXISTS (SELECT 1 FROM auth.user_account u
                      WHERE u.id = v_user AND u.is_active AND u.email = i.email
                        AND u.email_verified_at IS NOT NULL)
       OR org.member_role(i.invited_by, i.organization_id) IS DISTINCT FROM 'org_admin' THEN
        RAISE EXCEPTION 'Zaproszenie jest nieprawidłowe lub wygasło' USING ERRCODE = '42501';
    END IF;

    INSERT INTO org.membership (user_id, organization_id, role, all_sites, granted_by)
    VALUES (v_user, i.organization_id, i.role, i.all_sites, i.invited_by)
    RETURNING id INTO v_mid;

    INSERT INTO org.membership_site (membership_id, organization_id, site_id)
    SELECT v_mid, i.organization_id, s.id FROM unnest(i.site_ids) AS s(id);

    UPDATE org.invitation SET accepted_at = now(), accepted_by = v_user WHERE id = i.id;
    RETURN i.organization_id;
END
$$;

-- Zawieszenie / przywrócenie / likwidacja podmiotu przez mc_operator (ROLES.md §6.4)
CREATE FUNCTION org.set_status(p_org uuid, p_status org.organization_status, p_reason text, p_successor uuid DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_old org.organization_status;
BEGIN
    IF NOT auth.has_mc_role('mc_operator') THEN
        RAISE EXCEPTION 'Wymagana rola mc_operator' USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN
        RAISE EXCEPTION 'Wymagane uzasadnienie' USING ERRCODE = '22023';
    END IF;
    SELECT status INTO v_old FROM org.organization WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Podmiot nie istnieje' USING ERRCODE = '22023';
    END IF;
    IF NOT (   (v_old = 'active'    AND p_status = 'suspended')
            OR (v_old = 'suspended' AND p_status = 'active')
            OR (v_old IN ('active', 'suspended', 'orphaned') AND p_status = 'dissolved')) THEN
        RAISE EXCEPTION 'Niedozwolona zmiana statusu % → %', v_old, p_status USING ERRCODE = '22023';
    END IF;
    IF p_status = 'dissolved' AND EXISTS (SELECT 1 FROM aed.device d
                                          WHERE d.owner_organization_id = p_org AND d.status <> 'removed') THEN
        RAISE EXCEPTION 'Przed likwidacją AED muszą zostać przekazane lub wycofane' USING ERRCODE = '23514';
    END IF;

    UPDATE org.organization
       SET status = p_status, status_reason = p_reason, status_changed_at = now(),
           status_changed_by = auth.current_user_id(),
           successor_id = CASE WHEN p_status = 'dissolved' THEN p_successor END
     WHERE id = p_org;

    IF p_status IN ('suspended', 'dissolved') THEN
        UPDATE auth.session SET revoked_at = now(), revoke_reason = 'organization_' || p_status::text
         WHERE organization_id = p_org AND revoked_at IS NULL;
    END IF;
END
$$;

-- =============================================================================
--  11. Dane AED: wersje, przekazania, interwencje MC (ROLES.md §12–§14)
-- =============================================================================

-- Adres do wyświetlenia (SCHEMA.md 1.1.0). Gdy właściwości mają części adresu (addr_*), adres jest z nich
-- składany: "{cecha} {ulica} {nr}[/{lokal}], {kod} {miejscowość}"; bez ulicy: "{miejscowość} {nr}, {kod} {miejscowość}".
-- Bez części – zwraca przesłany tekst address (format 1.0.0).
CREATE FUNCTION aed.compose_address(p jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT CASE
        WHEN num_nonnulls(p ->> 'addr_street_type', p ->> 'addr_street', p ->> 'addr_housenumber',
                          p ->> 'addr_unit', p ->> 'addr_postcode', p ->> 'addr_city') = 0
            THEN p ->> 'address'
        ELSE NULLIF(concat_ws(', ',
            NULLIF(concat_ws(' ',
                p ->> 'addr_street_type',
                COALESCE(p ->> 'addr_street',
                         CASE WHEN p ->> 'addr_housenumber' IS NOT NULL THEN p ->> 'addr_city' END),
                (p ->> 'addr_housenumber') || COALESCE('/' || (p ->> 'addr_unit'), '')), ''),
            NULLIF(concat_ws(' ', p ->> 'addr_postcode', p ->> 'addr_city'), '')), '')
    END
$$;

-- Normalizacja kluczy do porównań (DEDUPLIKACJA.md §2.1): „AB-12 34” = „ab1234”.
CREATE FUNCTION aed.norm_key(p text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT NULLIF(upper(regexp_replace(p, '[^0-9A-Za-z]', '', 'g')), '')
$$;

CREATE FUNCTION aed.manufacturer_key(p text) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT COALESCE((SELECT a.canonical FROM aed.manufacturer_alias a WHERE a.alias_norm = aed.norm_key(p)),
                    aed.norm_key(p))
$$;

-- Zapis kluczy niepublicznych z danych wersji. Wywoływana tylko z aed.apply_version().
-- Konflikt zgłaszany jako 23505 z nazwą indeksu w CONSTRAINT i w DETAIL: identyfikator AED, gdy należy do tego
-- samego podmiotu, albo 'other_owner' – bez ujawniania danych innego podmiotu (API.md §2.3: duplicate_device*).
-- Wyścig dwóch transakcji kończy się zwykłym naruszeniem indeksu unikalnego; API klasyfikuje je wtedy
-- przez aed.match_device_keys().
CREATE FUNCTION aed.store_device_keys(p_device text, p_owner uuid, p_status aed.device_status, p jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_serial    text := NULLIF(btrim(p ->> 'serial_number'), '');
    v_serial_n  text := aed.norm_key(p ->> 'serial_number');
    v_manuf_n   text := aed.manufacturer_key(p ->> 'manufacturer');
    v_external  text := NULLIF(btrim(p ->> 'external_id'), '');
    v_other     aed.device_key;
BEGIN
    IF v_serial IS NOT NULL AND v_serial_n IS NULL THEN
        RAISE EXCEPTION 'Numer seryjny musi zawierać litery lub cyfry'
            USING ERRCODE = '23514', CONSTRAINT = 'device_key_serial_norm_ck';
    END IF;
    IF v_serial_n IS NOT NULL AND v_manuf_n IS NULL THEN
        RAISE EXCEPTION 'Numer seryjny wymaga podania producenta'
            USING ERRCODE = '23514', CONSTRAINT = 'device_key_serial_manufacturer_ck';
    END IF;

    IF v_serial_n IS NOT NULL AND p_status <> 'removed' THEN
        SELECT * INTO v_other FROM aed.device_key k
        WHERE k.manufacturer_norm = v_manuf_n AND k.serial_norm = v_serial_n AND k.in_service
          AND k.device_id <> p_device;
        IF FOUND THEN
            RAISE EXCEPTION 'AED o tym numerze seryjnym jest już w rejestrze'
                USING ERRCODE = '23505', CONSTRAINT = 'device_key_serial_uk',
                      DETAIL = CASE WHEN v_other.owner_organization_id = p_owner
                                    THEN v_other.device_id ELSE 'other_owner' END;
        END IF;
    END IF;

    IF v_external IS NOT NULL THEN
        SELECT * INTO v_other FROM aed.device_key k
        WHERE k.owner_organization_id = p_owner AND k.external_id = v_external AND k.device_id <> p_device;
        IF FOUND THEN
            RAISE EXCEPTION 'AED o tym identyfikatorze podmiotu (external_id) jest już w rejestrze'
                USING ERRCODE = '23505', CONSTRAINT = 'device_key_external_uk', DETAIL = v_other.device_id;
        END IF;
    END IF;

    INSERT INTO aed.device_key AS k (device_id, owner_organization_id, in_service, manufacturer_norm,
                                     serial_number, serial_norm, external_id)
    VALUES (p_device, p_owner, p_status <> 'removed', v_manuf_n,
            CASE WHEN v_serial_n IS NOT NULL THEN v_serial END, v_serial_n, v_external)
    ON CONFLICT (device_id) DO UPDATE SET
        owner_organization_id = EXCLUDED.owner_organization_id, in_service = EXCLUDED.in_service,
        manufacturer_norm = EXCLUDED.manufacturer_norm, serial_number = EXCLUDED.serial_number,
        serial_norm = EXCLUDED.serial_norm, external_id = EXCLUDED.external_id, updated_at = now();
END
$$;

-- Sprawdzenie kluczy przed zapisem: pojedynczy zapis, import (także dry_run) i klasyfikacja błędu 23505.
-- Zwraca identyfikator AED tylko z bieżącego podmiotu; dla innego podmiotu – sam fakt istnienia.
CREATE FUNCTION aed.match_device_keys(p_manufacturer text, p_serial text, p_external_id text)
RETURNS TABLE (key text, device_id text, same_owner boolean, in_service boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT 'serial_number',
           CASE WHEN k.owner_organization_id = auth.current_org_id() THEN k.device_id END,
           k.owner_organization_id = auth.current_org_id(), k.in_service
    FROM aed.device_key k
    WHERE auth.current_org_id() IS NOT NULL
      AND aed.norm_key(p_serial) IS NOT NULL
      AND k.manufacturer_norm = aed.manufacturer_key(p_manufacturer)
      AND k.serial_norm = aed.norm_key(p_serial)
      AND k.in_service
    UNION ALL
    SELECT 'external_id', k.device_id, true, k.in_service
    FROM aed.device_key k
    WHERE k.owner_organization_id = auth.current_org_id()
      AND k.external_id = NULLIF(btrim(p_external_id), '')
$$;

-- Dopisanie wersji = utworzenie lub zmiana AED. Wylicza autora, łańcuch skrótów i bieżący stan.
CREATE FUNCTION aed.apply_version() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    v_user      uuid := auth.current_user_id();
    v_org       uuid := auth.current_org_id();
    v_role      org.org_role;
    v_owner     uuid;
    v_old_site  uuid;
    v_prev      bytea;
    v_no        integer;
    v_lon       numeric(9, 6);
    v_lat       numeric(8, 6);
    p           jsonb;
BEGIN
    -- autor = bieżący użytkownik w bieżącym podmiocie (niezaprzeczalność, ROLES.md §13.3)
    IF v_user IS NULL OR v_org IS NULL
       OR NEW.author_user_id IS DISTINCT FROM v_user
       OR NEW.author_organization_id IS DISTINCT FROM v_org THEN
        RAISE EXCEPTION 'Autor wersji musi być bieżącym użytkownikiem w bieżącym podmiocie' USING ERRCODE = '42501';
    END IF;
    v_role := org.member_role(v_user, v_org);
    IF v_role IS NULL OR NOT org.can_edit_device(v_org, NEW.site_id) THEN
        RAISE EXCEPTION 'Brak uprawnień do zmiany danych AED' USING ERRCODE = '42501';
    END IF;
    NEW.author_role := v_role;

    -- podmiot zaakceptował aktualne oświadczenie o odpowiedzialności (ROLES.md §13.1)
    IF NOT EXISTS (
        SELECT 1 FROM org.statement_acceptance a
        WHERE a.organization_id = v_org
          AND a.statement_id = (SELECT s.id FROM org.responsibility_statement s
                                WHERE s.kind = 'registration' AND s.valid_from <= now()
                                ORDER BY s.valid_from DESC LIMIT 1)) THEN
        RAISE EXCEPTION 'Podmiot musi zaakceptować aktualne oświadczenie o odpowiedzialności' USING ERRCODE = '42501';
    END IF;

    -- potwierdzenie zmiany (ROLES.md §13.2)
    IF NOT EXISTS (SELECT 1 FROM org.responsibility_statement s
                   WHERE s.id = NEW.confirmation_statement_id AND s.kind = 'change_confirmation') THEN
        RAISE EXCEPTION 'Wymagane potwierdzenie zgodności danych ze stanem faktycznym' USING ERRCODE = '22023';
    END IF;

    -- import zbiorczy tylko przez org_admin własnego podmiotu
    IF NEW.import_batch_id IS NOT NULL AND (v_role <> 'org_admin' OR NOT EXISTS (
            SELECT 1 FROM aed.import_batch b WHERE b.id = NEW.import_batch_id AND b.organization_id = v_org)) THEN
        RAISE EXCEPTION 'Nieprawidłowy import zbiorczy' USING ERRCODE = '42501';
    END IF;
    -- import w trybie create nie zmienia istniejących AED (DEDUPLIKACJA.md §2.2)
    IF NEW.import_batch_id IS NOT NULL AND NEW.device_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM aed.import_batch b WHERE b.id = NEW.import_batch_id AND b.mode = 'create') THEN
        RAISE EXCEPTION 'Import w trybie create nie może aktualizować istniejących AED' USING ERRCODE = '22023';
    END IF;

    IF NEW.device_id IS NULL THEN
        NEW.device_id := 'aed-' || gen_random_uuid()::text;
        v_no := 1;
    ELSE
        SELECT d.owner_organization_id, d.site_id INTO v_owner, v_old_site
        FROM aed.device d WHERE d.id = NEW.device_id FOR UPDATE;
        IF NOT FOUND OR v_owner <> v_org OR NOT org.can_edit_device(v_org, v_old_site) THEN
            RAISE EXCEPTION 'Brak uprawnień do zmiany danych AED' USING ERRCODE = '42501';
        END IF;
        SELECT v.version_no, v.sha256 INTO v_no, v_prev
        FROM aed.device_version v WHERE v.device_id = NEW.device_id
        ORDER BY v.version_no DESC LIMIT 1;
        v_no := COALESCE(v_no, 0) + 1;
    END IF;

    NEW.data := jsonb_set(jsonb_set(NEW.data, '{id}', to_jsonb(NEW.device_id)),
                          '{properties,id}', to_jsonb(NEW.device_id));
    -- adres złożony z części trafia do danych wersji przed policzeniem skrótu (SCHEMA.md 1.1.0)
    IF aed.compose_address(NEW.data -> 'properties') IS NOT NULL THEN
        NEW.data := jsonb_set(NEW.data, '{properties,address}',
                              to_jsonb(aed.compose_address(NEW.data -> 'properties')));
    END IF;
    NEW.version_no  := v_no;
    NEW.prev_sha256 := v_prev;
    NEW.created_at  := clock_timestamp();
    -- czasy w postaci kanonicznej (UTC), żeby skrót nie zależał od ustawień TimeZone/DateStyle sesji
    -- i dał się przeliczyć poza bazą (np. w kopii w ELK, sekcja 16)
    NEW.sha256 := digest(
        COALESCE(v_prev, ''::bytea) || convert_to(jsonb_build_array(
            NEW.device_id, NEW.version_no, NEW.site_id, NEW.author_user_id, NEW.author_organization_id,
            NEW.author_role, NEW.confirmation_statement_id, audit.canonical_ts(NEW.confirmed_at),
            NEW.import_batch_id, audit.canonical_ts(NEW.created_at), NEW.data)::text, 'UTF8'),
        'sha256');

    -- bieżący stan urządzenia
    p := NEW.data -> 'properties';
    v_lon := round((NEW.data #>> '{geometry,coordinates,0}')::numeric, 6);
    v_lat := round((NEW.data #>> '{geometry,coordinates,1}')::numeric, 6);

    INSERT INTO aed.device AS d (
        id, owner_organization_id, site_id, status, current_version_id, last_confirmed_at, lon, lat,
        access, opening_hours, is_24_7, seasonal, access_note, locked,
        indoor, level, location_pl, location_en, description, description_en,
        vehicle_mounted, portable, device_count, address,
        addr_street_type, addr_street, addr_housenumber, addr_unit, addr_postcode, addr_city,
        teryt_terc, teryt_simc, teryt_ulic,
        name, operator, operator_short, email, website, manufacturer, model,
        condition, condition_checked_at,
        check_date, needs_verification, fixme, source, import_batch_id)
    VALUES (
        NEW.device_id, v_org, NEW.site_id,
        COALESCE((p ->> 'status')::aed.device_status, 'active'), NEW.id, NEW.confirmed_at, v_lon, v_lat,
        COALESCE((p ->> 'access')::aed.access_level, 'unknown'), p ->> 'opening_hours',
        (p ->> 'is_24_7')::boolean, COALESCE((p ->> 'seasonal')::boolean, false),
        p ->> 'access_note', (p ->> 'locked')::boolean,
        (p ->> 'indoor')::boolean, (p ->> 'level')::numeric, p ->> 'location_pl', p ->> 'location_en',
        p ->> 'description', p ->> 'description_en',
        COALESCE((p ->> 'vehicle_mounted')::boolean, false), COALESCE((p ->> 'portable')::boolean, false),
        COALESCE((p ->> 'count')::smallint, 1), p ->> 'address',
        p ->> 'addr_street_type', p ->> 'addr_street', p ->> 'addr_housenumber', p ->> 'addr_unit',
        p ->> 'addr_postcode', p ->> 'addr_city',
        p ->> 'teryt_terc', p ->> 'teryt_simc', p ->> 'teryt_ulic',
        p ->> 'name', p ->> 'operator', p ->> 'operator_short', p ->> 'email', p ->> 'website',
        p ->> 'manufacturer', p ->> 'model',
        COALESCE((p ->> 'condition')::aed.device_condition, 'unknown'), (p ->> 'condition_checked_at')::date,
        p ->> 'check_date', COALESCE((p ->> 'needs_verification')::boolean, false),
        p ->> 'fixme', p ->> 'source', NEW.import_batch_id)
    ON CONFLICT (id) DO UPDATE SET
        site_id = EXCLUDED.site_id, status = EXCLUDED.status,
        current_version_id = EXCLUDED.current_version_id, last_confirmed_at = EXCLUDED.last_confirmed_at,
        lon = EXCLUDED.lon, lat = EXCLUDED.lat, access = EXCLUDED.access, opening_hours = EXCLUDED.opening_hours,
        is_24_7 = EXCLUDED.is_24_7, seasonal = EXCLUDED.seasonal, access_note = EXCLUDED.access_note,
        locked = EXCLUDED.locked, indoor = EXCLUDED.indoor, level = EXCLUDED.level,
        location_pl = EXCLUDED.location_pl, location_en = EXCLUDED.location_en,
        description = EXCLUDED.description, description_en = EXCLUDED.description_en,
        vehicle_mounted = EXCLUDED.vehicle_mounted, portable = EXCLUDED.portable,
        device_count = EXCLUDED.device_count, address = EXCLUDED.address,
        addr_street_type = EXCLUDED.addr_street_type, addr_street = EXCLUDED.addr_street,
        addr_housenumber = EXCLUDED.addr_housenumber, addr_unit = EXCLUDED.addr_unit,
        addr_postcode = EXCLUDED.addr_postcode, addr_city = EXCLUDED.addr_city,
        teryt_terc = EXCLUDED.teryt_terc, teryt_simc = EXCLUDED.teryt_simc, teryt_ulic = EXCLUDED.teryt_ulic,
        name = EXCLUDED.name, operator = EXCLUDED.operator, operator_short = EXCLUDED.operator_short,
        email = EXCLUDED.email, website = EXCLUDED.website,
        manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model,
        condition = EXCLUDED.condition, condition_checked_at = EXCLUDED.condition_checked_at,
        check_date = EXCLUDED.check_date, needs_verification = EXCLUDED.needs_verification,
        fixme = EXCLUDED.fixme, source = EXCLUDED.source, import_batch_id = EXCLUDED.import_batch_id;

    DELETE FROM aed.device_phone WHERE device_id = NEW.device_id;
    INSERT INTO aed.device_phone (device_id, position, phone)
    SELECT NEW.device_id, (t.ord - 1)::smallint, t.value
    FROM jsonb_array_elements_text(COALESCE(p -> 'phones', '[]')) WITH ORDINALITY AS t(value, ord);

    DELETE FROM aed.device_image WHERE device_id = NEW.device_id;
    INSERT INTO aed.device_image (device_id, position, url)
    SELECT NEW.device_id, (t.ord - 1)::smallint, t.value
    FROM jsonb_array_elements_text(COALESCE(p -> 'images', '[]')) WITH ORDINALITY AS t(value, ord);

    -- klucze niepubliczne i kontrola duplikatów (DEDUPLIKACJA.md §2.1)
    PERFORM aed.store_device_keys(NEW.device_id, v_org,
                                  COALESCE((p ->> 'status')::aed.device_status, 'active'), p);

    RETURN NEW;
END
$$;

CREATE TRIGGER device_version_apply BEFORE INSERT ON aed.device_version
    FOR EACH ROW EXECUTE FUNCTION aed.apply_version();
CREATE TRIGGER device_version_append_only BEFORE UPDATE OR DELETE ON aed.device_version
    FOR EACH ROW EXECUTE FUNCTION audit.forbid_change();
CREATE TRIGGER device_version_no_truncate BEFORE TRUNCATE ON aed.device_version
    FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_change();
CREATE TRIGGER device_version_audit AFTER INSERT ON aed.device_version
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

-- Zakaz fizycznego usuwania AED – wycofanie to wersja ze statusem removed (ROLES.md §13.3)
CREATE TRIGGER device_no_delete BEFORE DELETE ON aed.device
    FOR EACH ROW EXECUTE FUNCTION audit.forbid_change();
CREATE TRIGGER device_no_truncate BEFORE TRUNCATE ON aed.device
    FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_change();

-- Coroczne potwierdzenie aktualności bez zmiany danych (ROLES.md §13.4)
CREATE FUNCTION aed.confirm_device(p_device text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_owner uuid;
    v_site  uuid;
BEGIN
    SELECT owner_organization_id, site_id INTO v_owner, v_site FROM aed.device WHERE id = p_device FOR UPDATE;
    IF NOT FOUND OR NOT org.can_edit_device(v_owner, v_site) THEN
        RAISE EXCEPTION 'Brak uprawnień do potwierdzenia danych AED' USING ERRCODE = '42501';
    END IF;
    UPDATE aed.device SET last_confirmed_at = now() WHERE id = p_device;
    PERFORM audit.write('confirm', 'aed.device', p_device, 'success', NULL, '{}', v_owner);
END
$$;

-- Przekazanie AED: walidacja wniosku
CREATE FUNCTION aed.transfer_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM aed.device d
                   WHERE d.id = NEW.device_id AND d.owner_organization_id = NEW.from_organization_id) THEN
        RAISE EXCEPTION 'Podmiot przekazujący nie jest właścicielem AED' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM org.organization o WHERE o.id = NEW.to_organization_id AND o.status = 'active') THEN
        RAISE EXCEPTION 'Podmiot przyjmujący nie jest aktywny' USING ERRCODE = '22023';
    END IF;
    IF NEW.status <> 'pending' OR NEW.decided_by IS NOT NULL THEN
        RAISE EXCEPTION 'Nowe przekazanie musi mieć status pending' USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER transfer_guard BEFORE INSERT ON aed.device_transfer
    FOR EACH ROW EXECUTE FUNCTION aed.transfer_guard();
CREATE TRIGGER transfer_audit AFTER INSERT OR UPDATE ON aed.device_transfer
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

-- Decyzja o przekazaniu:
--   agreement  – org_admin podmiotu przyjmującego (w kontekście tego podmiotu),
--   succession – inny mc_operator niż wnioskujący (zasada czterech oczu).
CREATE FUNCTION aed.decide_transfer(p_transfer uuid, p_accept boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_me uuid := auth.current_user_id();
    t    aed.device_transfer;
BEGIN
    SELECT * INTO t FROM aed.device_transfer WHERE id = p_transfer FOR UPDATE;
    IF NOT FOUND OR t.status <> 'pending' THEN
        RAISE EXCEPTION 'Przekazanie nie istnieje lub zostało rozpatrzone' USING ERRCODE = '22023';
    END IF;
    IF t.expires_at <= now() THEN
        UPDATE aed.device_transfer SET status = 'expired' WHERE id = p_transfer;
        RETURN;
    END IF;
    IF t.basis = 'agreement' AND NOT org.is_current_org_admin(t.to_organization_id) THEN
        RAISE EXCEPTION 'Decyzję podejmuje org_admin podmiotu przyjmującego' USING ERRCODE = '42501';
    END IF;
    IF t.basis = 'succession' AND (NOT auth.has_mc_role('mc_operator') OR v_me = t.initiated_by) THEN
        RAISE EXCEPTION 'Sukcesję zatwierdza inny mc_operator niż wnioskujący' USING ERRCODE = '42501';
    END IF;

    UPDATE aed.device_transfer
       SET status = CASE WHEN p_accept THEN 'accepted' ELSE 'rejected' END::aed.transfer_status,
           decided_by = v_me, decided_at = now()
     WHERE id = p_transfer;

    IF p_accept THEN
        -- odpowiedzialność przechodzi z chwilą akceptacji; lokalizacja poprzedniego właściciela jest zerowana
        UPDATE aed.device
           SET owner_organization_id = t.to_organization_id, site_id = NULL
         WHERE id = t.device_id AND owner_organization_id = t.from_organization_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Właściciel AED zmienił się w międzyczasie' USING ERRCODE = '40001';
        END IF;
        -- external_id to identyfikator w systemie poprzedniego właściciela (DEDUPLIKACJA.md §2.1)
        UPDATE aed.device_key
           SET owner_organization_id = t.to_organization_id, external_id = NULL, updated_at = now()
         WHERE device_id = t.device_id;
    END IF;
END
$$;

-- Interwencje MC (ROLES.md §14)
CREATE FUNCTION aed.intervention_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_me    uuid := auth.current_user_id();
    v_owner uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT auth.has_mc_role('mc_operator') OR NEW.created_by IS DISTINCT FROM v_me THEN
            RAISE EXCEPTION 'Interwencję tworzy mc_operator jako bieżący użytkownik' USING ERRCODE = '42501';
        END IF;
        IF NEW.approved_by IS NOT NULL OR NEW.responded_by IS NOT NULL OR NEW.resolved_by IS NOT NULL THEN
            RAISE EXCEPTION 'Nowa interwencja nie może być zatwierdzona ani rozwiązana' USING ERRCODE = '22023';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.device_id, NEW.type, NEW.reason, NEW.created_by, NEW.created_at)
       IS DISTINCT FROM (OLD.device_id, OLD.type, OLD.reason, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'Treści interwencji nie można zmieniać' USING ERRCODE = '42501';
    END IF;

    -- zatwierdzenie ukrycia przez drugiego mc_operator
    IF NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
        IF OLD.approved_by IS NOT NULL OR NEW.type <> 'hide' OR NEW.approved_by IS DISTINCT FROM v_me
           OR NOT auth.has_mc_role('mc_operator') THEN
            RAISE EXCEPTION 'Niedozwolone zatwierdzenie interwencji' USING ERRCODE = '42501';
        END IF;
    END IF;

    -- odpowiedź podmiotu-właściciela
    IF (NEW.organization_response, NEW.responded_by) IS DISTINCT FROM (OLD.organization_response, OLD.responded_by) THEN
        SELECT owner_organization_id INTO v_owner FROM aed.device WHERE id = NEW.device_id;
        IF NEW.responded_by IS DISTINCT FROM v_me OR NOT org.in_current_org(v_owner) THEN
            RAISE EXCEPTION 'Odpowiada członek podmiotu-właściciela jako bieżący użytkownik' USING ERRCODE = '42501';
        END IF;
    END IF;

    -- rozwiązanie przez mc_operator
    IF (NEW.resolved_by, NEW.resolution) IS DISTINCT FROM (OLD.resolved_by, OLD.resolution) THEN
        IF OLD.resolved_by IS NOT NULL OR NEW.resolved_by IS DISTINCT FROM v_me
           OR NOT auth.has_mc_role('mc_operator') THEN
            RAISE EXCEPTION 'Niedozwolone rozwiązanie interwencji' USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER intervention_guard BEFORE INSERT OR UPDATE ON aed.mc_intervention
    FOR EACH ROW EXECUTE FUNCTION aed.intervention_guard();

-- Skutek interwencji dla widoczności wpisu (zmiana wyłącznie przez ten trigger)
CREATE FUNCTION aed.intervention_apply() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.type = 'flag' THEN
        UPDATE aed.device SET visibility = 'flagged' WHERE id = NEW.device_id AND visibility = 'published';
    ELSIF TG_OP = 'INSERT' AND NEW.type = 'unhide' THEN
        UPDATE aed.device SET visibility = 'published' WHERE id = NEW.device_id;
    ELSIF TG_OP = 'UPDATE' AND NEW.type = 'hide' AND OLD.approved_by IS NULL AND NEW.approved_by IS NOT NULL THEN
        UPDATE aed.device SET visibility = 'hidden' WHERE id = NEW.device_id;
    ELSIF TG_OP = 'UPDATE' AND NEW.type = 'flag' AND OLD.resolved_by IS NULL AND NEW.resolved_by IS NOT NULL THEN
        UPDATE aed.device SET visibility = 'published' WHERE id = NEW.device_id AND visibility = 'flagged';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER intervention_apply AFTER INSERT OR UPDATE ON aed.mc_intervention
    FOR EACH ROW EXECUTE FUNCTION aed.intervention_apply();
CREATE TRIGGER intervention_audit AFTER INSERT OR UPDATE ON aed.mc_intervention
    FOR EACH ROW EXECUTE FUNCTION audit.capture();

-- =============================================================================
--  12. Row-Level Security (ROLES.md §8)
--  Polityki dotyczą roli aed_api; aed_auth ma osobne, wąskie polityki odczytu.
--  Właściciel tabel (migracje) i funkcje SECURITY DEFINER omijają RLS.
-- =============================================================================


-- aed_auth: odczyt ról i członkostw do budowy tokenów (JWT.md §4)


-- org.organization


-- org.site


-- org.membership


-- org.membership_site


-- org.invitation (przyjęcie wyłącznie funkcją org.accept_invitation)


-- org.registration_request (zmiany wyłącznie funkcjami org.*_registration)


-- org.document


-- org.statement_acceptance


-- org.access_review


-- aed.import_batch


-- aed.device: publicznie wszystko poza ukrytymi; ukryte widzi właściciel i MC (nadzór/audyt)


-- aed.device_key: klucze niepubliczne – tylko właściciel i MC (DEDUPLIKACJA.md §2.1)


-- aed.device_version: historia widoczna dla właściciela, autora i MC (nie publicznie)


-- aed.device_transfer


-- aed.mc_intervention


-- audit.event: MC – całość; podmiot – zdarzenia dotyczące siebie (ROLES.md §10)


-- =============================================================================
--  13. Uprawnienia ról bazodanowych
-- =============================================================================


-- Serwis uwierzytelniania: odczyt członkostw i podmiotów do budowy tokenów (JWT.md §4).
-- Uprawnienia do tabel auth.* nadaje sql/auth.sql.
   -- bez token_hash
     -- zapis tylko przez wersje
             -- zapis tylko przez wersje / migracje


-- Funkcje: domyślnie brak EXECUTE dla PUBLIC


-- =============================================================================
--  14. Widok publiczny w formacie SCHEMA.md (GeoJSON Feature)
--  Widok działa z uprawnieniami właściciela (omija RLS), dlatego sam filtruje
--  wpisy ukryte przez MC. Pola null i puste tablice są pomijane.
-- =============================================================================

CREATE VIEW aed.device_feature AS
SELECT
    d.id,
    d.status,
    d.lon,
    d.lat,
    jsonb_build_object(
        'type', 'Feature',
        'id', d.id,
        'geometry', jsonb_build_object('type', 'Point', 'coordinates', jsonb_build_array(d.lon, d.lat)),
        'properties', jsonb_strip_nulls(jsonb_build_object(
            'id', d.id,
            'osm_id', d.osm_id,
            'osm_type', d.osm_type,
            'osm_version', d.osm_version,
            'status', d.status,
            'visibility', CASE WHEN d.visibility = 'flagged' THEN 'flagged' END,
            'last_confirmed_at', to_char(d.last_confirmed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'),
            'access', d.access,
            'opening_hours', d.opening_hours,
            'is_24_7', d.is_24_7,
            'seasonal', d.seasonal,
            'access_note', d.access_note,
            'indoor', d.indoor,
            'level', d.level,
            'location_pl', d.location_pl,
            'location_en', d.location_en,
            'description', d.description,
            'description_en', d.description_en,
            'vehicle_mounted', d.vehicle_mounted,
            'portable', d.portable,
            'locked', d.locked,
            'count', d.device_count,
            'address', d.address,
            'addr_street_type', d.addr_street_type,
            'addr_street', d.addr_street,
            'addr_housenumber', d.addr_housenumber,
            'addr_unit', d.addr_unit,
            'addr_postcode', d.addr_postcode,
            'addr_city', d.addr_city,
            'teryt_terc', d.teryt_terc,
            'teryt_simc', d.teryt_simc,
            'teryt_ulic', d.teryt_ulic,
            'name', d.name,
            'operator', d.operator,
            'operator_short', d.operator_short,
            'phones', (SELECT jsonb_agg(p.phone ORDER BY p.position)
                         FROM aed.device_phone p WHERE p.device_id = d.id),
            'email', d.email,
            'website', d.website,
            'manufacturer', d.manufacturer,
            'model', d.model,
            'condition', d.condition,
            'condition_checked_at', to_char(d.condition_checked_at, 'YYYY-MM-DD'),
            'images', (SELECT jsonb_agg(i.url ORDER BY i.position)
                         FROM aed.device_image i WHERE i.device_id = d.id),
            'check_date', d.check_date,
            'needs_verification', d.needs_verification,
            'fixme', d.fixme,
            'source', d.source
        ))
    ) AS feature
FROM aed.device d
WHERE d.visibility <> 'hidden';

COMMENT ON VIEW aed.device_feature IS
    'AED jako GeoJSON Feature zgodny z SCHEMA.md (bez wpisów ukrytych przez MC). Zawiera też pola '
    'niepubliczne (telefony, e-mail, fixme) – do panelu podmiotu i MC. Publiczne API i Elasticsearch '
    'korzystają z aed.search_document (sekcja 15).';

-- =============================================================================
--  15. Indeksowanie w Elasticsearch (indeks „aed”, ES 6.8 portalu dane.gov.pl)
--
--  Przepływ (transakcyjna kolejka zmian, „outbox”):
--    1. każda zmiana aed.device (nowa wersja, potwierdzenie, interwencja MC, zmiana statusu) dopisuje
--       w TEJ SAMEJ transakcji wiersz do aed.search_outbox i wysyła pg_notify('aed_search_outbox', id);
--    2. zadanie Celery (kolejka „aed”, co kilka sekund z Celery Beat lub po NOTIFY) wywołuje
--       aed.search_outbox_claim(), dostaje bieżący dokument albo polecenie usunięcia i wysyła je do ES
--       zapytaniem _bulk z wersjonowaniem zewnętrznym: version = outbox_id, version_type = external_gte
--       (starsze zmiany nie nadpiszą nowszych, także przy równoległych workerach i ponowieniach);
--    3. po odpowiedzi ES zadanie wywołuje aed.search_outbox_ack() albo aed.search_outbox_fail();
--    4. raz na dobę zadanie zgodności (jak compare_postgres_and_elasticsearch_consistency_task portalu)
--       porównuje doc_hash z aed.search_document z polem doc_hash w ES.
--  Dlaczego outbox, a nie sygnały Django (django-elasticsearch-dsl): dane AED zmieniają triggery bazy
--  (aed.apply_version, aed.intervention_apply), których sygnały ORM nie widzą; outbox gwarantuje, że
--  zmiana zatwierdzona w bazie trafi do indeksu, a wycofana – nie.
--  Indeks zawiera WYŁĄCZNIE dane publiczne (API.md §8, TRANSFER_DANEGOVPL.md §3): aktywne, nieukryte AED,
--  bez telefonów, e-maili, fixme, source, osm_*, needs_verification i danych podmiotu.
--  Mapowanie indeksu i konfiguracja: komentarz na końcu pliku.
-- =============================================================================

CREATE TABLE aed.search_outbox (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,   -- = wersja dokumentu w ES
    doc_id       text        NOT NULL REFERENCES aed.device (id),
    enqueued_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    claimed_at   timestamptz,
    attempts     smallint    NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    processed_at timestamptz,
    last_error   text,

    CONSTRAINT outbox_processed_ck CHECK (processed_at IS NULL OR claimed_at IS NOT NULL)
);

-- co najwyżej jeden oczekujący (jeszcze nie pobrany) wpis na dokument – kolejne zmiany go odświeżają
CREATE UNIQUE INDEX search_outbox_pending_uk ON aed.search_outbox (doc_id)
    WHERE claimed_at IS NULL AND processed_at IS NULL;
CREATE INDEX search_outbox_open_ix ON aed.search_outbox (id) WHERE processed_at IS NULL;

COMMENT ON TABLE aed.search_outbox IS
    'Transakcyjna kolejka zmian do indeksu Elasticsearch „aed”. id służy jako zewnętrzna wersja dokumentu w ES. '
    'Wiersze przetworzone usuwa aed.search_outbox_purge().';   -- brak polityk: dostęp tylko przez funkcje

-- Dokument indeksu „aed” (tylko AED widoczne publicznie). Nazwy pól jak w SCHEMA.md,
-- położenie jako geo_point {lat, lon}. doc_hash = MD5 treści dokumentu (do kontroli zgodności z ES).
CREATE VIEW aed.search_document AS
SELECT s.id, s.version_no, s.doc || jsonb_build_object('doc_hash', md5(s.doc::text)) AS document
FROM (
    SELECT
        d.id,
        v.version_no,
        jsonb_strip_nulls(jsonb_build_object(
            'id', d.id,
            'location', jsonb_build_object('lat', d.lat, 'lon', d.lon),
            'status', d.status,
            'flagged', d.visibility = 'flagged',
            'last_confirmed_at', to_char(d.last_confirmed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'),
            'access', d.access,
            'opening_hours', d.opening_hours,
            'is_24_7', d.is_24_7,
            'seasonal', d.seasonal,
            'access_note', d.access_note,
            'locked', d.locked,
            'indoor', d.indoor,
            'level', d.level,
            'location_pl', d.location_pl,
            'location_en', d.location_en,
            'description', d.description,
            'description_en', d.description_en,
            'vehicle_mounted', d.vehicle_mounted,
            'portable', d.portable,
            'count', d.device_count,
            'address', d.address,
            'addr_street_type', d.addr_street_type,
            'addr_street', d.addr_street,
            'addr_housenumber', d.addr_housenumber,
            'addr_unit', d.addr_unit,
            'addr_postcode', d.addr_postcode,
            'addr_city', d.addr_city,
            'teryt_terc', d.teryt_terc,
            'teryt_simc', d.teryt_simc,
            'teryt_ulic', d.teryt_ulic,
            'name', d.name,
            'operator', d.operator,
            'operator_short', d.operator_short,
            'website', d.website,
            'manufacturer', d.manufacturer,
            'model', d.model,
            'condition', d.condition,
            'condition_checked_at', to_char(d.condition_checked_at, 'YYYY-MM-DD'),
            'images', (SELECT jsonb_agg(i.url ORDER BY i.position)
                         FROM aed.device_image i WHERE i.device_id = d.id),
            'check_date', d.check_date,
            'version_no', v.version_no,
            'updated_at', to_char(d.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')  -- ES 6.8: ms
        )) AS doc
    FROM aed.device d
    JOIN aed.device_version v ON v.id = d.current_version_id
    WHERE d.status = 'active' AND d.visibility <> 'hidden'
) s;

COMMENT ON VIEW aed.search_document IS
    'Dokumenty indeksu Elasticsearch „aed” – wyłącznie dane publiczne (API.md §8). Brak wiersza = dokument '
    'do usunięcia z indeksu.';

-- Trigger: każda zmiana urządzenia trafia do kolejki w tej samej transakcji
CREATE FUNCTION aed.search_enqueue() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id bigint;
BEGIN
    INSERT INTO aed.search_outbox AS o (doc_id) VALUES (NEW.id)
    ON CONFLICT (doc_id) WHERE claimed_at IS NULL AND processed_at IS NULL
    DO UPDATE SET enqueued_at = clock_timestamp()
    RETURNING o.id INTO v_id;
    PERFORM pg_notify('aed_search_outbox', v_id::text);   -- wysyłane dopiero po COMMIT
    RETURN NULL;
END
$$;

CREATE TRIGGER device_search_enqueue AFTER INSERT OR UPDATE ON aed.device
    FOR EACH ROW EXECUTE FUNCTION aed.search_enqueue();

-- Pobranie paczki do indeksowania (FOR UPDATE SKIP LOCKED – bezpieczne dla wielu workerów).
-- Wpis pobrany, ale niepotwierdzony w czasie p_lease, wraca do kolejki. Po 10 próbach wpis zostaje
-- w kolejce jako „martwy” (widok aed.search_outbox_dead) i wymaga interwencji.
-- Dokument jest czytany w chwili pobrania (stan bieżący), a nie w chwili zmiany.
CREATE FUNCTION aed.search_outbox_claim(p_limit integer DEFAULT 500, p_lease interval DEFAULT '5 minutes')
RETURNS TABLE (outbox_id bigint, doc_id text, op text, document jsonb)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH picked AS (
        SELECT o.id
        FROM aed.search_outbox o
        WHERE o.processed_at IS NULL
          AND o.attempts < 10
          AND (o.claimed_at IS NULL OR o.claimed_at < clock_timestamp() - p_lease)
        ORDER BY o.id
        LIMIT LEAST(GREATEST(p_limit, 1), 5000)
        FOR UPDATE SKIP LOCKED
    ), claimed AS (
        UPDATE aed.search_outbox o
        SET claimed_at = clock_timestamp(), attempts = o.attempts + 1
        FROM picked
        WHERE o.id = picked.id
        RETURNING o.id, o.doc_id
    )
    SELECT c.id, c.doc_id,
           CASE WHEN s.id IS NULL THEN 'delete' ELSE 'index' END,
           s.document
    FROM claimed c
    LEFT JOIN aed.search_document s ON s.id = c.doc_id
    ORDER BY c.id
$$;

CREATE FUNCTION aed.search_outbox_ack(p_ids bigint[]) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH done AS (
        UPDATE aed.search_outbox
        SET processed_at = clock_timestamp(), last_error = NULL
        WHERE id = ANY (p_ids) AND claimed_at IS NOT NULL AND processed_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::integer FROM done
$$;

-- Błąd indeksowania: wpis zostaje pobrany do czasu wygaśnięcia dzierżawy (ponowienie z opóźnieniem).
-- Konflikt wersji w ES (409) NIE jest błędem – oznacza, że indeks ma już nowszą wersję; wtedy ack.
CREATE FUNCTION aed.search_outbox_fail(p_id bigint, p_error text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE aed.search_outbox
    SET last_error = left(p_error, 2000)
    WHERE id = p_id AND processed_at IS NULL
$$;

-- Pełne przeindeksowanie (np. nowe mapowanie: indeks aed-v2, potem przełączenie aliasu „aed”)
CREATE FUNCTION aed.search_reindex_all() RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH ins AS (
        INSERT INTO aed.search_outbox (doc_id)
        SELECT d.id FROM aed.device d
        ON CONFLICT (doc_id) WHERE claimed_at IS NULL AND processed_at IS NULL DO NOTHING
        RETURNING 1
    )
    SELECT count(*)::integer FROM ins
$$;

-- Sprzątanie przetworzonych wpisów (zadanie okresowe)
CREATE FUNCTION aed.search_outbox_purge(p_older_than interval DEFAULT '7 days') RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH del AS (
        DELETE FROM aed.search_outbox
        WHERE processed_at < clock_timestamp() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM del
$$;

-- Monitoring (np. metryka Prometheus / alert): zaległości i martwe wpisy
CREATE VIEW aed.search_outbox_status AS
SELECT count(*) FILTER (WHERE processed_at IS NULL)                         AS pending,
       count(*) FILTER (WHERE processed_at IS NULL AND attempts >= 10)       AS dead,
       min(enqueued_at) FILTER (WHERE processed_at IS NULL)                  AS oldest_pending_at,
       max(processed_at)                                                     AS last_processed_at
FROM aed.search_outbox;

CREATE VIEW aed.search_outbox_dead AS
SELECT id, doc_id, enqueued_at, claimed_at, attempts, last_error
FROM aed.search_outbox
WHERE processed_at IS NULL AND attempts >= 10;
-- aed.search_reindex_all() – tylko właściciel bazy (operacja administracyjna)

-- Publiczne API może czytać dokumenty bezpośrednio z bazy jako rezerwę, gdy ES jest niedostępny


-- =============================================================================
--  16. Eksport dziennika audytu do ELK (Logstash → Elasticsearch → Kibana)
--
--  Logstash (wejście JDBC) co minutę czyta nowe zdarzenia przyrostowo po chain_seq i zapisuje je
--  w indeksach aed-audit-RRRR.MM z document_id = chain_seq i action = create (zapis idempotentny,
--  bez nadpisywania). Kopia w ELK służy do przeszukiwania, alertów (ROLES.md §10) i niezależnej
--  weryfikacji łańcucha skrótów. Elasticsearch NIE jest magazynem WORM – wymaganie kopii niezmienialnej
--  spełniają migawki indeksów do repozytorium z blokadą zapisu (np. S3 Object Lock). Konfiguracja Logstash
--  i szablon indeksu: komentarz na końcu pliku.
-- =============================================================================

CREATE VIEW audit.event_export AS
SELECT
    e.chain_seq,
    audit.canonical_ts(e.occurred_at)   AS occurred_at_utc,
    e.actor_user_id,
    e.actor_role,
    e.organization_context_id,
    e.action,
    e.object_type,
    e.object_id,
    e.result,
    e.reason,
    host(e.ip)                          AS ip,
    e.session_id,
    e.details::text                     AS details_json,
    encode(e.prev_sha256, 'hex')        AS prev_sha256_hex,
    encode(e.sha256, 'hex')             AS sha256_hex,
    audit.event_hash_input(e)           AS hash_input
FROM audit.event e;

COMMENT ON VIEW audit.event_export IS
    'Zdarzenia audytu do Logstash (JDBC, przyrostowo po chain_seq). Weryfikacja poza bazą: '
    'sha256_hex = SHA-256(bajty(prev_sha256_hex) || UTF-8(hash_input)), a prev_sha256_hex = sha256_hex '
    'zdarzenia chain_seq - 1. Widok działa z uprawnieniami właściciela (omija RLS) – tylko dla aed_log_shipper.';

-- Weryfikacja łańcucha w bazie (np. codzienne zadanie i porównanie z kopią w ELK).
-- Zwraca liczbę sprawdzonych zdarzeń i pierwsze uszkodzone ogniwo (NULL = łańcuch poprawny).
CREATE FUNCTION audit.verify_chain(p_from bigint DEFAULT 1, p_to bigint DEFAULT NULL)
RETURNS TABLE (checked bigint, first_broken_seq bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$  -- public: digest() z pgcrypto
DECLARE
    e         audit.event;
    v_prev    bytea;
    v_seq     bigint;
    v_checked bigint := 0;
BEGIN
    IF p_from > 1 THEN
        SELECT x.sha256 INTO v_prev FROM audit.event x WHERE x.chain_seq = p_from - 1;
    END IF;
    v_seq := p_from - 1;
    FOR e IN
        SELECT * FROM audit.event x
        WHERE x.chain_seq >= p_from AND (p_to IS NULL OR x.chain_seq <= p_to)
        ORDER BY x.chain_seq
    LOOP
        IF e.chain_seq <> v_seq + 1
           OR e.prev_sha256 IS DISTINCT FROM v_prev
           OR e.sha256 <> digest(COALESCE(v_prev, ''::bytea) || convert_to(audit.event_hash_input(e), 'UTF8'), 'sha256') THEN
            checked := v_checked;
            first_broken_seq := e.chain_seq;
            RETURN NEXT;
            RETURN;
        END IF;
        v_prev := e.sha256;
        v_seq := e.chain_seq;
        v_checked := v_checked + 1;
    END LOOP;
    checked := v_checked;
    first_broken_seq := NULL;
    RETURN NEXT;
END
$$;

-- -----------------------------------------------------------------------------
--  Przykładowe zapytania (API, rola aed_api)
-- -----------------------------------------------------------------------------
--
--  Kontekst transakcji ustawiany ze zweryfikowanego tokenu (JWT.md §7):
--
--    BEGIN;
--    SELECT set_config('app.user_id', $1, true), set_config('app.org_id', $2, true),
--           set_config('app.session_id', $3, true), set_config('app.actor_role', $4, true),
--           set_config('app.client_ip', $5, true);
--    ...
--    COMMIT;
--
--  Nowe AED albo zmiana danych (jedyna droga zapisu; device_id NULL = nowe urządzenie):
--
--    INSERT INTO aed.device_version (device_id, site_id, data, author_user_id, author_organization_id,
--                                    confirmation_statement_id, confirmed_at)
--    VALUES (NULL, NULL, $feature_jsonb, $user_id, $org_id, $statement_id, now())
--    RETURNING device_id, version_no;
--
--  Mapa i „najbliższe AED” obsługuje Elasticsearch (zapytania niżej). Zapytania SQL poniżej to
--  REZERWA na wypadek niedostępności ES (np. publiczne API w trybie awaryjnym).
--
--  Rezerwa: 10 najbliższych AED od punktu (lat 52.2297, lon 21.0122) w promieniu 5 km (earthdistance):
--
--    SELECT s.id, s.document,
--           round(earth_distance(ll_to_earth(52.2297, 21.0122),
--                                ll_to_earth((s.document #>> '{location,lat}')::float8,
--                                            (s.document #>> '{location,lon}')::float8))) AS distance_m
--    FROM aed.search_document s
--    WHERE s.document ->> 'access' IN ('public', 'customers', 'on_request')
--      AND earth_box(ll_to_earth(52.2297, 21.0122), 5000)
--          @> ll_to_earth((s.document #>> '{location,lat}')::float8, (s.document #>> '{location,lon}')::float8)
--    ORDER BY distance_m
--    LIMIT 10;
--
--  Rezerwa: FeatureCollection dla prostokąta mapy (bbox: minLon, minLat, maxLon, maxLat) w panelu MC:
--
--    SELECT jsonb_build_object('type', 'FeatureCollection',
--                              'features', COALESCE(jsonb_agg(feature), '[]'::jsonb))
--    FROM aed.device_feature
--    WHERE status = 'active'
--      AND lon BETWEEN 20.85 AND 21.27 AND lat BETWEEN 52.10 AND 52.37;
--
--  Zadanie indeksujące (rola aed_indexer), jedna iteracja:
--
--    SELECT * FROM aed.search_outbox_claim(500);          -- → _bulk do ES (wersja = outbox_id)
--    SELECT aed.search_outbox_ack(ARRAY[101, 102, 103]);  -- sukces lub 409 (nowsza wersja już w ES)
--    SELECT aed.search_outbox_fail(104, 'es_rejected_execution_exception');
--
-- -----------------------------------------------------------------------------
--  Elasticsearch 6.8: indeks „aed” (alias) → indeks fizyczny „aed-v1”
--  Wymaga wtyczek obecnych w obrazie ES portalu: analysis-stempel (polish_stem), analysis-icu (icu_folding).
-- -----------------------------------------------------------------------------
--
--    PUT /aed-v1
--    {
--      "settings": {
--        "number_of_shards": 1,
--        "number_of_replicas": 1,
--        "analysis": {
--          "analyzer": {
--            "pl_text": { "type": "custom", "tokenizer": "standard",
--                         "filter": ["lowercase", "polish_stem", "icu_folding"] },
--            "folded":  { "type": "custom", "tokenizer": "standard",
--                         "filter": ["lowercase", "icu_folding"] }
--          }
--        }
--      },
--      "mappings": {
--        "doc": {
--          "dynamic": "strict",
--          "properties": {
--            "id":                { "type": "keyword" },
--            "location":          { "type": "geo_point" },
--            "status":            { "type": "keyword" },
--            "flagged":           { "type": "boolean" },
--            "last_confirmed_at": { "type": "date", "format": "yyyy-MM-dd" },
--            "access":            { "type": "keyword" },
--            "opening_hours":     { "type": "keyword", "index": false },
--            "is_24_7":           { "type": "boolean" },
--            "seasonal":          { "type": "boolean" },
--            "access_note":       { "type": "text", "analyzer": "pl_text" },
--            "locked":            { "type": "boolean" },
--            "indoor":            { "type": "boolean" },
--            "level":             { "type": "scaled_float", "scaling_factor": 100 },
--            "location_pl":       { "type": "text", "analyzer": "pl_text" },
--            "location_en":       { "type": "text", "analyzer": "english" },
--            "description":       { "type": "text", "analyzer": "pl_text" },
--            "description_en":    { "type": "text", "analyzer": "english" },
--            "vehicle_mounted":   { "type": "boolean" },
--            "portable":          { "type": "boolean" },
--            "count":             { "type": "short" },
--            "address":           { "type": "text", "analyzer": "folded",
--                                   "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
--            "addr_street_type":  { "type": "keyword" },
--            "addr_street":       { "type": "text", "analyzer": "folded",
--                                   "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
--            "addr_housenumber":  { "type": "keyword" },
--            "addr_unit":         { "type": "keyword" },
--            "addr_postcode":     { "type": "keyword" },
--            "addr_city":         { "type": "text", "analyzer": "folded",
--                                   "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
--            "teryt_terc":        { "type": "keyword" },
--            "teryt_simc":        { "type": "keyword" },
--            "teryt_ulic":        { "type": "keyword" },
--            "name":              { "type": "text", "analyzer": "pl_text",
--                                   "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
--            "operator":          { "type": "text", "analyzer": "pl_text",
--                                   "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
--            "operator_short":    { "type": "keyword" },
--            "website":           { "type": "keyword", "index": false },
--            "manufacturer":      { "type": "keyword" },
--            "model":             { "type": "keyword" },
--            "condition":         { "type": "keyword" },
--            "condition_checked_at": { "type": "date", "format": "yyyy-MM-dd" },
--            "images":            { "type": "keyword", "index": false },
--            "check_date":        { "type": "date", "format": "yyyy-MM-dd||yyyy-MM||yyyy" },
--            "version_no":        { "type": "integer" },
--            "updated_at":        { "type": "date", "format": "strict_date_optional_time" },
--            "doc_hash":          { "type": "keyword" }
--          }
--        }
--      }
--    }
--    POST /_aliases { "actions": [ { "add": { "index": "aed-v1", "alias": "aed" } } ] }
--
--  Zapis z kolejki (_bulk), wersja zewnętrzna = outbox_id:
--    { "index":  { "_index": "aed", "_type": "doc", "_id": "<doc_id>", "version": <outbox_id>, "version_type": "external_gte" } }
--    { ...document... }
--    { "delete": { "_index": "aed", "_type": "doc", "_id": "<doc_id>", "version": <outbox_id>, "version_type": "external_gte" } }
--
--  Najbliższe AED (odpowiednik GET /aed/nearest, API.md §8):
--    GET /aed/_search
--    { "size": 5,
--      "query": { "bool": { "filter": [
--          { "terms": { "access": ["public", "customers", "on_request"] } },
--          { "terms": { "condition": ["working", "unknown"] } },
--          { "geo_distance": { "distance": "5km", "location": { "lat": 52.2297, "lon": 21.0122 } } } ] } },
--      "sort": [ { "_geo_distance": { "location": { "lat": 52.2297, "lon": 21.0122 },
--                                     "order": "asc", "unit": "m" } } ] }
--
--  Prostokąt mapy (GET /aed?bbox=…) i skupiska punktów przy małym przybliżeniu:
--    GET /aed/_search
--    { "size": 2000,
--      "query": { "bool": { "filter": { "geo_bounding_box": { "location": {
--          "top_left": { "lat": 52.37, "lon": 20.85 }, "bottom_right": { "lat": 52.10, "lon": 21.27 } } } } } },
--      "aggs": { "tiles": { "geohash_grid": { "field": "location", "precision": 5 } } } }
--
--  Przeindeksowanie po zmianie mapowania: utworzyć aed-v2, w bazie SELECT aed.search_reindex_all();
--  (zadanie pisze do indeksu wskazanego w konfiguracji), po opróżnieniu kolejki przełączyć alias „aed”.
--
-- -----------------------------------------------------------------------------
--  ELK: Logstash (wejście JDBC) → Elasticsearch (indeksy aed-audit-RRRR.MM) → Kibana
--  Konto bazy dla Logstash: osobny login z rolą aed_log_shipper (tylko audit.event_export).
-- -----------------------------------------------------------------------------
--
--    input {
--      jdbc {
--        jdbc_driver_library    => "/usr/share/logstash/drivers/postgresql.jar"
--        jdbc_driver_class      => "org.postgresql.Driver"
--        jdbc_connection_string => "jdbc:postgresql://<host>:5432/<baza>?sslmode=verify-full"
--        jdbc_user              => "<login z rolą aed_log_shipper>"
--        jdbc_password_filepath => "/run/secrets/aed_log_shipper_password"
--        schedule               => "* * * * *"
--        statement              => "SELECT * FROM audit.event_export WHERE chain_seq > :sql_last_value ORDER BY chain_seq LIMIT 5000"
--        use_column_value       => true
--        tracking_column        => "chain_seq"
--        tracking_column_type   => "numeric"
--        last_run_metadata_path => "/usr/share/logstash/data/aed_audit_last_run"
--      }
--    }
--    filter {
--      json { source => "details_json" target => "details" remove_field => ["details_json"] }
--      date { match => ["occurred_at_utc", "ISO8601"] }
--    }
--    output {
--      elasticsearch {
--        hosts       => ["<es-logi>:9200"]
--        index       => "aed-audit-%{+YYYY.MM}"
--        document_id => "%{chain_seq}"
--        action      => "create"        # nigdy nie nadpisuj istniejącego zdarzenia
--      }
--    }
--
--  Szablon indeksów audytu (ES 6.8):
--    PUT /_template/aed-audit
--    { "index_patterns": ["aed-audit-*"],
--      "settings": { "number_of_shards": 1, "number_of_replicas": 1 },
--      "mappings": { "doc": { "dynamic": "strict", "properties": {
--          "@timestamp": { "type": "date" }, "@version": { "type": "keyword" },
--          "tags": { "type": "keyword" },   -- Logstash dodaje np. _jsonparsefailure; bez tego „strict” odrzuci zdarzenie
--          "chain_seq": { "type": "long" }, "occurred_at_utc": { "type": "keyword" },
--          "actor_user_id": { "type": "keyword" }, "actor_role": { "type": "keyword" },
--          "organization_context_id": { "type": "keyword" }, "action": { "type": "keyword" },
--          "object_type": { "type": "keyword" }, "object_id": { "type": "keyword" },
--          "result": { "type": "keyword" }, "reason": { "type": "text" }, "ip": { "type": "ip" },
--          "session_id": { "type": "keyword" },
--          "details": { "type": "object", "enabled": false },
--          "prev_sha256_hex": { "type": "keyword" }, "sha256_hex": { "type": "keyword" },
--          "hash_input": { "type": "keyword", "index": false, "doc_values": false } } } } }
--
--  Uwagi:
--    * occurred_at_utc jako keyword (nie date) – zachowuje mikrosekundy potrzebne do weryfikacji skrótu;
--      do wyszukiwania po czasie służy @timestamp (filtr date);
--    * dostęp do indeksów aed-audit-* tylko dla ról MC (mc_auditor, mc_operator, mc_admin) –
--      uprawnienia w Kibanie / X-Pack Security lub osobny klaster ELK;
--    * bez fazy usuwania w zasadach przechowywania do czasu decyzji o okresie przechowywania (ROLES.md §16);
--    * kopia niezmienialna: regularne migawki (_snapshot) do repozytorium z blokadą zapisu (WORM);
--    * logi aplikacyjne modułu (Python) idą do Logstash istniejącym w portalu handlerem python-logstash
--      (LOGSTASH_HOST) – bez tokenów, ciasteczek i dokładnej lokalizacji użytkownika (API.md §9.8).
