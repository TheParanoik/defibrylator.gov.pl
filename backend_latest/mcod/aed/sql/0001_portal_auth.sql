-- =============================================================================
--  Misja AED – warstwa zgodności ze schematem auth (konta portalu dane.gov.pl)
--
--  Specyfikacja modułu (sql/auth.sql) zakładała własny serwis kont. W portalu konta, hasła, sesje i 2FA
--  należą do aplikacji users (tabela public."user", mcod.users.mfa). Ten plik tworzy tylko to, czego
--  wymaga sql/aed.sql, z tymi samymi nazwami, żeby specyfikacja przeszła bez przepisywania:
--
--    auth.user_link      – UUID użytkownika modułu ↔ konto portalu ("user".id); cel kluczy obcych
--    auth.user_account   – widok: id, email, is_active, email_verified_at z konta portalu
--    auth.mc_role        – role MC (ROLES.md §3.1) z zasadą czterech oczu i min. dwoma mc_admin
--    auth.session        – minimalny rejestr kontekstu podmiotu (sesje portalu są w Redis)
--    auth.current_user_id() / current_org_id() – kontekst transakcji (SET LOCAL app.user_id / app.org_id)
--    auth.has_mfa()      – aplikacja uwierzytelniająca z mcod.users.mfa (tabela user_totp)
--    auth.has_verified_identity() – konto powiązane z login.gov.pl ("user".is_gov_auth)
--    auth.has_mc_role()  – rola MC aktywna; PRZEJŚCIOWO wystarcza TOTP (portal nie ma WebAuthn)
--    auth.revoke_user_sessions() – znacznik w auth.session + NOTIFY aed_session_revoke (dla Django)
--
--  Pominięte względem sql/auth.sql: hasła, TOTP/WebAuthn/kody zapasowe, tokeny, próby logowania,
--  blokady, refresh tokeny, klucze podpisu – to robi portal.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TYPE auth.identity_provider AS ENUM ('login_gov_pl', 'mc_sso');
CREATE TYPE auth.mc_role_name      AS ENUM ('mc_admin', 'mc_operator', 'mc_auditor');

-- -----------------------------------------------------------------------------
--  Użytkownicy modułu = konta portalu
-- -----------------------------------------------------------------------------

CREATE TABLE auth.user_link (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_user_id  integer NOT NULL UNIQUE REFERENCES public."user" (id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE auth.user_link IS
    'Identyfikator użytkownika w module AED (uuid) dla konta portalu. Tworzony przy pierwszym działaniu w module '
    '(mcod.aed.context.aed_user_id). Historia AED wskazuje ten uuid, więc konto portalu nie może zniknąć (RESTRICT).';

CREATE VIEW auth.user_account AS
SELECT l.id,
       l.portal_user_id,
       u.email::citext AS email,
       (u.is_active AND u.state = 'active' AND NOT u.is_removed AND NOT u.is_permanently_removed) AS is_active,
       u.email_confirmed AS email_verified_at
FROM auth.user_link l
JOIN public."user" u ON u.id = l.portal_user_id;

-- -----------------------------------------------------------------------------
--  Kontekst transakcji (ustawia mcod.aed.context, zawsze SET LOCAL)
-- -----------------------------------------------------------------------------

CREATE FUNCTION auth.current_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

CREATE FUNCTION auth.current_org_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.org_id', true), '')::uuid
$$;

-- MFA z portalu: potwierdzona aplikacja uwierzytelniająca (mcod.users.mfa). Portal nie ma WebAuthn,
-- więc metoda odporna na phishing (p_phishing_resistant = true) jest zawsze niedostępna.
CREATE FUNCTION auth.has_mfa(p_user uuid, p_phishing_resistant boolean DEFAULT false) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT NOT p_phishing_resistant
       AND EXISTS (SELECT 1
                   FROM auth.user_link l
                   JOIN public.user_totp t ON t.user_id = l.portal_user_id
                   WHERE l.id = p_user AND t.confirmed_at IS NOT NULL)
$$;

-- login.gov.pl: konto portalu powiązane z Węzłem Krajowym (is_gov_auth). mc_sso – brak w portalu.
CREATE FUNCTION auth.has_verified_identity(p_user uuid, p_provider auth.identity_provider) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_provider = 'login_gov_pl'
       AND EXISTS (SELECT 1 FROM auth.user_account a
                   JOIN public."user" u ON u.id = a.portal_user_id
                   WHERE a.id = p_user AND a.is_active AND u.is_gov_auth)
$$;

-- -----------------------------------------------------------------------------
--  Role MC (sql/auth.sql §6, §9)
-- -----------------------------------------------------------------------------

CREATE TABLE auth.mc_role (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        uuid              NOT NULL REFERENCES auth.user_link (id),
    role           auth.mc_role_name NOT NULL,
    reason         text              NOT NULL CHECK (length(btrim(reason)) >= 10),
    granted_by     uuid              NOT NULL REFERENCES auth.user_link (id),
    granted_at     timestamptz       NOT NULL DEFAULT now(),
    approved_by    uuid              REFERENCES auth.user_link (id),
    approved_at    timestamptz,
    expires_at     timestamptz       NOT NULL,
    revoked_at     timestamptz,
    revoked_by     uuid              REFERENCES auth.user_link (id),
    revoke_reason  text,

    CONSTRAINT mc_role_not_self_ck   CHECK (granted_by <> user_id),
    CONSTRAINT mc_role_four_eyes_ck  CHECK (approved_by IS NULL OR (approved_by <> granted_by AND approved_by <> user_id)),
    CONSTRAINT mc_role_approval_ck   CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT mc_role_expiry_ck     CHECK (expires_at > granted_at AND expires_at <= granted_at + interval '12 months'),
    CONSTRAINT mc_role_revoke_ck     CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
                                            AND (revoked_at IS NULL OR revoke_reason IS NOT NULL))
);

CREATE UNIQUE INDEX mc_role_active_uk ON auth.mc_role (user_id, role) WHERE revoked_at IS NULL;

COMMENT ON TABLE auth.mc_role IS
    'Role MC. Aktywna = zatwierdzona, nieodwołana, niewygasła, konto aktywne i z 2FA. '
    'Docelowo wymagany WebAuthn (ROLES.md §5.2) – portal go nie ma, przejściowo TOTP.';

-- Role MC zawsze z bazy (ROLES.md §8). PRZEJŚCIOWO: has_mfa(..., false) zamiast WebAuthn.
CREATE FUNCTION auth.has_mc_role(VARIADIC p_roles text[]) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1
        FROM auth.mc_role r
        JOIN auth.user_account u ON u.id = r.user_id
        WHERE r.user_id = auth.current_user_id()
          AND r.role::text = ANY (p_roles)
          AND r.approved_at IS NOT NULL
          AND r.revoked_at IS NULL
          AND r.expires_at > now()
          AND u.is_active
          AND auth.has_mfa(r.user_id, false)
    )
$$;

-- -----------------------------------------------------------------------------
--  Rejestr kontekstu podmiotu (sesje portalu są w Redis – mcod.lib.triggers.session_store)
-- -----------------------------------------------------------------------------

CREATE TABLE auth.session (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),   -- = app.session_id
    user_id              uuid        NOT NULL REFERENCES auth.user_link (id),
    portal_session_key   text,                                         -- klucz sesji Django
    aal                  smallint    NOT NULL DEFAULT 1 CHECK (aal BETWEEN 1 AND 3),
    created_at           timestamptz NOT NULL DEFAULT now(),
    absolute_expires_at  timestamptz NOT NULL DEFAULT now() + interval '4 hours',
    revoked_at           timestamptz,
    revoke_reason        text,

    CONSTRAINT session_revoke_ck CHECK (revoked_at IS NULL OR revoke_reason IS NOT NULL)
);

CREATE INDEX session_user_active_ix ON auth.session (user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE auth.session IS
    'Kontekst podmiotu dla sesji portalu (organization_id, org_role dodaje sql/aed.sql). '
    'Odwołanie jest sygnalizowane NOTIFY aed_session_revoke – usunięcie sesji Django to zadanie aplikacji.';

CREATE FUNCTION auth.revoke_user_sessions(p_user uuid, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE auth.session
       SET revoked_at = now(), revoke_reason = p_reason
     WHERE user_id = p_user AND revoked_at IS NULL;
    PERFORM pg_notify('aed_session_revoke', json_build_object('user_id', p_user, 'reason', p_reason)::text);
END
$$;

-- Reguły ról MC (sql/auth.sql §9)
CREATE FUNCTION auth.mc_role_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_remaining int;
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;   -- wyłączność z rolą w podmiocie sprawdza trigger z sql/aed.sql
    END IF;

    IF NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
        IF OLD.approved_by IS NOT NULL OR NEW.approved_by IS DISTINCT FROM auth.current_user_id()
           OR NOT auth.has_mc_role('mc_admin') THEN
            RAISE EXCEPTION 'Niedozwolone zatwierdzenie roli MC' USING ERRCODE = '42501';
        END IF;
    END IF;

    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        IF auth.current_user_id() IS NOT NULL
           AND (NEW.revoked_by IS DISTINCT FROM auth.current_user_id() OR NOT auth.has_mc_role('mc_admin')) THEN
            RAISE EXCEPTION 'Niedozwolone odwołanie roli MC' USING ERRCODE = '42501';
        END IF;
        IF OLD.role = 'mc_admin' AND OLD.approved_at IS NOT NULL THEN
            SELECT count(*) INTO v_remaining
            FROM auth.mc_role r
            WHERE r.role = 'mc_admin' AND r.id <> OLD.id AND r.approved_at IS NOT NULL
              AND r.revoked_at IS NULL AND r.expires_at > now();
            IF v_remaining < 2 THEN
                RAISE EXCEPTION 'Musi pozostać co najmniej dwóch aktywnych mc_admin (docs/ROLES.md §6.1)'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'Odwołanej roli nie można przywrócić – nadaj ją ponownie' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER mc_role_guard BEFORE INSERT OR UPDATE ON auth.mc_role
    FOR EACH ROW EXECUTE FUNCTION auth.mc_role_guard();

CREATE FUNCTION auth.mc_role_after() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM auth.revoke_user_sessions(NEW.user_id, 'mc_role_change');
    RETURN NULL;
END
$$;

CREATE TRIGGER mc_role_revoke_sessions AFTER INSERT OR UPDATE ON auth.mc_role
    FOR EACH ROW EXECUTE FUNCTION auth.mc_role_after();
