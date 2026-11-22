"""Endpointy API modułu AED – rdzeń kontraktu API.md (wersja 2.3).

Zaimplementowane: §4.2 ``GET /auth/aed/me``, §4.3 ``POST /auth/aed/context``, §5.2 ``GET /auth/aed/org``,
§6.2–§6.5 AED podmiotu (lista, szczegóły z ETag, utworzenie [I], PUT z If-Match, potwierdzenie, wersje),
§8.1 ``GET /aed`` i ``GET /aed/{id}`` (mapa publiczna). Status pozostałych: API.md §18.

Izolacja: podmiot wyłącznie z kontekstu sesji (``mcod.aed.api.auth``); każde zapytanie o AED idzie przez
``AedRequestContext.devices()``; obiekt spoza zakresu → 404. Zapis w ``aed_context`` – baza sprawdza
uprawnienia drugi raz (triggery ``aed.apply_version``, ``aed.confirm_device``).
"""

import hashlib
import json
import re
from typing import Optional
from uuid import UUID

import falcon
from django.conf import settings
from django.db import DatabaseError, connection
from django.db.models import Q

from mcod.aed import services
from mcod.aed.api import idempotency
from mcod.aed.api.auth import (
    ROLE_LOGIN_METHOD,
    aed_context_required,
    aed_login_required,
    load_context,
    login_method,
    require_json_api,
    select_context,
)
from mcod.aed.api.errors import AedError, FieldError, not_found, sql_error_info
from mcod.aed.api.validation import normalize_feature, validate_feature
from mcod.aed.context import aed_context, aed_user_id
from mcod.aed.models import (
    AedOrganization,
    Device,
    DeviceKey,
    DeviceVersion,
    McIntervention,
    McRole,
    Membership,
    ResponsibilityStatement,
    Site,
    UserLink,
)
from mcod.lib.encoders import LazyEncoder

JSONAPI = "application/vnd.api+json"
GEOJSON = "application/geo+json"
PRIVATE_KEYS = ("serial_number", "external_id")


# ---------------------------------------------------------------------------
#  Pomocnicze
# ---------------------------------------------------------------------------


def api_url(path: str) -> str:
    return f"{settings.API_URL}/1.4{path}"


def write(resp, body, status=falcon.HTTP_200, content_type=JSONAPI):
    resp.status = status
    resp.content_type = content_type
    resp.text = json.dumps(body, cls=LazyEncoder)


def read_body(req) -> dict:
    require_json_api(req)
    try:
        media = req.get_media()
    except Exception:
        raise AedError(400, "bad_request", detail="Niepoprawny JSON.")
    if not isinstance(media, dict) or not isinstance(media.get("data"), dict):
        raise AedError(400, "bad_request", detail='Oczekiwano {"data": {…}}.')
    return media


def attributes(media, expected_type: str, allowed: set) -> dict:
    data = media["data"]
    if data.get("type") != expected_type:
        raise AedError(400, "bad_request", detail=f"Oczekiwano type = {expected_type}.")
    attrs = data.get("attributes") or {}
    unknown = sorted(set(attrs) - allowed)
    if unknown:
        raise AedError(
            400,
            "unknown_field",
            field_errors=[FieldError(f"/data/attributes/{k}", "unknown_field", "Pole spoza kontraktu.") for k in unknown],
        )
    return attrs


def client_ip(req) -> Optional[str]:
    return req.remote_addr or None


def iso_date(value) -> Optional[str]:
    return value.date().isoformat() if value else None


# ---------------------------------------------------------------------------
#  Reprezentacje
# ---------------------------------------------------------------------------


def device_feature(device: Device, data: dict, key: Optional[DeviceKey]) -> dict:
    props = {k: v for k, v in (data.get("properties") or {}).items() if k not in PRIVATE_KEYS}
    props.update(id=device.id, status=device.status, last_confirmed_at=iso_date(device.last_confirmed_at))
    if key is not None:
        for name in PRIVATE_KEYS:  # klucze niepubliczne z tabeli kluczy, nie z wersji (API.md §6.1)
            if getattr(key, name):
                props[name] = getattr(key, name)
    return {"type": "Feature", "id": device.id, "geometry": data.get("geometry"), "properties": props}


def device_resource(device: Device) -> dict:
    version = device.current_version
    key = DeviceKey.objects.filter(device_id=device.id).first()
    open_interventions = McIntervention.objects.filter(device_id=device.id, resolved_at__isnull=True).count()
    return {
        "id": device.id,
        "type": "aed_device",
        "attributes": {
            "feature": device_feature(device, version.data, key),
            "site_id": str(device.site_id) if device.site_id else None,
            "visibility": device.visibility,
            "version_no": version.version_no,
            "updated_at": device.updated_at,
            "open_interventions": open_interventions,
        },
        "links": {"self": api_url(f"/auth/aed/org/devices/{device.id}")},
    }


def etag(device: Device) -> str:
    return f'"v{device.current_version.version_no}"'


def me_resource(req) -> dict:
    user = req.user
    link = aed_user_id(user)
    method = login_method(user)
    ctx = load_context(req)
    memberships, pending = [], []
    for m in Membership.objects.filter(user_id=link, revoked_at__isnull=True).select_related("organization"):
        required = ROLE_LOGIN_METHOD.get(m.role)
        memberships.append(
            {
                "organization_id": str(m.organization_id),
                "organization_name": m.organization.name,
                "org_role": m.role,
                "organization_status": m.organization.status,
                "login_method_required": required,
            }
        )
        if required == "login_gov_pl" and not user.is_gov_auth:
            pending.append("link_login_gov_pl")
        elif required == "login_gov_pl" and method != "login_gov_pl":
            pending.append("login_with_login_gov_pl")
    roles = McRole.objects.filter(user_id=link, approved_at__isnull=False, revoked_at__isnull=True)
    return {
        "id": str(user.id),
        "type": "aed_me",
        "attributes": {
            "display_name": user.fullname or user.email,
            "email": user.email,
            "login_method": method,
            "gov_linked": bool(user.is_gov_auth),
            "mc_roles": sorted({r.role for r in roles}),
            "context": {"organization_id": str(ctx.organization_id), "org_role": ctx.org_role} if ctx else None,
            "memberships": memberships,
            "pending_actions": sorted(set(pending)),
        },
        "links": {"self": api_url("/auth/aed/me")},
    }


# ---------------------------------------------------------------------------
#  Błędy zapisu z bazy → kody modułu
# ---------------------------------------------------------------------------


def map_write_error(exc: DatabaseError, ctx, feature: dict) -> AedError:
    pgcode, constraint, detail = sql_error_info(exc)
    if pgcode == "23505" and constraint in ("device_key_serial_uk", "device_key_external_uk"):
        key = "serial_number" if constraint == "device_key_serial_uk" else "external_id"
        if detail == "other_owner":
            return AedError(409, "duplicate_device_other_owner", meta={"key": key})
        if detail and detail.startswith("aed-"):
            return AedError(409, "duplicate_device", meta={"key": key, "device_id": detail})
        # wyścig dwóch zapisów: zwykłe naruszenie indeksu – klasyfikacja funkcją bazy (DEDUPLIKACJA.md §2.1)
        props = feature.get("properties", {})
        with aed_context(ctx.user, organization_id=ctx.organization_id):
            for match in services.match_device_keys(props.get("manufacturer"), props.get("serial_number"),
                                                    props.get("external_id")):  # fmt: skip
                if match["key"] == key and match["same_owner"]:
                    return AedError(409, "duplicate_device", meta={"key": key, "device_id": match["device_id"]})
        return AedError(409, "duplicate_device_other_owner", meta={"key": key})
    if pgcode == "42501":
        return AedError(403, "forbidden")
    if pgcode in ("23514", "23502", "22023", "22P02", "22007", "22008", "23503"):
        return AedError(422, "validation_failed", detail="Dane naruszają reguły rejestru AED.")
    raise exc


def write_attributes(req, ctx, media, allowed=frozenset({"feature", "site_id", "confirmation"})):
    attrs = attributes(media, "aed_device", set(allowed))
    errors = validate_feature(attrs.get("feature"))

    confirmation = attrs.get("confirmation") or {}
    statement = ResponsibilityStatement.objects.filter(kind="change_confirmation").order_by("-valid_from").first()
    if confirmation.get("confirmed") is not True or statement is None or confirmation.get("statement_id") != statement.id:
        errors.append(
            FieldError("/data/attributes/confirmation", "required", "Potwierdź zgodność danych z aktualnym oświadczeniem.")
        )

    site_id = attrs.get("site_id")
    if site_id is not None:
        try:
            site_uuid = UUID(str(site_id))
            valid = Site.objects.filter(id=site_uuid, organization_id=ctx.organization_id, is_active=True).exists()
            valid = valid and (ctx.all_sites or site_uuid in ctx.site_ids)
        except ValueError:
            valid = False
        if not valid:
            errors.append(FieldError("/data/attributes/site_id", "site_not_in_organization", "Lokalizacja spoza podmiotu."))
    elif not ctx.all_sites:
        errors.append(FieldError("/data/attributes/site_id", "required", "Wskaż lokalizację z Twojego zakresu."))

    if errors:
        raise AedError(422, "validation_failed", field_errors=errors)
    return normalize_feature(attrs["feature"]), site_id, statement


def save_version(req, ctx, feature, site_id, statement, device_id=None, expected_version=None) -> Device:
    try:
        with aed_context(
            ctx.user, organization_id=ctx.organization_id, session_id=ctx.session_id, actor_role=ctx.org_role,
            client_ip=client_ip(req),
        ):  # fmt: skip
            if device_id is not None:
                with connection.cursor() as cursor:  # blokada wiersza: If-Match bez wyścigu dwóch PUT
                    cursor.execute(
                        "SELECT v.version_no FROM aed.device d JOIN aed.device_version v ON v.id = d.current_version_id "
                        "WHERE d.id = %s FOR UPDATE OF d",
                        [device_id],
                    )
                    current = cursor.fetchone()[0]
                if current != expected_version:
                    raise AedError(412, "version_conflict", meta={"current_version_no": current})
            return services.save_device_version(
                feature, ctx.user_link_id, ctx.organization_id, device_id=device_id, site_id=site_id, statement=statement
            )
    except DatabaseError as exc:
        raise map_write_error(exc, ctx, feature)


def get_device_or_404(ctx, device_id: str) -> Device:
    device = ctx.devices().filter(pk=device_id).select_related("current_version").first()
    if device is None:
        raise not_found()
    return device


# ---------------------------------------------------------------------------
#  §4 Kontekst
# ---------------------------------------------------------------------------


class MeView:
    @falcon.before(aed_login_required)
    def on_get(self, req, resp, **kwargs):
        write(resp, {"jsonapi": {"version": "1.4"}, "data": me_resource(req)})


class ContextView:
    @falcon.before(aed_login_required)
    def on_post(self, req, resp, **kwargs):
        attrs = attributes(read_body(req), "aed_context", {"organization_id"})
        org_id = attrs.get("organization_id")
        try:
            org_uuid = UUID(str(org_id)) if org_id is not None else None
        except ValueError:
            raise AedError(422, "validation_failed",
                           field_errors=[FieldError("/data/attributes/organization_id", "invalid_format", "UUID.")])  # fmt: skip
        select_context(req, org_uuid)
        write(resp, {"jsonapi": {"version": "1.4"}, "data": me_resource(req)})


# ---------------------------------------------------------------------------
#  §5.2 Podmiot
# ---------------------------------------------------------------------------


class OrganizationView:
    @falcon.before(aed_context_required)
    def on_get(self, req, resp, **kwargs):
        org = AedOrganization.objects.get(pk=req.context.aed.organization_id)
        attrs = {k: getattr(org, k) for k in ("name", "type", "nip", "regon", "krs", "teryt", "address", "contact_email",
                                              "contact_phone", "status", "approved_at")}  # fmt: skip
        body = {"id": str(org.id), "type": "aed_organization", "attributes": attrs, "links": {"self": api_url("/auth/aed/org")}}
        write(resp, {"jsonapi": {"version": "1.4"}, "data": body})


# ---------------------------------------------------------------------------
#  §6 AED podmiotu
# ---------------------------------------------------------------------------


def int_param(req, name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(req.get_param(name) or default)
    except ValueError:
        value = low - 1
    if not low <= value <= high:
        raise AedError(400, "bad_request", detail=f"{name}: {low}–{high}.")
    return value


def filter_devices(req, qs):
    for name in ("status", "visibility", "teryt_terc"):
        if req.get_param(name):
            qs = qs.filter(**{name: req.get_param(name)})
    if req.get_param("site_id"):
        try:
            qs = qs.filter(site_id=UUID(req.get_param("site_id")))
        except ValueError:
            raise AedError(400, "bad_request", detail="site_id musi być UUID.")
    q = (req.get_param("q") or "").strip()
    if q:
        qs = qs.filter(Q(location_pl__icontains=q) | Q(address__icontains=q) | Q(name__icontains=q))
    return qs


class DevicesView:
    @falcon.before(aed_context_required)
    def on_get(self, req, resp, **kwargs):
        page = int_param(req, "page", 1, 1, 10**6)
        per_page = int_param(req, "per_page", 25, 1, 100)
        qs = filter_devices(req, req.context.aed.devices().select_related("current_version").order_by("-updated_at", "id"))
        count = qs.count()
        items = list(qs[(page - 1) * per_page : page * per_page])
        links = {"self": api_url(f"/auth/aed/org/devices?page={page}&per_page={per_page}")}
        if page * per_page < count:
            links["next"] = api_url(f"/auth/aed/org/devices?page={page + 1}&per_page={per_page}")
        body = {"jsonapi": {"version": "1.4"}, "data": [device_resource(d) for d in items], "meta": {"count": count}}
        write(resp, {**body, "links": links})

    @falcon.before(aed_context_required)
    def on_post(self, req, resp, **kwargs):
        ctx = req.context.aed
        media = read_body(req)
        idem_key = idempotency.replay(req, resp, "devices.create", media)
        if idem_key is None:
            return
        feature, site_id, statement = write_attributes(req, ctx, media)
        device = save_version(req, ctx, feature, site_id, statement)
        device = Device.objects.select_related("current_version").get(pk=device.pk)
        resp.set_header("Location", api_url(f"/auth/aed/org/devices/{device.id}"))
        resp.set_header("ETag", etag(device))
        write(resp, {"jsonapi": {"version": "1.4"}, "data": device_resource(device)}, status=falcon.HTTP_201)
        idempotency.store(req, resp, "devices.create", idem_key, media)


class DeviceView:
    @falcon.before(aed_context_required)
    def on_get(self, req, resp, device_id, **kwargs):
        device = get_device_or_404(req.context.aed, device_id)
        resp.set_header("ETag", etag(device))
        write(resp, {"jsonapi": {"version": "1.4"}, "data": device_resource(device)})

    @falcon.before(aed_context_required)
    def on_put(self, req, resp, device_id, **kwargs):
        ctx = req.context.aed
        device = get_device_or_404(ctx, device_id)
        if_match = (req.get_header("If-Match") or "").strip()
        if not if_match:
            raise AedError(428, "precondition_required", meta={"header": "If-Match"})
        match = re.match(r'^(W/)?"v(\d+)"$', if_match)
        if not match:
            raise AedError(412, "version_conflict", meta={"current_version_no": device.current_version.version_no})
        expected = int(match.group(2))
        feature, site_id, statement = write_attributes(req, ctx, read_body(req))
        save_version(req, ctx, feature, site_id, statement, device_id=device.id, expected_version=expected)
        device = Device.objects.select_related("current_version").get(pk=device.pk)
        resp.set_header("ETag", etag(device))
        write(resp, {"jsonapi": {"version": "1.4"}, "data": device_resource(device)})


class DeviceConfirmView:
    """§6.2 / ROLES.md §13.4 – potwierdzenie aktualności bez zmiany danych."""

    @falcon.before(aed_context_required)
    def on_post(self, req, resp, device_id, **kwargs):
        ctx = req.context.aed
        device = get_device_or_404(ctx, device_id)
        try:
            with aed_context(ctx.user, organization_id=ctx.organization_id, session_id=ctx.session_id,
                             actor_role=ctx.org_role, client_ip=client_ip(req)):  # fmt: skip
                services.call("aed.confirm_device", device.id)
        except DatabaseError as exc:
            raise map_write_error(exc, ctx, {})
        resp.status = falcon.HTTP_204
        resp.content_type = None


def _changes(previous: Optional[dict], current: dict):
    if previous is None:
        return sorted((current.get("properties") or {}).keys()) + ["geometry"]
    p_old, p_new = previous.get("properties") or {}, current.get("properties") or {}
    changed = sorted(k for k in set(p_old) | set(p_new) if p_old.get(k) != p_new.get(k))
    if previous.get("geometry") != current.get("geometry"):
        changed.append("geometry")
    return changed


class DeviceVersionsView:
    @falcon.before(aed_context_required)
    def on_get(self, req, resp, device_id, **kwargs):
        device = get_device_or_404(req.context.aed, device_id)
        versions = list(DeviceVersion.objects.filter(device_id=device.id).order_by("version_no"))
        # autor: konto portalu przez auth.user_link
        author_ids = {v.author_user_id for v in versions}
        links = {link.id: link.portal_user for link in UserLink.objects.filter(id__in=author_ids).select_related("portal_user")}
        data, previous = [], None
        for v in versions:
            user = links.get(v.author_user_id)
            data.append(
                {
                    "id": f"{device.id}:{v.version_no}",
                    "type": "aed_device_version",
                    "attributes": {
                        "version_no": v.version_no,
                        "created_at": v.created_at,
                        "author": {"id": str(user.id), "display_name": user.fullname or user.email} if user else None,
                        "author_role": v.author_role,
                        "changes": _changes(previous, v.data),
                    },
                }
            )
            previous = v.data
        write(resp, {"jsonapi": {"version": "1.4"}, "data": list(reversed(data))})


class DeviceVersionView:
    @falcon.before(aed_context_required)
    def on_get(self, req, resp, device_id, version_no, **kwargs):
        device = get_device_or_404(req.context.aed, device_id)
        version = DeviceVersion.objects.filter(device_id=device.id, version_no=version_no).first()
        if version is None:
            raise not_found()
        key = DeviceKey.objects.filter(device_id=device.id).first()
        body = {
            "id": f"{device.id}:{version.version_no}",
            "type": "aed_device_version",
            "attributes": {"version_no": version.version_no, "created_at": version.created_at,
                           "feature": device_feature(device, version.data, key)},  # fmt: skip
        }
        write(resp, {"jsonapi": {"version": "1.4"}, "data": body})


# ---------------------------------------------------------------------------
#  §8 Mapa publiczna (bez logowania; tylko pola publiczne z widoku aed.search_document)
# ---------------------------------------------------------------------------

INTERNAL_DOC_KEYS = ("location", "doc_hash", "version_no", "updated_at", "flagged")


def public_feature(doc: dict) -> dict:
    props = {k: v for k, v in doc.items() if k not in INTERNAL_DOC_KEYS}
    if doc.get("flagged"):
        props["visibility"] = "flagged"
    location = doc["location"]
    coords = [float(location["lon"]), float(location["lat"])]
    return {"type": "Feature", "id": doc["id"], "geometry": {"type": "Point", "coordinates": coords}, "properties": props}


def write_public(req, resp, body):
    text = json.dumps(body, cls=LazyEncoder)
    tag = '"' + hashlib.md5(text.encode("utf-8")).hexdigest() + '"'  # nosec - ETag, nie zabezpieczenie
    resp.set_header("Cache-Control", "public, max-age=60")
    resp.set_header("ETag", tag)
    if req.get_header("If-None-Match") == tag:
        resp.status = falcon.HTTP_304
        resp.content_type = None  # 304 bez treści i bez Content-Type
        return
    resp.status = falcon.HTTP_200
    resp.content_type = GEOJSON
    resp.text = text


def _csv_param(req, name, allowed):
    value = req.get_param(name)
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items or any(v not in allowed for v in items):
        raise AedError(400, "bad_request", detail=f"{name}: dozwolone {', '.join(sorted(allowed))}.")
    return items


def _bbox_filter(req):
    bbox = req.get_param("bbox")
    if not bbox:
        return None
    try:
        min_lon, min_lat, max_lon, max_lat = (float(v) for v in bbox.split(","))
        if min_lon > max_lon or min_lat > max_lat:
            raise ValueError
    except ValueError:
        raise AedError(400, "bad_request", detail="bbox=minLon,minLat,maxLon,maxLat.")
    return "d.lon BETWEEN %s AND %s AND d.lat BETWEEN %s AND %s", [min_lon, max_lon, min_lat, max_lat]


def public_filters(req):
    """Warunki SQL (stałe teksty) i parametry dla ``GET /aed``."""
    filters = [_bbox_filter(req)]
    access = _csv_param(req, "access", {"public", "customers", "on_request", "private", "no", "unknown"})
    filters.append(("d.access::text = ANY(%s)", [access]) if access else None)
    condition = _csv_param(req, "condition", {"working", "faulty", "unknown"})
    filters.append(("d.condition::text = ANY(%s)", [condition]) if condition else None)
    filters.append(("d.is_24_7 IS TRUE", []) if req.get_param("is_24_7") == "true" else None)
    terc = req.get_param("teryt_terc")
    filters.append(("d.teryt_terc = %s", [terc]) if terc else None)
    filters = [f for f in filters if f]
    return [f[0] for f in filters], [p for f in filters for p in f[1]]


class PublicDevicesView:
    @staticmethod
    def on_get(req, resp, **kwargs):
        where, params = public_filters(req)
        limit = int_param(req, "limit", 2000, 1, 5000)
        sql = "SELECT s.document FROM aed.search_document s JOIN aed.device d ON d.id = s.id"
        if where:
            sql += " WHERE " + " AND ".join(where)
        with connection.cursor() as cursor:
            cursor.execute(sql + " ORDER BY d.id LIMIT %s", params + [limit + 1])
            docs = [row[0] for row in cursor.fetchall()]
        features = [public_feature(d) for d in docs[:limit]]
        write_public(req, resp, {"type": "FeatureCollection", "features": features, "meta": {"truncated": len(docs) > limit}})


class PublicDeviceView:
    @staticmethod
    def on_get(req, resp, device_id, **kwargs):
        with connection.cursor() as cursor:
            cursor.execute("SELECT document FROM aed.search_document WHERE id = %s", [device_id])
            row = cursor.fetchone()
        if row is None:
            raise not_found()
        write_public(req, resp, public_feature(row[0]))
