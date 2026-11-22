"""API modułu AED – kontekst podmiotu, izolacja podmiotów, AED podmiotu, mapa publiczna (API.md §4–§8)."""

import uuid

import falcon
import pytest
from django.db import connection

from mcod.aed.context import aed_context
from mcod.aed.tests.conftest import ORG_A, ORG_B, SITE_A1, SITE_A2

pytestmark = [pytest.mark.django_db, pytest.mark.depends_on_component, pytest.mark.component_api]

JSONAPI = {"Content-Type": "application/vnd.api+json"}


def feature(lon=21.0, lat=52.2, **props):
    base = {"status": "active", "access": "public", "location_pl": "Hol główny przy portierni"}
    return {"type": "Feature", "geometry": {"type": "Point", "coordinates": [lon, lat]}, "properties": {**base, **props}}


def device_body(aed, feat=None, site_id=None, **extra):
    attrs = {"feature": feat or feature(), "confirmation": {"statement_id": aed["statement_id"], "confirmed": True}}
    if site_id:
        attrs["site_id"] = site_id
    attrs.update(extra)
    return {"data": {"type": "aed_device", "attributes": attrs}}


class Session:
    """Klient z sesją portalu użytkownika i (opcjonalnie) wybranym podmiotem."""

    def __init__(self, client, header):
        self.client, self.headers = client, {"Authorization": header}

    def call(self, method, path, json=None, headers=None):
        all_headers = {**self.headers, **(JSONAPI if json is not None else {}), **(headers or {})}
        return getattr(self.client, f"simulate_{method}")(path, json=json, headers=all_headers)

    def select(self, org_id):
        return self.call(
            "post", "/auth/aed/context", {"data": {"type": "aed_context", "attributes": {"organization_id": org_id}}}
        )

    def create(self, aed, feat=None, site_id=None, key=None):
        return self.call("post", "/auth/aed/org/devices", device_body(aed, feat, site_id),
                         {"Idempotency-Key": key or str(uuid.uuid4())})  # fmt: skip


@pytest.fixture
def sessions(client14, aed, auth_header):
    def make(who, org=None):
        session = Session(client14, auth_header(aed["users"][who]))
        if org:
            resp = session.select(org)
            assert resp.status == falcon.HTTP_200, resp.json
        return session

    return make


def code(resp):
    return resp.json["errors"][0]["code"]


# ---------------------------------------------------------------------------
#  §4 Kontekst
# ---------------------------------------------------------------------------


class TestContext:
    def test_me_lists_memberships_without_context(self, sessions):
        resp = sessions("a").call("get", "/auth/aed/me")
        assert resp.status == falcon.HTTP_200
        attrs = resp.json["data"]["attributes"]
        assert attrs["context"] is None and attrs["login_method"] == "login_gov_pl"
        assert [m["organization_id"] for m in attrs["memberships"]] == [ORG_A]
        assert resp.headers["cache-control"] == "no-store"

    def test_select_own_and_foreign_organization(self, sessions):
        session = sessions("a")
        assert session.select(ORG_B).status == falcon.HTTP_403
        resp = session.select(ORG_A)
        assert resp.status == falcon.HTTP_200
        assert resp.json["data"]["attributes"]["context"] == {"organization_id": ORG_A, "org_role": "org_admin"}

    def test_org_admin_requires_login_gov_pl_session(self, sessions, aed):
        aed["users"]["a"].last_logged_method = None  # brak zapisanej metody = logowanie hasłem
        aed["users"]["a"].save(update_fields=["last_logged_method"])
        resp = sessions("a").select(ORG_A)
        assert resp.status == falcon.HTTP_403 and code(resp) == "login_method_required"

    def test_org_endpoints_require_context(self, sessions):
        resp = sessions("a").call("get", "/auth/aed/org/devices")
        assert resp.status == falcon.HTTP_401 and code(resp) == "aed_context_required"

    def test_requires_portal_login(self, client14):
        assert client14.simulate_get("/auth/aed/me").status == falcon.HTTP_401

    def test_revoked_membership_loses_context_immediately(self, sessions, aed):
        editor = sessions("ed", ORG_A)
        assert editor.call("get", "/auth/aed/org").status == falcon.HTTP_200
        with aed_context(aed["users"]["a"], organization_id=ORG_A) as link:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE org.membership SET revoked_at = now(), revoked_by = %s, revoke_reason = 'koniec umowy' "
                    "WHERE id = %s",
                    [link, aed["editor_membership"]],
                )
        resp = editor.call("get", "/auth/aed/org")
        assert resp.status == falcon.HTTP_401 and code(resp) == "aed_context_required"

    def test_get_organization(self, sessions):
        resp = sessions("a", ORG_A).call("get", "/auth/aed/org")
        assert resp.json["data"]["id"] == ORG_A and resp.json["data"]["attributes"]["name"] == "Podmiot A"


# ---------------------------------------------------------------------------
#  §6 AED podmiotu + izolacja
# ---------------------------------------------------------------------------


class TestDevices:
    def test_create_and_read(self, sessions, aed):
        admin = sessions("a", ORG_A)
        resp = admin.create(aed, feature(manufacturer="Philips", serial_number="AB-12 34", phones=["+48221234567"]))
        assert resp.status == falcon.HTTP_201, resp.json
        device_id = resp.json["data"]["id"]
        assert resp.headers["etag"] == '"v1"' and resp.headers["location"].endswith(device_id)
        resp = admin.call("get", f"/auth/aed/org/devices/{device_id}")
        props = resp.json["data"]["attributes"]["feature"]["properties"]
        assert props["serial_number"] == "AB-12 34" and props["phones"] == ["+48221234567"]
        assert admin.call("get", "/auth/aed/org/devices").json["meta"]["count"] == 1

    def test_idempotency(self, sessions, aed):
        admin = sessions("a", ORG_A)
        key = str(uuid.uuid4())
        first = admin.create(aed, key=key)
        again = admin.create(aed, key=key)
        assert again.status == falcon.HTTP_201 and again.json["data"]["id"] == first.json["data"]["id"]
        assert admin.call("get", "/auth/aed/org/devices").json["meta"]["count"] == 1
        other = admin.create(aed, feature(location_pl="Inne miejsce w budynku"), key=key)
        assert other.status == falcon.HTTP_409 and code(other) == "idempotency_key_reused"
        resp = admin.call("post", "/auth/aed/org/devices", device_body(aed))
        assert resp.status == falcon.HTTP_428

    def test_validation(self, sessions, aed):
        admin = sessions("a", ORG_A)
        resp = admin.create(aed, feature(lon=52.2, lat=21.0, visibility="hidden", favourite=True, level=0.3))
        assert resp.status == falcon.HTTP_422 and code(resp) == "validation_failed"
        found = {(e["source"]["pointer"], e["meta"]["field_code"]) for e in resp.json["errors"]}
        assert ("/data/attributes/feature/geometry/coordinates", "out_of_bounds") in found
        assert ("/data/attributes/feature/properties/visibility", "not_editable") in found
        assert ("/data/attributes/feature/properties/favourite", "unknown_field") in found
        assert ("/data/attributes/feature/properties/level", "out_of_range") in found
        body = device_body(aed)
        body["data"]["attributes"]["confirmation"]["confirmed"] = False
        resp = admin.call("post", "/auth/aed/org/devices", body, {"Idempotency-Key": str(uuid.uuid4())})
        assert resp.json["errors"][0]["source"]["pointer"] == "/data/attributes/confirmation"

    def test_isolation_between_organizations(self, sessions, aed):
        device_id = sessions("a", ORG_A).create(aed).json["data"]["id"]
        other = sessions("b", ORG_B)
        assert other.call("get", "/auth/aed/org/devices").json["meta"]["count"] == 0
        for method, path in [
            ("get", f"/auth/aed/org/devices/{device_id}"),
            ("get", f"/auth/aed/org/devices/{device_id}/versions"),
            ("get", f"/auth/aed/org/devices/{device_id}/versions/1"),
            ("post", f"/auth/aed/org/devices/{device_id}/confirm"),
        ]:
            resp = other.call(method, path)
            assert resp.status == falcon.HTTP_404 and code(resp) == "not_found", path
        resp = other.call("put", f"/auth/aed/org/devices/{device_id}", device_body(aed), {"If-Match": '"v1"'})
        assert resp.status == falcon.HTTP_404
        # organization_id w żądaniu nie zmienia kontekstu – pole spoza kontraktu
        resp = other.call("post", "/auth/aed/org/devices", device_body(aed, organization_id=ORG_A),
                          {"Idempotency-Key": str(uuid.uuid4())})  # fmt: skip
        assert resp.status == falcon.HTTP_400 and code(resp) == "unknown_field"

    def test_editor_limited_to_own_sites(self, sessions, aed):
        admin = sessions("a", ORG_A)
        in_s2 = admin.create(aed, site_id=SITE_A2).json["data"]["id"]
        in_s1 = admin.create(aed, feature(location_pl="Hol szkoły numer 1"), site_id=SITE_A1).json["data"]["id"]
        editor = sessions("ed", ORG_A)
        listed = [d["id"] for d in editor.call("get", "/auth/aed/org/devices").json["data"]]
        assert listed == [in_s1]
        assert editor.call("get", f"/auth/aed/org/devices/{in_s2}").status == falcon.HTTP_404
        resp = editor.create(aed)
        assert resp.status == falcon.HTTP_422 and resp.json["errors"][0]["meta"]["field_code"] == "required"
        resp = editor.create(aed, site_id=SITE_A2)
        assert resp.json["errors"][0]["meta"]["field_code"] == "site_not_in_organization"
        assert editor.create(aed, feature(location_pl="Pokój nauczycielski"), site_id=SITE_A1).status == falcon.HTTP_201

    def test_update_with_if_match(self, sessions, aed):
        admin = sessions("a", ORG_A)
        device_id = admin.create(aed).json["data"]["id"]
        path = f"/auth/aed/org/devices/{device_id}"
        body = device_body(aed, feature(access="customers"))
        resp = admin.call("put", path, body)
        assert resp.status == falcon.HTTP_428, resp.json
        resp = admin.call("put", path, body, {"If-Match": '"v7"'})
        assert resp.status == falcon.HTTP_412 and resp.json["errors"][0]["meta"]["current_version_no"] == 1
        resp = admin.call("put", path, body, {"If-Match": '"v1"'})
        assert resp.status == falcon.HTTP_200 and resp.headers["etag"] == '"v2"'
        assert resp.json["data"]["attributes"]["feature"]["properties"]["access"] == "customers"
        versions = admin.call("get", f"{path}/versions").json["data"]
        assert [v["attributes"]["version_no"] for v in versions] == [2, 1]
        assert versions[0]["attributes"]["changes"] == ["access"]
        assert admin.call("post", f"{path}/confirm").status == falcon.HTTP_204

    def test_duplicates(self, sessions, aed):
        admin = sessions("a", ORG_A)
        first = admin.create(aed, feature(manufacturer="Philips", serial_number="AB1234")).json["data"]["id"]
        resp = admin.create(aed, feature(manufacturer="PHILIPS", serial_number="ab-12 34"))
        assert resp.status == falcon.HTTP_409 and code(resp) == "duplicate_device"
        assert resp.json["errors"][0]["meta"] == {"key": "serial_number", "device_id": first}
        resp = sessions("b", ORG_B).create(aed, feature(manufacturer="Philips", serial_number="AB1234"))
        assert resp.status == falcon.HTTP_409 and code(resp) == "duplicate_device_other_owner"
        assert "device_id" not in resp.json["errors"][0]["meta"]


# ---------------------------------------------------------------------------
#  §8 Mapa publiczna
# ---------------------------------------------------------------------------


class TestPublicMap:
    def test_public_fields_only(self, sessions, aed, client14):
        admin = sessions("a", ORG_A)
        device_id = admin.create(aed, feature(manufacturer="Philips", serial_number="AB1", external_id="INW-1",
                                              phones=["+48221234567"], email="aed@example.pl")).json["data"]["id"]  # fmt: skip
        resp = client14.simulate_get(f"/aed/{device_id}")
        assert resp.status == falcon.HTTP_200 and resp.headers["content-type"].startswith("application/geo+json")
        props = resp.json["properties"]
        assert props["manufacturer"] == "Philips" and resp.json["geometry"]["coordinates"] == [21.0, 52.2]
        for private in ("serial_number", "external_id", "phones", "email", "fixme", "source"):
            assert private not in props
        assert resp.headers["cache-control"] == "public, max-age=60"
        again = client14.simulate_get(f"/aed/{device_id}", headers={"If-None-Match": resp.headers["etag"]})
        assert again.status == falcon.HTTP_304

    def test_bbox_filters_and_hidden(self, sessions, aed, client14):
        admin = sessions("a", ORG_A)
        warsaw = admin.create(aed).json["data"]["id"]
        krakow = admin.create(aed, feature(lon=19.94, lat=50.06, location_pl="Rynek Główny 1")).json["data"]["id"]
        resp = client14.simulate_get("/aed", params={"bbox": "20.5,52.0,21.5,52.5"})
        assert [f["id"] for f in resp.json["features"]] == [warsaw]
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL session_replication_role = replica")
            cursor.execute("UPDATE aed.device SET visibility = 'hidden' WHERE id = %s", [krakow])
            cursor.execute("SET LOCAL session_replication_role = origin")
        assert client14.simulate_get(f"/aed/{krakow}").status == falcon.HTTP_404
        assert admin.call("get", f"/auth/aed/org/devices/{krakow}").status == falcon.HTTP_200  # właściciel widzi
        assert client14.simulate_get("/aed", params={"limit": "0"}).status == falcon.HTTP_400
