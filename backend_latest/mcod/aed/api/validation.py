"""Walidacja zapisu AED – API.md §6.3 (format danych SCHEMA.md 1.3.0).

Backend sprawdza każdą regułę przed zapisem; baza i tak egzekwuje ograniczenia (CHECK, triggery), ale błąd
z bazy nie wskazuje pola. Zwraca listę ``FieldError`` z wskaźnikiem JSON i kodem pola (API.md §2.3).
"""

import re
from datetime import date
from typing import Any, List, Optional

from mcod.aed.api.errors import FieldError
from mcod.aed.models import ACCESS_LEVELS, DEVICE_CONDITIONS, DEVICE_STATUSES

P = "/data/attributes/feature/properties/"
GEOMETRY = "/data/attributes/feature/geometry/coordinates"

LON_RANGE, LAT_RANGE = (14.07, 24.16), (49.00, 54.84)
EMERGENCY_NUMBERS = {"112", "999", "998", "997", "986"}

# pola, których klient nie może ustawić (API.md §6.3)
READ_ONLY = {
    "id", "osm_id", "osm_type", "osm_version", "visibility", "last_confirmed_at", "needs_verification",
    "fixme", "source", "version_no", "updated_at", "open_interventions",
}  # fmt: skip

TEXT_LIMITS = {
    "location_pl": (5, 500),
    "location_en": (0, 500),
    "opening_hours": (0, 255),
    "access_note": (0, 1000),
    "description": (0, 1000),
    "description_en": (0, 1000),
    "name": (0, 255),
    "operator": (0, 255),
    "operator_short": (0, 255),
    "address": (0, 255),
    "addr_street_type": (0, 10),
    "addr_street": (0, 150),
    "addr_housenumber": (0, 20),
    "addr_unit": (0, 20),
    "addr_city": (0, 100),
    "email": (0, 254),
    "website": (0, 2048),
    "manufacturer": (0, 100),
    "model": (0, 100),
    "serial_number": (0, 50),
    "external_id": (1, 100),
    "check_date": (0, 10),
}
MULTILINE = {"location_pl", "location_en", "access_note", "description", "description_en"}
BOOLEANS = {"is_24_7", "seasonal", "indoor", "locked", "vehicle_mounted", "portable"}
ENUMS = {
    "status": {v for v, _ in DEVICE_STATUSES},
    "access": {v for v, _ in ACCESS_LEVELS},
    "condition": {v for v, _ in DEVICE_CONDITIONS},
}
PATTERNS = {
    "addr_postcode": re.compile(r"^\d{2}-\d{3}$"),
    "addr_housenumber": re.compile(r"^\d"),
    "teryt_terc": re.compile(r"^\d{7}$"),
    "teryt_simc": re.compile(r"^\d{7}$"),
    "teryt_ulic": re.compile(r"^\d{5}$"),
    "email": re.compile(r"^[^@\s]+@[^@\s]+$"),
    "website": re.compile(r"^https://", re.I),
    "serial_number": re.compile(r"^[0-9A-Za-z][0-9A-Za-z ./-]*$"),
    "check_date": re.compile(r"^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?)?$"),
    "condition_checked_at": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
}
PHONE = re.compile(r"^\+[1-9]\d{7,14}$")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
CONTROL_NO_NEWLINE = re.compile(r"[\x00-\x1f\x7f]")
ADDR_PARTS = ("addr_street_type", "addr_street", "addr_housenumber", "addr_unit", "addr_postcode", "addr_city")
KNOWN = (
    set(TEXT_LIMITS) | BOOLEANS | set(ENUMS) | set(PATTERNS)
    | {"level", "count", "phones", "images", "condition_checked_at", "teryt_terc", "teryt_simc", "teryt_ulic", "addr_postcode"}
)  # fmt: skip


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class _Errors(list):
    def add(self, name: str, code: str, detail: str, pointer: Optional[str] = None):
        self.append(FieldError(pointer or P + name, code, detail))


def _check_geometry(feature: dict, errors: _Errors) -> None:
    geometry = feature.get("geometry")
    coords = geometry.get("coordinates") if isinstance(geometry, dict) else None
    is_point = isinstance(geometry, dict) and geometry.get("type") == "Point"
    if not (is_point and isinstance(coords, list) and len(coords) == 2 and all(_is_number(c) for c in coords)):
        errors.add("", "required", "Wymagany punkt [lon, lat].", GEOMETRY)
    elif not (LON_RANGE[0] <= coords[0] <= LON_RANGE[1] and LAT_RANGE[0] <= coords[1] <= LAT_RANGE[1]):
        errors.add("", "out_of_bounds", "Punkt leży poza Polską (kolejność współrzędnych: [lon, lat]).", GEOMETRY)


def _check_names_and_required(props: dict, errors: _Errors) -> None:
    for name in props:
        if name in READ_ONLY:
            errors.add(name, "not_editable", "Pole tylko do odczytu.")
        elif name not in KNOWN:
            errors.add(name, "unknown_field", "Pole spoza formatu danych AED.")
    for name in ("status", "access", "location_pl"):
        if props.get(name) in (None, ""):
            errors.add(name, "required", "Pole wymagane.")


def _check_types(props: dict, errors: _Errors) -> None:
    for name, allowed in ENUMS.items():
        value = props.get(name)
        if value is not None and value not in allowed:
            errors.add(name, "invalid_enum", f"Dozwolone wartości: {', '.join(sorted(allowed))}.")
    for name in BOOLEANS:
        if props.get(name) is not None and not isinstance(props[name], bool):
            errors.add(name, "invalid_format", "Oczekiwano wartości logicznej.")
    level = props.get("level")
    if level is not None and (not _is_number(level) or not -20 <= level <= 200 or (level * 4) % 1):
        errors.add("level", "out_of_range", "Piętro od -20 do 200, krok 0,25.")
    count = props.get("count")
    if count is not None and (not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 50):
        errors.add("count", "out_of_range", "Liczba urządzeń od 1 do 50.")


def _check_text(name: str, value: Any, errors: _Errors) -> None:
    low, high = TEXT_LIMITS[name]
    if not isinstance(value, str):
        errors.add(name, "invalid_format", "Oczekiwano tekstu.")
        return
    if len(value) > high:
        errors.add(name, "too_long", f"Maksymalnie {high} znaków.")
    elif len(value.strip()) < low:
        errors.add(name, "too_short", f"Minimalnie {low} znaków.")
    if (CONTROL if name in MULTILINE else CONTROL_NO_NEWLINE).search(value):
        errors.add(name, "invalid_format", "Niedozwolone znaki sterujące.")


def _check_texts_and_formats(props: dict, errors: _Errors) -> None:
    for name in TEXT_LIMITS:
        if props.get(name) is not None:
            _check_text(name, props[name], errors)
    for name, pattern in PATTERNS.items():
        value = props.get(name)
        if isinstance(value, str) and value and not pattern.search(value):
            errors.add(name, "invalid_format", "Nieprawidłowy format.")
    if props.get("is_24_7") is True and props.get("opening_hours") not in (None, "24/7"):
        errors.add("opening_hours", "invalid_format", "Dla is_24_7 = true godziny muszą mieć wartość 24/7.")


def _check_list(props: dict, name: str, limit: int, is_valid, detail: str, errors: _Errors) -> None:
    values = props.get(name)
    if values is None:
        return
    if not isinstance(values, list) or len(values) > limit:
        errors.add(name, "invalid_format", f"Maksymalnie {limit} pozycji.")
        return
    for i, value in enumerate(values):
        if not is_valid(value):
            errors.add(name, "invalid_format", detail, f"{P}{name}/{i}")


def _valid_phone(phone: Any) -> bool:
    return isinstance(phone, str) and bool(PHONE.match(phone)) and phone.lstrip("+") not in EMERGENCY_NUMBERS


def _valid_image(url: Any) -> bool:
    return isinstance(url, str) and url.lower().startswith("https://") and len(url) <= 2048


DEPENDENCIES = [  # (pole, wymagane gdy podane, komunikat)
    ("addr_street_type", "addr_street", "Wymagane przy podaniu cechy ulicy."),
    ("addr_unit", "addr_housenumber", "Wymagane przy podaniu numeru lokalu."),
    ("teryt_ulic", "teryt_simc", "Wymagane przy podaniu teryt_ulic."),
    ("serial_number", "manufacturer", "Wymagane przy podaniu numeru seryjnego."),
]


def _check_dependencies(props: dict, errors: _Errors) -> None:
    has_parts = any(props.get(p) not in (None, "") for p in ADDR_PARTS)
    if has_parts and props.get("address") not in (None, ""):
        errors.add("address", "not_editable", "Adres jest składany z części addr_*.")
    if has_parts and not props.get("addr_city"):
        errors.add("addr_city", "required", "Wymagane przy podaniu części adresu.")
    for field, required, detail in DEPENDENCIES:
        if props.get(field) and not props.get(required):
            errors.add(required, "required", detail)


def _check_dates(props: dict, errors: _Errors) -> None:
    check_date = props.get("check_date")
    if isinstance(check_date, str) and PATTERNS["check_date"].match(check_date):
        if check_date > date.today().isoformat()[: len(check_date)]:
            errors.add("check_date", "out_of_range", "Data z przyszłości.")
    condition, checked = props.get("condition", "unknown"), props.get("condition_checked_at")
    if condition != "unknown" and not checked:
        errors.add("condition_checked_at", "required", "Wymagane, gdy stan jest znany.")
    if isinstance(checked, str) and PATTERNS["condition_checked_at"].match(checked):
        try:
            if date.fromisoformat(checked) > date.today():
                errors.add("condition_checked_at", "out_of_range", "Data z przyszłości.")
        except ValueError:
            errors.add("condition_checked_at", "invalid_format", "Nieprawidłowa data.")


def validate_feature(feature: Any) -> List[FieldError]:
    if not isinstance(feature, dict) or feature.get("type") != "Feature":
        return [FieldError("/data/attributes/feature", "invalid_format", "Oczekiwano obiektu GeoJSON Feature.")]
    errors = _Errors()
    _check_geometry(feature, errors)
    props = feature.get("properties")
    if not isinstance(props, dict):
        errors.add("", "required", "Brak właściwości AED.", "/data/attributes/feature/properties")
        return list(errors)
    _check_names_and_required(props, errors)
    _check_types(props, errors)
    _check_texts_and_formats(props, errors)
    _check_list(props, "phones", 5, _valid_phone, "Numer w formacie E.164, bez numerów alarmowych.", errors)
    _check_list(props, "images", 10, _valid_image, "Adres https://.", errors)
    _check_dependencies(props, errors)
    _check_dates(props, errors)
    return list(errors)


def normalize_feature(feature: dict) -> dict:
    """Po walidacji: SCHEMA.md 1.3.0 – przy stanie ``unknown`` data sprawdzenia jest pomijana."""
    props = dict(feature["properties"])
    if props.get("condition", "unknown") == "unknown":
        props.pop("condition_checked_at", None)
    props = {k: v for k, v in props.items() if v is not None}
    return {"type": "Feature", "geometry": feature["geometry"], "properties": props}
