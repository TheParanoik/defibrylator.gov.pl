"""Idempotencja żądań oznaczonych [I] – API.md §6.4.

Klucz ``Idempotency-Key`` (UUID v4) jest wymagany. Odpowiedź przechowujemy 24 h w cache portalu (Redis)
w zakresie (użytkownik, endpoint, klucz): powtórzenie z tą samą treścią zwraca zapisaną odpowiedź,
z inną treścią → 409 ``idempotency_key_reused``. Zapisujemy tylko odpowiedzi 2xx – błąd można ponowić.
"""

import hashlib
import json
from typing import Optional
from uuid import UUID

from django.core.cache import caches

from mcod.aed.api.errors import AedError

TTL_SECONDS = 24 * 3600


def _cache():
    return caches["default"]


def _key(user_id, endpoint: str, idem_key: str) -> str:
    return f"aed:idem:{user_id}:{endpoint}:{idem_key}"


def body_hash(media) -> str:
    return hashlib.sha256(json.dumps(media, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def require_key(req) -> str:
    value = req.get_header("Idempotency-Key")
    if not value:
        raise AedError(428, "precondition_required", meta={"header": "Idempotency-Key"})
    try:
        if UUID(value).version != 4:
            raise ValueError
    except ValueError:
        raise AedError(400, "bad_request", detail="Idempotency-Key musi być UUID v4.")
    return value


def replay(req, resp, endpoint: str, media) -> Optional[str]:
    """Zwraca klucz do zapisu albo odtwarza zapisaną odpowiedź (wtedy ustawia resp i zwraca None)."""
    idem_key = require_key(req)
    stored = _cache().get(_key(req.user.id, endpoint, idem_key))
    if stored is None:
        return idem_key
    if stored["hash"] != body_hash(media):
        raise AedError(409, "idempotency_key_reused")
    resp.status = stored["status"]
    resp.content_type = stored["content_type"]
    for name, value in stored["headers"].items():
        resp.set_header(name, value)
    resp.text = stored["text"]
    return None


def store(req, resp, endpoint: str, idem_key: str, media) -> None:
    headers = {name: resp.get_header(name) for name in ("Location", "ETag") if resp.get_header(name)}
    _cache().set(
        _key(req.user.id, endpoint, idem_key),
        {"hash": body_hash(media), "status": resp.status, "content_type": resp.content_type, "headers": headers,
         "text": resp.text},  # fmt: skip
        TTL_SECONDS,
    )
