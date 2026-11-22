"""Błędy API modułu AED w formacie portalu (JSON:API ``errors``) z kodami modułu (API.md §2.2–§2.3).

Ogólny handler portalu w API 1.4 zastępuje ``code`` statusem HTTP i gubi ``source``/``meta``, dlatego moduł
zgłasza błędy wyjątkiem ``AedError`` z własnym handlerem (rejestrowanym w ``mcod.api``).
Treść błędu nie zdradza, który warunek uwierzytelnienia zawiódł (JWT.md §6).
"""

import json
from typing import Any, Dict, List, Optional
from uuid import uuid4

import falcon
from django.db import Error as DatabaseError

from mcod.lib.encoders import LazyEncoder

STATUS = {
    400: falcon.HTTP_400,
    401: falcon.HTTP_401,
    403: falcon.HTTP_403,
    404: falcon.HTTP_404,
    409: falcon.HTTP_409,
    412: falcon.HTTP_412,
    413: falcon.HTTP_413,
    415: falcon.HTTP_415,
    422: falcon.HTTP_422,
    428: falcon.HTTP_428,
    429: falcon.HTTP_429,
}

TITLES = {
    "bad_request": "Nieprawidłowe żądanie",
    "unknown_field": "Pole spoza kontraktu",
    "aed_context_required": "Wymagany wybór podmiotu",
    "forbidden": "Brak uprawnień",
    "login_method_required": "Wymagane logowanie przez login.gov.pl",
    "organization_inactive": "Podmiot nieaktywny",
    "not_found": "Nie znaleziono",
    "conflict": "Konflikt stanu",
    "idempotency_key_reused": "Klucz idempotencji użyty z inną treścią",
    "duplicate_device": "AED jest już w rejestrze podmiotu",
    "duplicate_device_other_owner": "AED jest w rejestrze innego podmiotu",
    "version_conflict": "Dane AED zmieniły się w międzyczasie",
    "unsupported_media_type": "Nieobsługiwany typ treści",
    "validation_failed": "Nieprawidłowe dane wejściowe",
    "precondition_required": "Brak wymaganego nagłówka",
}


class FieldError:
    def __init__(self, pointer: str, field_code: str, detail: str):
        self.pointer, self.field_code, self.detail = pointer, field_code, detail


class AedError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        detail: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        field_errors: Optional[List[FieldError]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(code)
        self.status, self.code, self.detail = status, code, detail
        self.meta, self.field_errors, self.headers = meta or {}, field_errors or [], headers or {}

    def body(self) -> dict:
        status = STATUS[self.status]
        title = TITLES.get(self.code, self.code)
        if self.field_errors:
            errors = [
                {
                    "id": str(uuid4()),
                    "status": status,
                    "code": self.code,
                    "title": title,
                    "detail": fe.detail,
                    "source": {"pointer": fe.pointer},
                    "meta": {"field_code": fe.field_code},
                }
                for fe in self.field_errors
            ]
        else:
            error = {"id": str(uuid4()), "status": status, "code": self.code, "title": title}
            if self.detail:
                error["detail"] = self.detail
            if self.meta:
                error["meta"] = self.meta
            errors = [error]
        return {"jsonapi": {"version": "1.4"}, "errors": errors}


def not_found() -> AedError:
    """Także dla obiektu innego podmiotu – bez rozróżnienia (API.md §2.3)."""
    return AedError(404, "not_found")


def context_required() -> AedError:
    return AedError(401, "aed_context_required")


def aed_error_handler(request, response, exc: AedError, params):
    response.status = STATUS[exc.status]
    response.content_type = "application/vnd.api+json"
    response.set_header("Cache-Control", "no-store")
    for name, value in exc.headers.items():
        response.set_header(name, value)
    response.text = json.dumps(exc.body(), cls=LazyEncoder)


def sql_error_info(exc: DatabaseError):
    cause = exc.__cause__ or exc
    diag = getattr(cause, "diag", None)
    return (
        getattr(cause, "pgcode", None),
        getattr(diag, "constraint_name", None) if diag else None,
        getattr(diag, "message_detail", None) if diag else None,
    )
