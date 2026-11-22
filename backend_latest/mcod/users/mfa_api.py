"""Błędy 2FA w API (Falcon).

Ogólny ``http_error_handler`` portalu w API 1.4 zastępuje ``code`` statusem HTTP, a klient musi odróżnić
„podaj kod” od „skonfiguruj aplikację” i „zły kod”. Dlatego błędy 2FA mają własną klasę i własny handler,
który zachowuje ``errors[].code`` (``mfa_required``, ``mfa_setup_required``, ``mfa_invalid_code``, …).

Status 403, nie 401: frontend przy 401 czyści stan użytkownika i przekierowuje na stronę logowania.
"""

import json
from contextlib import contextmanager
from uuid import uuid4

import falcon
from django.utils.translation import gettext_lazy as _

from mcod.core.api.jsonapi.serializers import ErrorsSchema
from mcod.lib.encoders import LazyEncoder
from mcod.lib.errors import update_content_type
from mcod.lib.schemas import ErrorSchema
from mcod.users import mfa

MFA_ERROR_DESCRIPTIONS = {
    mfa.MfaRequired.code: _("Enter the code from your authenticator app or a recovery code."),
    mfa.MfaSetupRequired.code: _(
        "The administrator requires two-factor authentication for this account. Set up an authenticator app."
    ),
    mfa.MfaInvalidCode.code: _("Invalid or already used verification code."),
    mfa.MfaNotAllowed.code: _("This two-factor authentication operation is not allowed for this account."),
    mfa.MfaSetupNotStarted.code: _("Two-factor authentication setup has not been started."),
}


class MfaHTTPError(falcon.HTTPForbidden):
    def __init__(self, code):
        super().__init__(
            title="403 Forbidden",
            description=MFA_ERROR_DESCRIPTIONS.get(code, _("Two-factor authentication error.")),
            code=code,
        )


@contextmanager
def mfa_api_errors():
    try:
        yield
    except mfa.MfaError as exc:
        raise MfaHTTPError(exc.code) from exc


def mfa_error_handler(request, response, exc, params):
    update_content_type(request, response)
    response.status = exc.status
    if getattr(request, "api_version", None) == "1.0":
        body = ErrorSchema().dump({"title": exc.title, "description": exc.description, "code": exc.code})
    else:
        body = ErrorsSchema().dump(
            {
                "jsonapi": {"version": "1.4"},
                "errors": [
                    {
                        "id": uuid4(),
                        "status": exc.status,
                        "code": exc.code,
                        "title": exc.title,
                        "detail": exc.description,
                    }
                ],
            }
        )
    response.text = json.dumps(body, cls=LazyEncoder)
