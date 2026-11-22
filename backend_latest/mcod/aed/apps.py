from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AedConfig(AppConfig):
    """Moduł „Misja AED” – rejestr i mapa defibrylatorów (docs: ARCHITEKTURA.md, ROLES.md, SCHEMA.md)."""

    name = "mcod.aed"
    # Etykieta celowo sortuje się po wszystkich aplikacjach portalu: przy świeżej bazie Django planuje migracje
    # od liści grafu w kolejności alfabetycznej etykiet. Moduł zależy od users.0034 (user_totp, is_gov_auth),
    # więc etykieta „aed” wciągała cały łańcuch users przed histories.0004_apply_patches, którego łatki SQL
    # zależą od kolejności, a nie od zadeklarowanych zależności – i tworzenie bazy testowej padało.
    label = "zz_aed"
    verbose_name = _("AED register")
