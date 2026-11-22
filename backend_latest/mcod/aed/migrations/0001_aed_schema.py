"""Schematy auth (warstwa zgodności z kontami portalu), org, aed, audit – z plików mcod/aed/sql/.

SQL jest wykonywany jako jedna instrukcja (lista z jednym elementem), żeby Django nie dzielił go
po średnikach – funkcje PL/pgSQL zawierają średniki w blokach $$…$$.
Pliki są zamrożoną częścią tej migracji: zmiany specyfikacji wprowadza się kolejnymi migracjami.
"""

from pathlib import Path

from django.db import migrations

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"


def _read(name):
    return (SQL_DIR / name).read_text(encoding="utf-8")


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0034_user_mfa"),  # auth.has_mfa() czyta public.user_totp
    ]

    operations = [
        migrations.RunSQL(
            sql=[_read("0001_portal_auth.sql"), _read("0002_aed.sql")],
            reverse_sql=["DROP SCHEMA IF EXISTS audit, aed, org, auth CASCADE"],
        ),
    ]
