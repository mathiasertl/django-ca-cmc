"""App configuration for django-ca-cmc."""

from django.apps import AppConfig


class DjangoCaCmcConfig(AppConfig):
    """Main Django app config."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_ca_cmc"
