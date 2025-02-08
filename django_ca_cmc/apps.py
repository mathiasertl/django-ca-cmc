"""App configuration for django-ca-cmc."""

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DjangoCaCmcConfig(AppConfig):
    """Main Django app config."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_ca_cmc"
    verbose_name = _("Certificate Authority: CMC")
