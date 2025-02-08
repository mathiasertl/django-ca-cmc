"""Admin for django-ca-cmc."""

from typing import ClassVar

# Register your models here.
from django.contrib import admin

from django_ca_cmc.models import CMCClient


@admin.register(CMCClient)
class CMCClientAdmin(admin.ModelAdmin):
    """Model admin class for CMC client."""

    list_display = ("serial", "not_before", "not_after")
    readonly_fields = ("not_after", "not_before", "serial")

    class Media:
        css: ClassVar[dict[str, tuple[str, ...]]] = {
            "all": ("django_ca/admin/css/base.css",),
        }
