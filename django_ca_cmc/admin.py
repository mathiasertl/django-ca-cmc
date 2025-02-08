"""Admin for django-ca-cmc."""

from typing import TYPE_CHECKING, ClassVar

# Register your models here.
from django.contrib import admin

from django_ca_cmc.models import CMCClient

if TYPE_CHECKING:
    CMCClientAdminBase = admin.ModelAdmin[CMCClient]
else:
    CMCClientAdminBase = admin.ModelAdmin


@admin.register(CMCClient)
class CMCClientAdmin(CMCClientAdminBase):
    """Model admin class for CMC client."""

    list_display = ("serial", "not_before", "not_after")
    readonly_fields = ("not_after", "not_before", "serial")

    class Media:
        css: ClassVar[dict[str, tuple[str, ...]]] = {
            "all": ("django_ca/admin/css/base.css",),
        }
