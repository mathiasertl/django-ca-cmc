"""Settings for django-ca-cmc."""

from typing import Annotated, Any

from cryptography import x509
from django_ca.conf import SettingsProxyBase
from django_ca.pydantic.type_aliases import Serial
from pydantic import BaseModel, BeforeValidator, ConfigDict


def oid_validator(value: Any) -> Any:
    """Convert OID strings to x509.ObjectIdentifier."""
    print(value, type(value))
    if isinstance(value, str):
        return x509.ObjectIdentifier(value)
    return value


class CMCModelSettings(BaseModel):
    """CMC settings."""

    model_config = ConfigDict(arbitrary_types_allowed=True, from_attributes=True, frozen=True)

    CA_CMC_COPY_CSR_EXTENSIONS: tuple[
        Annotated[x509.ObjectIdentifier, BeforeValidator(oid_validator)], ...
    ] = ()
    CA_CMC_DEFAULT_SERIAL: Serial | None = None
    CA_CMC_DEFAULT_RESPONDER_SERIAL: Serial | None = None


class CMCSettingsProxy(SettingsProxyBase[CMCModelSettings]):
    """Proxy class to access model settings."""

    settings_model = CMCModelSettings
    __settings: CMCModelSettings


cmc_settings = CMCSettingsProxy()
