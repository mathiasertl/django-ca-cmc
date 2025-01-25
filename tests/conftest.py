"""
pytest configuration and fixtures.

.. seealso:: https://docs.pytest.org/en/stable/reference/fixtures.html
"""

from datetime import UTC, datetime, timedelta

import pytest
from _pytest.fixtures import SubRequest
from cryptography import x509
from django_ca.key_backends import key_backends
from django_ca.key_backends.db.models import DBCreatePrivateKeyOptions
from django_ca.models import CertificateAuthority

from django_ca_cmc.models import CMCClient


@pytest.fixture
def ca(request: "SubRequest") -> CertificateAuthority:
    """Create a new (RSA-based) root CA."""
    request.getfixturevalue("db")
    key_backend_options = DBCreatePrivateKeyOptions(key_type="RSA", key_size=1024)
    not_after = datetime.now(UTC) + timedelta(days=365)
    return CertificateAuthority.objects.init(
        "ca",
        key_backends["default"],
        key_backend_options,
        subject=x509.Name([]),
        not_after=not_after,
    )


@pytest.fixture
def pre_created_client(ca: CertificateAuthority) -> CMCClient:
    """Create CMCClient with certificate for pre-created requests."""
    client = CMCClient()
    cert = x509.load_pem_x509_certificate(b"""-----BEGIN CERTIFICATE-----
MIIBJDCByqADAgECAgRhfDUqMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD1Rlc3Qg
Q01DIENsaWVudDAeFw0yMTEwMjkxNzUzNDZaFw0yNjEwMjkxNzUzNDZaMBoxGDAW
BgNVBAMMD1Rlc3QgQ01DIENsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BJuWGZFY9U8KD8RsIALCJYElSH4GgI6/nY6L5RTPGdYl5xzF2yYKRlFQBNVbB359
HBmaVuhuKbTkLiKsTTy0qRMwCgYIKoZIzj0EAwIDSQAwRgIhAIitbkx60TsqHZbH
k9ko+ojFQ3XWJ0zTaKGQcfglrTU/AiEAjJs3LuO1F6GxDjgpLVVp+u750rVCwsUJ
zIqw8k4ytIY=
-----END CERTIFICATE-----""")

    client.update_certificate(cert)
    client.save()
    return client
