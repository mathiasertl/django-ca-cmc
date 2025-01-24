from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from _pytest.fixtures import SubRequest
from cryptography import x509
from django_ca.key_backends import key_backends
from django_ca.key_backends.db.models import DBCreatePrivateKeyOptions
from django_ca.models import CertificateAuthority


@pytest.fixture
def ca(request: "SubRequest") -> CertificateAuthority:
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
