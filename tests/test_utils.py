"""Test utility functions."""

from unittest.mock import PropertyMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from django_ca_cmc.utils import get_signed_digest_algorithm


def test_get_signed_digest_algorithm_with_rsa_with_unsupported_hash_algorithm(
    rsa_certificate_2048_sha256: x509.Certificate,
) -> None:
    """Test unsupported hash algorithm."""
    mock = PropertyMock(return_value=hashes.SHA3_256())
    error = r"^sha3-256: Signature hash algorithm not supported\.$"
    with patch("cryptography.x509.Certificate.signature_hash_algorithm", new_callable=mock):
        with pytest.raises(ValueError, match=error):
            get_signed_digest_algorithm(rsa_certificate_2048_sha256)


def test_get_signed_digest_algorithm_with_ec_with_unsupported_curve(
    ec_certificate_sect571k1: x509.Certificate,
) -> None:
    """Test unsupported curve."""
    with pytest.raises(ValueError, match=r"^sect571k1: Elliptic curve not supported\.$"):
        get_signed_digest_algorithm(ec_certificate_sect571k1)


def test_get_signed_digest_algorithm_with_unsupported_object() -> None:
    """Test unsupported object."""
    error = r"None: Must be of type cryptography\.x509\.Certificate\.$"
    with pytest.raises(TypeError, match=error):
        get_signed_digest_algorithm(None)  # type: ignore[arg-type]  # What we're testing.


def test_get_signed_digest_algorithm_with_unsopported_public_key_type(
    dsa_certificate: x509.Certificate,
) -> None:
    """Test unsupported public key type (DSA)."""
    with pytest.raises(ValueError, match=r"Public key type not supported\.$"):
        get_signed_digest_algorithm(dsa_certificate)
