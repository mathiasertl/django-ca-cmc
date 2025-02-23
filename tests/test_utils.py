"""Test utility functions."""

from unittest.mock import PropertyMock, patch

import asn1crypto.cms
import freezegun
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from python_cmc import cmc

from django_ca_cmc.utils import get_signed_digest_algorithm
from tests.utils import create_cmc_request, create_tagged_csr_message, load_file


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


def test_create_tagged_csr_message(rsa_private_key_2048: rsa.RSAPrivateKey) -> None:
    """Test create_tagged_csr_message()."""
    expected_msg = asn1crypto.cms.ContentInfo.load(load_file("cmc_with_csr"))
    raw_cmc_request = expected_msg["content"]["encap_content_info"]["content"].parsed.dump()
    expected = cmc.PKIData.load(raw_cmc_request)

    # Get CSR from expected request
    csr = x509.load_der_x509_csr(expected["reqSequence"][0].chosen["certificationRequest"].dump())

    actual = cmc.PKIData.load(create_tagged_csr_message(csr))
    assert expected.native == actual.native


def test_create_cmc_request(
    cmc_client_private_key: ec.EllipticCurvePrivateKey,
    cmc_client_public_key: x509.Certificate,
) -> None:
    """Test the create_cmc_request function."""
    expected_msg = asn1crypto.cms.ContentInfo.load(load_file("cmc_with_csr"))
    data = expected_msg["content"]["encap_content_info"]["content"].native

    with freezegun.freeze_time("2023-1-30 22:18:43"):
        actual_msg = asn1crypto.cms.ContentInfo.load(
            create_cmc_request(cmc_client_private_key, cmc_client_public_key, data)
        )

    # Just ensure that data is generally valid
    _ = expected_msg.native
    _ = actual_msg.native

    # Verify content type
    assert actual_msg["content_type"] == expected_msg["content_type"]

    # Retrieve content
    expected = expected_msg["content"]
    actual = actual_msg["content"]
    assert isinstance(expected, asn1crypto.cms.SignedData)
    assert isinstance(actual, asn1crypto.cms.SignedData)

    # Assert basic properties of ContentInfo
    assert actual["version"] == expected["version"]
    assert actual["digest_algorithms"].native == expected["digest_algorithms"].native
    assert isinstance(actual["certificates"], type(expected["certificates"]))
    assert isinstance(actual["certificates"][0], type(expected["certificates"][0]))
    assert isinstance(actual["signer_infos"], type(expected["signer_infos"]))
    assert isinstance(actual["signer_infos"][0], type(expected["signer_infos"][0]))

    # Check the encapsulated content info
    actual_encap_content_info = actual["encap_content_info"]
    expected_encap_content_info = expected["encap_content_info"]
    assert isinstance(actual_encap_content_info, asn1crypto.cms.EncapsulatedContentInfo)
    assert isinstance(expected_encap_content_info, asn1crypto.cms.EncapsulatedContentInfo)
    assert actual_encap_content_info["content_type"] == expected_encap_content_info["content_type"]
    print(expected_encap_content_info["content"].native)
    assert (
        actual_encap_content_info["content"].native == expected_encap_content_info["content"].native
    )

    # Check signer_info
    assert len(actual["signer_infos"]) == len(expected["signer_infos"]) == 1
    actual_signer_info = actual["signer_infos"][0]
    expected_signer_info = expected["signer_infos"][0]
    assert isinstance(actual_signer_info, asn1crypto.cms.SignerInfo)
    assert isinstance(expected_signer_info, asn1crypto.cms.SignerInfo)

    assert actual_signer_info["version"].native == expected_signer_info["version"].native
    assert (
        actual_signer_info["digest_algorithm"].native
        == expected_signer_info["digest_algorithm"].native
    )
    assert (
        actual_signer_info["signature_algorithm"].native
        == expected_signer_info["signature_algorithm"].native
    )
    assert isinstance(actual_signer_info["signature"].native, bytes)
    assert isinstance(actual_signer_info["sid"], asn1crypto.cms.SignerIdentifier)

    # verify signer infos
    assert actual_signer_info["signed_attrs"].native == expected_signer_info["signed_attrs"].native
