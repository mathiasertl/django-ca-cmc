"""Full view tests for django_ca_cmc."""

from http import HTTPStatus

import asn1crypto.cms
import asn1crypto.x509
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID, NameOID
from django.test import Client
from django.urls import reverse
from django_ca.models import Certificate, CertificateAuthority

from django_ca_cmc.models import CMCClient
from tests.utils import create_cmc_request, create_tagged_csr_message, load_file


@pytest.mark.usefixtures("pre_created_client")
def test_pre_created_csr(client: Client, ca: CertificateAuthority) -> None:
    """Test valid, pre-created request payloads."""
    public_key = ca.pub.loaded.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
        public_key.curve, ec.SECT571K1
    ):
        pytest.xfail("This curve is known to not be supported at the moment.")

    assert ca.certificate_set.all().count() == 0  # just assert initial state

    decoded = load_file("cmc_with_csr")
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.OK, response.content

    certificate: Certificate = ca.certificate_set.get()

    info = asn1crypto.cms.ContentInfo.load(response.content)

    # Check content type
    content_type = info["content_type"]
    assert isinstance(content_type, asn1crypto.cms.ContentType)
    assert content_type.dotted == "1.2.840.113549.1.7.2"  # signed_data

    # Check content
    content = info["content"]
    assert isinstance(content, asn1crypto.cms.SignedData)
    assert content.native["version"] == "v2"

    # Check certificates in the response
    certificates = [cert.chosen for cert in content["certificates"]]
    assert isinstance(content["certificates"], asn1crypto.cms.CertificateSet)
    assert all(isinstance(cert, asn1crypto.x509.Certificate) for cert in certificates)
    assert set(cert.dump() for cert in certificates) == set([ca.pub.der, certificate.pub.der])

    signer_infos = content["signer_infos"]
    assert isinstance(signer_infos, asn1crypto.cms.SignerInfos)
    assert len(signer_infos) == 1

    signer_info = signer_infos[0]
    signature = signer_info["signature"].contents
    signed_data = signer_info["signed_attrs"].retag(17).dump()

    # Verify signature
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm = ca.algorithm
        assert algorithm is not None  # just to make mypy happy
        public_key.verify(signature, signed_data, algorithm=algorithm, padding=PKCS1v15())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA512()))
    elif isinstance(public_key, ed448.Ed448PublicKey | ed25519.Ed25519PublicKey):
        public_key.verify(signature, signed_data)
    else:
        raise ValueError("New key type?")


@pytest.mark.usefixtures("pre_created_client")
def test_pre_created_crmf(client: Client, rsa_2048_sha256_ca: CertificateAuthority) -> None:
    """Test valid, pre-created request payloads."""
    decoded = load_file("cmc_with_crmf")
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": rsa_2048_sha256_ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.OK, response.content


def test_with_copied_extensions(
    cmc_client_private_key: ec.EllipticCurvePrivateKey,
    cmc_client: CMCClient,
    client: Client,
    rsa_private_key_2048: rsa.RSAPrivateKey,
    rsa_2048_sha256_ca: CertificateAuthority,
) -> None:
    """Test copying extensions."""
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(CertificatePoliciesOID.ANY_POLICY, None)]
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(oid=x509.ObjectIdentifier("1.2.3"), value=b"123"),
            critical=False,
        )
        # This extension is blacklisted and will not be copied.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )
    csr = csr_builder.sign(rsa_private_key_2048, hashes.SHA256())

    cmc_client.copy_extensions = True
    cmc_client.save()

    tcr = create_tagged_csr_message(csr)
    decoded = create_cmc_request(cmc_client_private_key, cmc_client.certificate.loaded, tcr)

    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": rsa_2048_sha256_ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.OK, response.content

    cert: Certificate = Certificate.objects.get()

    # CertificatePolicies is copied
    assert cert.extensions[ExtensionOID.CERTIFICATE_POLICIES] == x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES,
        critical=False,
        value=x509.CertificatePolicies(
            [x509.PolicyInformation(CertificatePoliciesOID.ANY_POLICY, None)]
        ),
    )

    # UnrecognizedExtension is also copied
    assert cert.extensions[x509.ObjectIdentifier("1.2.3")] == x509.Extension(
        critical=False,
        oid=x509.ObjectIdentifier("1.2.3"),
        value=x509.UnrecognizedExtension(oid=x509.ObjectIdentifier("1.2.3"), value=b"123"),
    )

    # BasicConstraints is in the blacklist, so it's not copied
    assert cert.extensions[ExtensionOID.BASIC_CONSTRAINTS] == x509.Extension(
        critical=True,
        oid=ExtensionOID.BASIC_CONSTRAINTS,
        value=x509.BasicConstraints(ca=False, path_length=None),
    )


@pytest.mark.usefixtures("pre_created_client")
def test_pre_created_request_with_invalid_signature(
    client: Client, rsa_2048_sha256_ca: CertificateAuthority
) -> None:
    """Test pre-created request with an invalid signature."""
    decoded = load_file("cmc_with_invalid_signature")
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": rsa_2048_sha256_ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.content == b"invalid signature"


def test_invalid_content_type(client: Client, rsa_2048_sha256_ca: CertificateAuthority) -> None:
    """Test sending an invalid content type."""
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": rsa_2048_sha256_ca.serial})
    response = client.post(url_path, data=b"", content_type="text/plain")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content == b"invalid content type"
