"""
pytest configuration and fixtures.

.. seealso:: https://docs.pytest.org/en/stable/reference/fixtures.html
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from _pytest.fixtures import SubRequest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import NameOID
from django_ca.key_backends.db.models import DBStorePrivateKeyOptions
from django_ca.models import CertificateAuthority
from django_ca.typehints import AllowedHashTypes

from django_ca_cmc.models import CMCClient

RSA_KEY_SIZES = (2048, 4096)
RSA_ALGORITHMS = (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
ELLIPTIC_CURVES = [ec.SECP521R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECT571K1()]


def _sign(
    private_key: CertificateIssuerPrivateKeyTypes,
    common_name: str,
    algorithm: AllowedHashTypes | None = None,
) -> x509.Certificate:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    now = datetime.now(UTC)
    serial = x509.random_serial_number()
    public_key = private_key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10))
        # Add necessary extensions:
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
    )

    return builder.sign(private_key, algorithm)


def _ca(
    name: str, private_key: CertificateIssuerPrivateKeyTypes, certificate: x509.Certificate
) -> CertificateAuthority:
    ca = CertificateAuthority(
        name=name, key_backend_alias="default", ocsp_key_backend_alias="default"
    )
    ca.key_backend.store_private_key(ca, private_key, certificate, DBStorePrivateKeyOptions())
    ca.update_certificate(certificate)
    ca.save()
    return ca


def generate_ec_private_key_fixture(
    elliptic_curve: ec.EllipticCurve,
) -> Callable[[], ec.EllipticCurvePrivateKey]:
    """Function to generate a fixture for an elliptic curve private key."""

    @pytest.fixture(scope="session")
    def func() -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(elliptic_curve)

    return func


def generate_ec_certificate_fixture(
    curve: ec.EllipticCurve,
) -> Callable[["SubRequest"], x509.Certificate]:
    """Function to generate a fixture for an elliptic curve certificate."""

    @pytest.fixture(scope="session")
    def func(request: "SubRequest") -> x509.Certificate:
        private_key = request.getfixturevalue(f"ec_private_key_{curve.name}")
        return _sign(private_key, f"ec_{curve.name}", hashes.SHA256())

    return func


def generate_rsa_private_key_fixture(key_size: int) -> Callable[[], rsa.RSAPrivateKey]:
    """Function to generate a fixture for an RSA private key."""

    @pytest.fixture(scope="session")
    def func() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    return func


def generate_rsa_certificate_fixture(
    key_size: int, algorithm: AllowedHashTypes
) -> Callable[[SubRequest], x509.Certificate]:
    """Function to generate a fixture for an RSA certificate."""

    @pytest.fixture(scope="session")
    def func(request: "SubRequest") -> x509.Certificate:
        private_key = request.getfixturevalue(f"rsa_private_key_{key_size}")
        return _sign(private_key, f"rsa_{key_size}", algorithm)

    return func


def generate_ca_fixture(
    name: str, private_key_name: str, certificate_name: str
) -> Callable[[SubRequest], CertificateAuthority]:
    """Function to generate a CA fixture."""

    @pytest.fixture
    def func(request: "SubRequest") -> CertificateAuthority:
        """Fixture for RSA-based certificate authorities."""
        request.getfixturevalue("db")
        private_key: ec.EllipticCurvePrivateKey = request.getfixturevalue(private_key_name)
        certificate: x509.Certificate = request.getfixturevalue(certificate_name)

        # Some sanity checks that private key/certificate match
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            ec_public_key = cast(ec.EllipticCurvePublicKey, certificate.public_key())
            assert isinstance(ec_public_key, ec.EllipticCurvePublicKey)
            assert private_key.curve == ec_public_key.curve
            assert private_key.key_size == ec_public_key.key_size
        elif isinstance(private_key, rsa.RSAPrivateKey):
            rsa_public_key = cast(rsa.RSAPublicKey, certificate.public_key())
            assert isinstance(rsa_public_key, rsa.RSAPublicKey)
            assert private_key.key_size == rsa_public_key.key_size

        return _ca(name, private_key, certificate)

    return func


@pytest.fixture(scope="session")
def dsa_private_key() -> dsa.DSAPrivateKey:
    """Session fixture for a DSA private key."""
    return dsa.generate_private_key(key_size=1024)


@pytest.fixture(scope="session")
def dsa_certificate(dsa_private_key: dsa.DSAPrivateKey) -> x509.Certificate:
    """Session fixture for a signed certificate of a DSA CA."""
    return _sign(dsa_private_key, "dsa", hashes.SHA256())


@pytest.fixture(scope="session")
def ed448_private_key() -> ed448.Ed448PrivateKey:
    """Session fixture for an Ed448 private key."""
    return ed448.Ed448PrivateKey.generate()


@pytest.fixture(scope="session")
def ed448_certificate(ed448_private_key: ed448.Ed448PrivateKey) -> x509.Certificate:
    """Session fixture for a signed certificate of an Ed448 CA."""
    return _sign(ed448_private_key, "ed448")


@pytest.fixture
def ed448_ca(
    request: "SubRequest",
    ed448_private_key: ed448.Ed448PrivateKey,
    ed448_certificate: x509.Certificate,
) -> CertificateAuthority:
    """Fixture for an Ed448 CA."""
    request.getfixturevalue("db")
    return _ca("ed448", ed448_private_key, ed448_certificate)


@pytest.fixture(scope="session")
def ed25519_private_key() -> ed25519.Ed25519PrivateKey:
    """Session fixture for an Ed25519 private key."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def ed25519_certificate(ed25519_private_key: ed25519.Ed25519PrivateKey) -> x509.Certificate:
    """Session fixture for a signed certificate of an Ed25519 CA."""
    return _sign(ed25519_private_key, "ed25519")


@pytest.fixture
def ed25519_ca(
    request: "SubRequest",
    ed25519_private_key: ed25519.Ed25519PrivateKey,
    ed25519_certificate: x509.Certificate,
) -> CertificateAuthority:
    """Fixture for an Ed25519 CA."""
    request.getfixturevalue("db")
    return _ca("ed25519", ed25519_private_key, ed25519_certificate)


for _curve in ELLIPTIC_CURVES:
    globals()[f"ec_private_key_{_curve.name}"] = generate_ec_private_key_fixture(_curve)
    globals()[f"ec_certificate_{_curve.name}"] = generate_ec_certificate_fixture(_curve)
    globals()[f"ec_{_curve.name}_ca"] = generate_ca_fixture(
        f"ec_{_curve.name}", f"ec_private_key_{_curve.name}", f"ec_certificate_{_curve.name}"
    )
for _key_size in RSA_KEY_SIZES:
    globals()[f"rsa_private_key_{_key_size}"] = generate_rsa_private_key_fixture(_key_size)
    for _algorithm in RSA_ALGORITHMS:
        globals()[f"rsa_certificate_{_key_size}_{_algorithm.name}"] = (
            generate_rsa_certificate_fixture(_key_size, _algorithm)
        )
        globals()[f"rsa_{_key_size}_{_algorithm.name}_ca"] = generate_ca_fixture(
            f"rsa_{_key_size}_{_algorithm.name}",
            f"rsa_private_key_{_key_size}",
            f"rsa_certificate_{_key_size}_{_algorithm.name}",
        )


@pytest.fixture(params=[f"ec_{curve.name}_ca" for curve in ELLIPTIC_CURVES])
def ec_ca(request: "SubRequest") -> CertificateAuthority:
    """Fixture for all elliptic curve-based CAs."""
    ca = request.getfixturevalue(request.param)
    assert isinstance(ca, CertificateAuthority)
    return ca


@pytest.fixture(
    params=[
        f"rsa_{key_size}_{algorithm.name}_ca"
        for key_size in RSA_KEY_SIZES
        for algorithm in RSA_ALGORITHMS
    ]
    + [f"ec_{curve.name}_ca" for curve in ELLIPTIC_CURVES]
    + ["ed448_ca", "ed25519_ca"]
)
def ca(request: "SubRequest") -> CertificateAuthority:
    """Fixture for all RSA, elliptic curve, Ed448 and Ed25519 based CAs."""
    ca = request.getfixturevalue(request.param)
    assert isinstance(ca, CertificateAuthority)
    return ca


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
