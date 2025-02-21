"""TEst the cmc_add_client command."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import resources
from io import StringIO
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from django.core.management import CommandError, call_command

from django_ca_cmc.models import CMCClient
from tests import files
from tests.conftest import CMC_CLIENT_ONE_PEM

cmc_client_1_path = resources.files(files) / "cmc_client_1.pem"
serial = "617C352A"


@contextmanager
def stdin_bytes(value: bytes) -> Iterator[None]:
    """Mock stdin bytes."""

    # mock https://docs.python.org/3/library/io.html#io.BufferedReader.read
    def _read_mock(size=None):  # type: ignore # pylint: disable=unused-argument
        return value

    with mock.patch("sys.stdin.buffer.read", side_effect=_read_mock):
        yield


@pytest.mark.django_db
def test_with_path_with_pem() -> None:
    """Test passing a path to a PEM."""
    stdout = StringIO()
    call_command("cmc_add_client", cmc_client_1_path, stdout=stdout)
    assert stdout.getvalue() == f"Client with serial {serial} added successfully.\n"

    client = CMCClient.objects.get()
    assert client.certificate.pem.strip() == CMC_CLIENT_ONE_PEM.decode()
    assert client.serial == serial
    assert client.not_after == datetime(2026, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.not_before == datetime(2021, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.comment == ""


@pytest.mark.django_db
def test_with_stdin_with_pem() -> None:
    """Test passing a path to a PEM."""
    stdout = StringIO()
    with stdin_bytes(CMC_CLIENT_ONE_PEM):
        call_command("cmc_add_client", "-", stdout=stdout)
    assert stdout.getvalue() == f"Client with serial {serial} added successfully.\n"

    client = CMCClient.objects.get()
    assert client.certificate.pem.strip() == CMC_CLIENT_ONE_PEM.decode()
    assert client.serial == serial
    assert client.not_after == datetime(2026, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.not_before == datetime(2021, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.comment == ""


@pytest.mark.django_db
def test_with_stdin_with_der() -> None:
    """Test passing a path to a DER."""
    loaded_certificate = x509.load_pem_x509_certificate(CMC_CLIENT_ONE_PEM)
    cmc_client_der = loaded_certificate.public_bytes(Encoding.DER)

    stdout = StringIO()
    with stdin_bytes(cmc_client_der):
        call_command("cmc_add_client", "-", stdout=stdout)
    assert stdout.getvalue() == f"Client with serial {serial} added successfully.\n"

    client = CMCClient.objects.get()
    assert client.certificate.pem.strip() == CMC_CLIENT_ONE_PEM.decode()
    assert client.serial == serial
    assert client.not_after == datetime(2026, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.not_before == datetime(2021, 10, 29, 17, 53, 46, tzinfo=UTC)
    assert client.comment == ""


def test_with_path_does_not_exist() -> None:
    """Test passing a path that does not exist."""
    with pytest.raises(CommandError, match=r"^/does/not/exist: File does not exist\.$"):
        call_command("cmc_add_client", "/does/not/exist")


def test_with_invalid_data() -> None:
    """Test passing a path that does not exist."""
    with pytest.raises(CommandError, match=r"^Cannot parse certificate\.$"):
        call_command("cmc_add_client", __file__)
