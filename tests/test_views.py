"""Full view tests for django_ca_cmc."""

from http import HTTPStatus

import pytest
from django.test import Client
from django.urls import reverse
from django_ca.models import CertificateAuthority

from tests.utils import load_file


@pytest.mark.parametrize("filename", ["cmc_with_crmf", "cmc_with_csr"])
@pytest.mark.usefixtures("pre_created_client")
def test_pre_created_requests(client: Client, ca: CertificateAuthority, filename: str) -> None:
    """Test valid, pre-created request payloads."""
    decoded = load_file(filename)
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.OK, response.content


@pytest.mark.usefixtures("pre_created_client")
def test_pre_created_request_with_invalid_signature(
    client: Client, ca: CertificateAuthority
) -> None:
    """Test pre-created request with an invalid signature."""
    decoded = load_file("cmc_with_invalid_signature")
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": ca.serial})
    response = client.post(url_path, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.content == b"invalid signature"


def test_invalid_content_type(client: Client, ca: CertificateAuthority) -> None:
    """Test sending an invalid content type."""
    url_path = reverse("django_ca_cmc:cmc", kwargs={"serial": ca.serial})
    response = client.post(url_path, data=b"", content_type="text/plain")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content == b"invalid content type"
