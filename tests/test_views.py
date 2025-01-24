"""Full view tests for django_ca_cmc."""

from http import HTTPStatus

import pytest
from django.test import Client
from django.urls import reverse

from tests.utils import load_file

URL_PATH = reverse("django_ca_cmc:cmc")


@pytest.mark.parametrize("filename", ["cmc_with_crmf", "cmc_with_csr"])
def test_with_pre_created_requests(client: Client, filename: str) -> None:
    """Test valid, pre-created request payloads."""
    decoded = load_file(filename)
    response = client.post(URL_PATH, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.OK, response.content


def test_with_pre_created_requests_with_invalid_signature(client: Client) -> None:
    """Test pre-created request with an invalid signature."""
    decoded = load_file("cmc_with_invalid_signature")
    response = client.post(URL_PATH, data=decoded, content_type="application/pkcs7-mime")
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.content == b"invalid signature"


def test_with_invalid_content_type(client: Client) -> None:
    """Test sending an invalid content type."""
    response = client.post(URL_PATH, data=b"", content_type="text/plain")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content == b"invalid content type"
