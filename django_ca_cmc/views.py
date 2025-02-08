"""Views for django-ca-cmc."""

import logging

import asn1crypto.cms
import asn1crypto.x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from django.conf import settings
from django.core.exceptions import BadRequest, ImproperlyConfigured, PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django_ca.models import CertificateAuthority
from python_cmc import cmc

from django_ca_cmc.cmc import (
    check_request_signature,
    create_cert_from_csr,
    create_cmc_response,
    create_csr_from_crmf,
)

log = logging.getLogger(__name__)
CONTENT_TYPE = "application/pkcs7-mime"


@method_decorator(csrf_exempt, name="dispatch")
class CMCView(View):
    """View handling CMC requests."""

    serial: str | None = None

    def handle_request(self, ca: CertificateAuthority, data: bytes) -> bytes:
        """Handle and extract CMS CMC request."""
        created_certs: dict[int, asn1crypto.x509.Certificate] = {}

        content_info = asn1crypto.cms.ContentInfo.load(data)
        _ = content_info.native  # Ensure valid data
        content = content_info["content"]

        # Ensure valid signature for the request
        if len(content["signer_infos"]) == 0 or len(content["certificates"]) == 0:
            raise PermissionDenied("Invalid signature or certificate for the signature")
        check_request_signature(content["certificates"], content["signer_infos"])

        raw_cmc_request = content["encap_content_info"]["content"].parsed.dump()
        cmc_req = cmc.PKIData.load(raw_cmc_request)
        _ = cmc_req.native  # Ensure valid data

        cmc_requests = [req.chosen for req in cmc_req["reqSequence"]]

        # Make sure that all sub-requests are supported
        if unsupported := [
            _
            for _ in cmc_requests
            if not isinstance(_, cmc.CertReqMsg | cmc.TaggedCertificationRequest)
        ]:
            log.error("CMC requests of unknown type: %s", unsupported)
            raise BadRequest("CMC requests of unknown type.")

        try:
            for value in cmc_requests:
                if isinstance(value, cmc.CertReqMsg):  # CRMF
                    req_id = int(value["certReq"]["certReqId"].native)
                    csr = create_csr_from_crmf(value["certReq"]["certTemplate"])
                    created_certs[req_id] = create_cert_from_csr(ca, csr)

                elif isinstance(value, cmc.TaggedCertificationRequest):  # CSR
                    req_id = int(value["bodyPartID"].native)
                    csr = x509.load_der_x509_csr(value["certificationRequest"].dump())
                else:  # pragma: no cover  # must not happen, types asserted outside of loop
                    raise ValueError("Unsupported message type")

                created_certs[req_id] = create_cert_from_csr(ca, csr)

            ret = create_cmc_response(ca, cmc_req["controlSequence"], created_certs, failed=False)
        except (ValueError, TypeError):
            ret = create_cmc_response(ca, cmc_req["controlSequence"], created_certs, failed=True)

        return ret

    def get(self, request: HttpRequest, serial: str | None = None) -> HttpResponse:
        return HttpResponse("CMC endpoint here!")

    def post(self, request: HttpRequest, serial: str | None = None) -> HttpResponse:
        content_type = request.headers.get("Content-type")
        if content_type is None or content_type != CONTENT_TYPE:
            return HttpResponseBadRequest("invalid content type", content_type=CONTENT_TYPE)

        if serial is None:
            serial = self.serial
        if serial is None:
            serial = settings.CA_DEFAULT_CMC_SERIAL
        if serial is None:
            # If it's still None, we cannot determine the serial.
            raise ImproperlyConfigured("No serial configured for this view.")

        certificate_authority = CertificateAuthority.objects.usable().get(serial=serial)

        try:
            data_content = self.handle_request(certificate_authority, request.body)
        except InvalidSignature:
            return HttpResponseForbidden("invalid signature", content_type=CONTENT_TYPE)
        except Exception as ex:
            log.exception("Internal error: %s", ex)
            return HttpResponseBadRequest("internal error", content_type=CONTENT_TYPE)

        return HttpResponse(data_content, content_type=CONTENT_TYPE)
