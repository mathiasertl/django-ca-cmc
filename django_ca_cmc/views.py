"""Views for django-ca-cmc."""

import logging

import asn1crypto.cms
import asn1crypto.x509
from cryptography.exceptions import InvalidSignature
from django.conf import settings
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views import View
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


class CMCView(View):
    """View handling CMC requests."""

    def handle_request(self, certificate_authority: CertificateAuthority, data: bytes) -> bytes:
        """Handle and extract CMS CMC request."""
        created_certs: dict[int, asn1crypto.x509.Certificate] = {}

        content_info = asn1crypto.cms.ContentInfo.load(data)
        _ = content_info.native  # Ensure valid data

        # Ensure valid signature for the request
        if (
            len(content_info["content"]["signer_infos"]) == 0
            or len(content_info["content"]["certificates"]) == 0
        ):
            raise PermissionDenied("Invalid signature or certificate for the signature")
        check_request_signature(
            content_info["content"]["certificates"], content_info["content"]["signer_infos"]
        )

        raw_cmc_request = content_info["content"]["encap_content_info"]["content"].parsed.dump()
        cmc_req = cmc.PKIData.load(raw_cmc_request)
        _ = cmc_req.native  # Ensure valid data

        try:
            for value in cmc_req["reqSequence"]:
                if isinstance(value.chosen, cmc.CertReqMsg):  # CRMF
                    req_id = int(value.chosen["certReq"]["certReqId"].native)
                    crmf_csr = create_csr_from_crmf(value.chosen["certReq"]["certTemplate"])
                    created_certs[req_id] = create_cert_from_csr(crmf_csr)

                elif isinstance(value.chosen, cmc.TaggedCertificationRequest):  # CSR
                    req_id = int(value.chosen["bodyPartID"].native)
                    created_certs[req_id] = create_cert_from_csr(
                        value.chosen["certificationRequest"]
                    )

                else:
                    log.error("CMC request type of unknown type: %s", value.chosen)
                    raise BadRequest("CMC request of unknown type.")

            ret = create_cmc_response(cmc_req["controlSequence"], created_certs, failed=False)
        except (ValueError, TypeError):
            ret = create_cmc_response(cmc_req["controlSequence"], created_certs, failed=True)

        return ret

    def post(self, request: HttpRequest, serial: str | None) -> HttpResponse:  # noqa: D102
        content_type = request.headers.get("Content-type")
        if content_type is None or content_type != CONTENT_TYPE:
            return HttpResponseBadRequest("invalid content type", content_type=CONTENT_TYPE)

        if serial is None:
            serial = settings.CMC_DEFAULT_CA

        certificate_authority = CertificateAuthority.objects.usable().get(serial=serial)

        try:
            data_content = self.handle_request(certificate_authority, request.body)
        except InvalidSignature:
            return HttpResponseForbidden("invalid signature", content_type=CONTENT_TYPE)
        except (ValueError, TypeError):
            return HttpResponseBadRequest("internal error", content_type=CONTENT_TYPE)

        return HttpResponse(data_content, content_type=CONTENT_TYPE)
