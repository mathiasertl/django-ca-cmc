"""Views for django-ca-cmc."""

import asn1crypto.cms
import asn1crypto.x509
from cryptography.exceptions import InvalidSignature
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views import View
from python_cmc import cmc

from django_ca_cmc.cmc import check_request_signature

CONTENT_TYPE = "application/pkcs7-mime"


class MyView(View):
    def handle_request(self, data: bytes) -> bytes:
        """Handle and extract CMS CMC request"""
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
            for _, value in enumerate(cmc_req["reqSequence"]):
                if isinstance(value.chosen, cmc.CertReqMsg):  # CRMF
                    req_id = int(value.chosen["certReq"]["certReqId"].native)
                    crmf_csr = create_csr_from_crmf(value.chosen["certReq"]["certTemplate"])
                    created_certs[req_id] = await create_cert_from_csr(crmf_csr)

                elif isinstance(value.chosen, cmc.TaggedCertificationRequest):  # CSR
                    req_id = int(value.chosen["bodyPartID"].native)
                    created_certs[req_id] = await create_cert_from_csr(
                        value.chosen["certificationRequest"]
                    )

                elif isinstance(value.chosen, cmc.ORM):  # ORM
                    print("ERROR: CMC request type is ORM, cannot handle this")
                    raise BadRequest("Cannot process CMC type ORM")

            ret = await create_cmc_response(cmc_req["controlSequence"], created_certs, failed=False)
        except (ValueError, TypeError):
            ret = await create_cmc_response(cmc_req["controlSequence"], created_certs, failed=True)

        return ret

    def post(self, request: HttpRequest) -> HttpResponse:  # noqa: D102
        content_type = request.headers.get("Content-type")
        if content_type is None or content_type != CONTENT_TYPE:
            return HttpResponseBadRequest(b"0", content_type=CONTENT_TYPE)

        try:
            data_content = self.handle_request(request.body)
        except InvalidSignature as ex:
            return HttpResponseForbidden(str(ex), content_type=CONTENT_TYPE)
        except (ValueError, TypeError):
            return HttpResponseBadRequest("0", content_type=CONTENT_TYPE)

        return HttpResponse(data_content, content_type=CONTENT_TYPE)
