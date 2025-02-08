"""CMC-related functions."""

import logging
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime

import asn1crypto.algos
import asn1crypto.keys
import asn1crypto.pem
import asn1crypto.x509
from asn1crypto import cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from django.conf import settings
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from python_cmc import cmc

from django_ca_cmc.constants import SUPPORTED_PUBLIC_KEY_TYPES
from django_ca_cmc.hash import digest
from django_ca_cmc.models import CMCClient
from django_ca_cmc.utils import get_signed_digest_algorithm

log = logging.getLogger(__name__)


def _public_key_verify_ecdsa_signature(
    pub_key: ec.EllipticCurvePublicKey, signature: bytes, signed_data: bytes
) -> None:
    # NOTE: We removed convert_rs_ec_signature conversion here. The signature comes from the
    #   sender and hopefully does not really still require conversion. If signature verification
    #   fails, we might have to re-add this.
    if pub_key.curve.name == "secp256r1":
        pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    elif pub_key.curve.name == "secp384r1":
        pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA384()))
    elif pub_key.curve.name == "secp521r1":
        pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA512()))
    else:
        raise ValueError("Unsupported EC curve")


def verify_signature(
    public_key: CertificateIssuerPublicKeyTypes, signature: bytes, signed_data: bytes
) -> None:
    """
    Verify signature with a public key.

    raises cryptography.exceptions.InvalidSignature
    if invalid signature or ValueError if the public key is not supported.

    Potentially fails if the signature is made using nonstandard hashing of the data.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA512())

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        _public_key_verify_ecdsa_signature(public_key, signature, signed_data)

    elif isinstance(public_key, (ed25519.Ed25519PublicKey | ed448.Ed448PublicKey)):
        public_key.verify(signature, signed_data)

    else:
        raise ValueError("Non supported public key in certificate")


def check_request_signature(
    request_signers: cms.CertificateSet, signer_infos: cms.SignerInfos
) -> None:
    """Check a CMC request signature."""
    now = datetime.now(tz=UTC)
    if settings.USE_TZ is False:
        now = now.replace(tzinfo=None)

    clients = CMCClient.objects.filter(not_before__lt=now, not_after__gt=now)

    for request_signer in request_signers:
        for client in clients:
            cert = asn1crypto.x509.Certificate.load(client.certificate.der)
            if request_signer.chosen.native == cert.native:
                for signer_info in signer_infos:
                    signer_cert = x509.load_der_x509_certificate(request_signer.chosen.dump())
                    public_key = signer_cert.public_key()
                    if not isinstance(public_key, SUPPORTED_PUBLIC_KEY_TYPES):
                        raise ValueError(
                            f"{public_key}: Client passed an unsupported public signer key."
                        )

                    signature = signer_info["signature"].contents
                    signed_data = signer_info["signed_attrs"].retag(17).dump()
                    try:
                        verify_signature(public_key, signature, signed_data)
                        return
                    except (InvalidSignature, ValueError, TypeError):
                        pass

    raise InvalidSignature("Wrong or missing CMS signer")


# FIXME This need to be improved to fully support crmf, not just basics
def create_csr_from_crmf(
    certificate_request_message: cmc.CertReqMsg,
) -> x509.CertificateSigningRequest:
    """Manually handle the CRMF request into a CSR."""
    attrs = asn1crypto.csr.CRIAttributes()

    cert_req_info = asn1crypto.csr.CertificationRequestInfo()
    cert_req_info["version"] = 0
    cert_req_info["subject"] = certificate_request_message["subject"]
    cert_req_info["subject_pk_info"] = certificate_request_message["publicKey"]

    set_of_exts = asn1crypto.csr.SetOfExtensions()

    set_of_exts.append(certificate_request_message["extensions"])
    cri_attr = asn1crypto.csr.CRIAttribute(
        {"type": asn1crypto.csr.CSRAttributeType("1.2.840.113549.1.9.14"), "values": set_of_exts}
    )
    attrs.append(cri_attr)

    cert_req_info["attributes"] = attrs

    asn1crypto_certification_request = asn1crypto.csr.CertificationRequest()
    asn1crypto_certification_request["certification_request_info"] = cert_req_info
    asn1crypto_certification_request["signature_algorithm"] = (
        asn1crypto.algos.SignedDigestAlgorithm(
            {"algorithm": asn1crypto.algos.SignedDigestAlgorithmId("1.2.840.10045.4.3.2")}
        )
    )
    asn1crypto_certification_request["signature"] = b"dummy_sig"

    # Convert CSR to cryptography and return.
    return x509.load_der_x509_csr(asn1crypto_certification_request.dump())


def create_cert_from_csr(
    ca: CertificateAuthority, csr: x509.CertificateSigningRequest
) -> Certificate:
    """Create cert from a csr."""
    key_backend_options = ca.key_backend.get_use_private_key_options(ca, {})
    return Certificate.objects.create_cert(ca, key_backend_options, csr, subject=csr.subject)


def cmc_revoke(revoke_data: bytes) -> None:
    """Revoke a certificate based on the CMC RevokeRequest."""
    # set_of_revoke_request = cmc.SetOfRevokeRequest.load(revoke_data)
    # revoked_certs = 0
    #
    # for revoke_request in set_of_revoke_request:
    #     # Try certs
    #     db_certificate_objs = await db_load_data_class(
    #         Certificate, CertificateInput(
    #           serial_number=str(revoke_request["serial_number"].native)
    #         )
    #     )
    #     for obj in db_certificate_objs:
    #         if isinstance(obj, Certificate):
    #             if (
    #                 pem_cert_to_name_dict(await obj.issuer_pem())
    #                 == revoke_request["issuerName"].native
    #             ):
    #                 await obj.revoke(
    #                     1, int(revoke_request["reason"])
    #                 )  # Change to cmc request signer
    #                 revoked_certs += 1
    #                 print("Revoked cert due to CMC request")
    #
    #     # Try Ca's
    #     db_ca_objs = await db_load_data_class(
    #         Ca, CaInput(serial_number=str(revoke_request["serial_number"].native))
    #     )
    #     for obj in db_ca_objs:
    #         if isinstance(obj, Ca):
    #             if (
    #                 pem_cert_to_name_dict(await obj.issuer_pem())
    #                 == revoke_request["issuerName"].native
    #             ):
    #                 await obj.revoke(
    #                     1, int(revoke_request["reason"])
    #                 )  # Change to cmc request signer
    #                 revoked_certs += 1
    #                 print("Revoked cert due to CMC request")
    #
    # if revoked_certs == 0:
    #     print("Could not find the certificate to revoke from CMC RevokeRequest")
    #     raise ValueError


def _create_cmc_response_status_packet(
    created_certs: dict[int, asn1crypto.x509.Certificate], failed: bool
) -> cmc.TaggedAttribute:
    body_part_references = cmc.BodyPartReferences()

    for req_id in created_certs:
        body_part_references.append(cmc.BodyPartReference({"bodyPartID": req_id}))

    status_v2 = cmc.CMCStatusInfoV2()
    if len(body_part_references) == 0:
        status_v2["bodyList"] = cmc.BodyPartReferences([])
    else:
        status_v2["bodyList"] = body_part_references

    if failed:
        status_v2["cMCStatus"] = cmc.CMCStatus(2)
        status_v2["statusString"] = "Failed processing CMC request"
        status_v2["otherInfo"] = cmc.OtherStatusInfo({"failInfo": cmc.CMCFailInfo(11)})
    else:
        status_v2["cMCStatus"] = cmc.CMCStatus(0)
        status_v2["statusString"] = "OK"

    status_v2_attr_values = cmc.SetOfCMCStatusInfoV2()
    status_v2_attr_values.append(status_v2)
    status_v2_attr = cmc.TaggedAttribute()
    status_v2_attr["bodyPartID"] = secrets.randbelow(4294967293)
    status_v2_attr["attrType"] = cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.25")
    status_v2_attr["attrValues"] = status_v2_attr_values
    return status_v2_attr


def create_cmc_response_packet(
    controls: cmc.Controls, created_certs: dict[int, asn1crypto.x509.Certificate], failed: bool
) -> cmc.PKIResponse:
    """
    Create a CMC response package.

    Revoke cert(s) if the request had a RevokeRequest(s).
    """
    response_controls = cmc.Controls()
    nonce: bytes | None = None
    reg_info: bytes | None = None

    for control_value in controls:
        if control_value["attrType"].native == "id-cmc-senderNonce":
            nonce = control_value["attrValues"].dump()

        if control_value["attrType"].native == "id-cmc-regInfo":
            reg_info = control_value["attrValues"].dump()

    # If a revoke request
    if not failed:
        for control_value in controls:
            if control_value["attrType"].native == "id-cmc-revokeRequest":
                revoke_request = control_value["attrValues"].dump()
                cmc_revoke(revoke_request)

    if nonce is not None:
        nonce_attr = cmc.TaggedAttribute()
        nonce_attr["bodyPartID"] = secrets.randbelow(4294967293)
        nonce_attr["attrType"] = cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.7")
        nonce_attr["attrValues"] = asn1crypto.cms.SetOfOctetString.load(nonce)
        response_controls.append(nonce_attr)

    if reg_info is not None:
        reg_info_attr = cmc.TaggedAttribute()
        reg_info_attr["bodyPartID"] = secrets.randbelow(4294967293)
        reg_info_attr["attrType"] = cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.19")
        reg_info_attr["attrValues"] = asn1crypto.cms.SetOfOctetString.load(reg_info)
        response_controls.append(reg_info_attr)

    status_v2_attr = _create_cmc_response_status_packet(created_certs, failed)
    response_controls.append(status_v2_attr)

    pki_response = cmc.PKIResponse()
    pki_response["controlSequence"] = response_controls
    pki_response["cmsSequence"] = cmc.TaggedContentInfos([])
    pki_response["otherMsgSequence"] = cmc.OtherMsgs([])
    return pki_response


def pem_cert_to_key_hash(certificate: x509.Certificate) -> bytes:
    """Get digest of the SubjectKeyIdentifier extension of the given certificate."""
    try:
        ext: x509.Extension[x509.SubjectKeyIdentifier] = (
            certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        )
    except x509.ExtensionNotFound as ex:
        raise ValueError("No SubjectKeyIdentifier extension in certificate.") from ex

    return ext.value.digest


def create_cmc_response(  # pylint: disable-msg=too-many-locals
    ca: CertificateAuthority,
    controls: cmc.Controls,
    created_certs: dict[int, Certificate],
    failed: bool,
) -> bytes:
    """Create a CMS response containing a CMC package."""
    # Add CA bundle and created certificates to the chain.
    model_chain: Sequence[X509CertMixin] = ca.bundle + list(created_certs.values())

    # Get digest and signature algorithms
    digest_algorithm_name = getattr(settings, "CA_CMC_DIGEST_ALGORITHM", "sha256")
    digest_algorithm = asn1crypto.algos.DigestAlgorithm(
        {"algorithm": asn1crypto.algos.DigestAlgorithmId(digest_algorithm_name)}
    )
    signature_algorithm = get_signed_digest_algorithm(ca.pub.loaded)

    # Convert chain to asn1crypto options
    chain: list[asn1crypto.x509.Certificate] = [
        asn1crypto.x509.Certificate.load(c.pub.der) for c in model_chain
    ]

    packet = create_cmc_response_packet(controls, created_certs, failed)

    eci = asn1crypto.cms.EncapsulatedContentInfo()
    eci["content_type"] = asn1crypto.cms.ContentType("1.3.6.1.5.5.7.12.3")
    packet_data = asn1crypto.core.ParsableOctetString()
    packet_data.set(packet.dump())
    eci["content"] = packet_data

    signed_data = asn1crypto.cms.SignedData()
    signed_data["version"] = 2
    signed_data["digest_algorithms"] = asn1crypto.cms.DigestAlgorithms({digest_algorithm})
    signed_data["encap_content_info"] = eci

    signer_info = asn1crypto.cms.SignerInfo()
    signer_info["version"] = 1
    signer_info["sid"] = asn1crypto.cms.SignerIdentifier(
        {"subject_key_identifier": pem_cert_to_key_hash(ca.pub.loaded)}
    )

    cms_attributes = asn1crypto.cms.CMSAttributes()
    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("content_type"),
                "values": asn1crypto.cms.SetOfContentType(
                    [asn1crypto.cms.ContentType("1.3.6.1.5.5.7.12.3")]
                ),
            }
        )
    )

    # Calculate message digest
    message_digest = digest.hash(
        signed_data["encap_content_info"]["content"].contents, digest_algorithm
    )

    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("message_digest"),
                "values": asn1crypto.cms.SetOfOctetString([message_digest]),
            }
        )
    )

    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("signing_time"),
                "values": asn1crypto.cms.SetOfTime([asn1crypto.core.UTCTime(datetime.now(UTC))]),
            }
        )
    )

    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("cms_algorithm_protection"),
                "values": asn1crypto.cms.SetOfCMSAlgorithmProtection(
                    [
                        asn1crypto.cms.CMSAlgorithmProtection(
                            {
                                "digest_algorithm": digest_algorithm,
                                "signature_algorithm": signature_algorithm,
                            }
                        )
                    ]
                ),
            }
        )
    )

    signer_info["signed_attrs"] = cms_attributes

    signer_info["digest_algorithm"] = digest_algorithm
    signer_info["signature_algorithm"] = signature_algorithm

    # Sign the data
    raw_data = signer_info["signed_attrs"].retag(17).dump()

    sign_kwargs = {}
    if ca.key_type == "RSA":
        sign_kwargs["padding"] = PKCS1v15()
    raw_signature = ca.sign_data(raw_data, **sign_kwargs)

    signer_info["signature"] = raw_signature

    signed_data["signer_infos"] = asn1crypto.cms.SignerInfos({signer_info})
    signed_data["certificates"] = asn1crypto.cms.CertificateSet(chain)

    cmc_resp = asn1crypto.cms.ContentInfo()
    cmc_resp["content_type"] = asn1crypto.cms.ContentType("signed_data")
    cmc_resp["content"] = signed_data

    ret: bytes = cmc_resp.dump()
    return ret
