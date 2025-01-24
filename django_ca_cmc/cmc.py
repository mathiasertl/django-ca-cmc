import hashlib
import secrets
from datetime import UTC, datetime, timezone
from typing import Union

import asn1crypto.algos
import asn1crypto.keys
import asn1crypto.pem
import asn1crypto.x509
from asn1crypto import cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from django.conf import settings
from python_cmc import cmc

ASN1_INTEGER_CODE = 2
ASN1_INIT = 48
ASN1_SECP521R1_CODE = 129


def convert_rs_ec_signature(signature: bytes, key_type: str) -> bytes:
    """
    Convert an R&S ECDSA signature into the default ASN1 format.

    https://stackoverflow.com/questions/66101825/asn-1-structure-of-ecdsa-signature-in-x-509-certificate

    Parameters
    ----------
    signature (bytes): The signature.
    key_type (str): Key type.

    Returns
    -------
    bytes

    """
    if key_type not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"key_type must be in {['secp256r1', 'secp384r1', 'secp521r1']}")

    if key_type in ["secp521r1"]:
        asn1_init = [ASN1_INIT, ASN1_SECP521R1_CODE]
    else:
        asn1_init = [ASN1_INIT]

    r_length = int(len(signature) / 2)
    s_length = int(len(signature) / 2)

    # Get R and S bytes
    r_data = signature[:r_length]
    s_data = signature[r_length:]

    # Remove leading zeros, since integers cant start with a 0
    while r_data[0] == 0:
        r_data = r_data[1:]
        r_length -= 1
    while s_data[0] == 0:
        s_data = s_data[1:]
        s_length -= 1

    # Ensure the integers are positive numbers
    if r_data[0] >= 128:
        r_data = bytearray([0]) + r_data[:]
        r_length += 1
    if s_data[0] >= 128:
        s_data = bytearray([0]) + s_data[:]
        s_length += 1

    return bytes(
        bytearray(asn1_init)
        + bytearray([r_length + s_length + 4])
        + bytearray([ASN1_INTEGER_CODE, r_length])
        + r_data
        + bytearray([ASN1_INTEGER_CODE, s_length])
        + s_data
    )


def _public_key_verify_ecdsa_signature(
    pub_key: ec.EllipticCurvePublicKey, signature: bytes, signed_data: bytes
) -> None:
    if pub_key.curve.name == "secp256r1":
        try:
            pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            converted_signature = convert_rs_ec_signature(signature, "secp256r1")
            pub_key.verify(converted_signature, signed_data, ec.ECDSA(hashes.SHA256()))
    elif pub_key.curve.name == "secp384r1":
        try:
            pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            converted_signature = convert_rs_ec_signature(signature, "secp384r1")
            pub_key.verify(converted_signature, signed_data, ec.ECDSA(hashes.SHA384()))
    elif pub_key.curve.name == "secp521r1":
        try:
            pub_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA512()))
        except InvalidSignature:
            converted_signature = convert_rs_ec_signature(signature, "secp521r1")
            pub_key.verify(converted_signature, signed_data, ec.ECDSA(hashes.SHA512()))
    else:
        raise ValueError("Unsupported EC curve")


def public_key_verify_signature(  # pylint: disable=too-many-branches
    public_key_info_pem: str, signature: bytes, signed_data: bytes
) -> None:
    """
    Verify signature with a public key
    raises cryptography.exceptions.InvalidSignature
    if invalid signature or ValueError if the public key is not supported.

    Potentially fails if the signature is made using nonstandard hashing of the data.

    Parameters
    ----------
    public_key_info_pem (str): Public key in info in PEM form

    """
    data = public_key_info_pem.encode("utf-8")
    if asn1crypto.pem.detect(data):
        _, _, data = asn1crypto.pem.unarmor(data)

    pub_key_asn1 = asn1crypto.keys.PublicKeyInfo.load(data)

    pub_key = load_der_public_key(pub_key_asn1.dump())

    if isinstance(pub_key, rsa.RSAPublicKey):
        try:
            pub_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            pub_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA512())

    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        _public_key_verify_ecdsa_signature(pub_key, signature, signed_data)

    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pub_key.verify(signature, signed_data)

    else:
        raise ValueError("Non supported public key in certificate")


def pem_cert_verify_signature(pem: str, signature: bytes, signed_data: bytes) -> None:
    """
    Verify signature done by the certificates private key
    raises cryptography.exceptions.InvalidSignature
    if invalid signature or ValueError if the public key is not supported.

    Potentially fails if the signature is made using nonstandard hashing of the data.

    Parameters
    ----------
    pem (str): PEM input data.
    signature (bytes): The signature.
    signed_data (bytes): The signed data.

    """
    data = pem.encode("utf-8")
    if asn1crypto.pem.detect(data):
        _, _, data = asn1crypto.pem.unarmor(data)

    cert = asn1crypto.x509.Certificate().load(data)
    pub_key_info_pem: bytes = asn1crypto.pem.armor(
        "PUBLIC KEY", cert["tbs_certificate"]["subject_public_key_info"].dump()
    )
    return public_key_verify_signature(pub_key_info_pem.decode("utf-8"), signature, signed_data)


def check_request_signature(
    request_signers: cms.CertificateSet, signer_infos: cms.SignerInfos
) -> None:
    for request_signer in request_signers:
        for valid_cert in settings.CMC_REQUEST_CERTS:
            _, _, valid_cert_pem = asn1crypto.pem.unarmor(valid_cert.encode("UTF-8"))
            if (
                request_signer.chosen.native
                == asn1crypto.x509.Certificate.load(valid_cert_pem).native
            ):
                for signer_info in signer_infos:
                    signer_cert: bytes = asn1crypto.pem.armor(
                        "CERTIFICATE", request_signer.chosen.dump()
                    )
                    try:
                        pem_cert_verify_signature(
                            signer_cert.decode("utf-8"),
                            signer_info["signature"].contents,
                            signer_info["signed_attrs"].retag(17).dump(),
                        )
                        return
                    except (InvalidSignature, ValueError, TypeError):
                        pass

    raise InvalidSignature("Wrong or missing CMS signer")


# FIXME This need to be improved to fully support crmf, not just basics
def create_csr_from_crmf(cert_req: cmc.CertReqMsg) -> asn1crypto.csr.CertificationRequest:
    """
    Manually handle the CRMF request into a CSR
    since we use CSR as data type in the database and currently all certs have a csr which the are created from
    """
    attrs = asn1crypto.csr.CRIAttributes()

    cert_req_info = asn1crypto.csr.CertificationRequestInfo()
    cert_req_info["version"] = 0
    cert_req_info["subject"] = cert_req["subject"]
    cert_req_info["subject_pk_info"] = cert_req["publicKey"]

    set_of_exts = asn1crypto.csr.SetOfExtensions()

    set_of_exts.append(cert_req["extensions"])
    cri_attr = asn1crypto.csr.CRIAttribute(
        {"type": asn1crypto.csr.CSRAttributeType("1.2.840.113549.1.9.14"), "values": set_of_exts}
    )
    attrs.append(cri_attr)

    cert_req_info["attributes"] = attrs

    cert_req = asn1crypto.csr.CertificationRequest()
    cert_req["certification_request_info"] = cert_req_info
    cert_req["signature_algorithm"] = asn1crypto.algos.SignedDigestAlgorithm(
        {"algorithm": asn1crypto.algos.SignedDigestAlgorithmId("1.2.840.10045.4.3.2")}
    )
    cert_req["signature"] = b"dummy_sig"
    return cert_req


def create_cert_from_csr(
    csr_data: asn1crypto.csr.CertificationRequest,
) -> asn1crypto.x509.Certificate:
    """Create cert from a csr"""
    # issuer_pkcs11_key = await pkcs11_key_request(
    #     Pkcs11KeyInput(key_label=CMC_CERT_ISSUING_KEY_LABEL)
    # )
    # issuer = await ca_request(CaInput(pkcs11_key=issuer_pkcs11_key.serial))
    #
    # csr_pem: bytes = asn1crypto.pem.armor("CERTIFICATE REQUEST", csr_data.dump())
    #
    # extra_extensions = aia_and_cdp_exts(issuer.path)
    #
    # signed_cert = await sign_csr(
    #     CMC_CERT_ISSUING_KEY_LABEL,
    #     CMC_CERT_ISSUING_NAME_DICT,
    #     csr_pem.decode("utf-8"),
    #     extra_extensions=extra_extensions,
    #     ignore_auth_exts=True,
    #     key_type="secp256r1",
    # )
    #
    # # Get public key from csr
    # public_key_obj = PublicKey(
    #     {"pem": public_key_pem_from_csr(csr_pem.decode("utf-8")), "authorized_by": 1}
    # )  # FIXME
    # await public_key_obj.save()
    #
    # # Save csr
    # csr_internal_obj = Csr(
    #     {"pem": csr_pem.decode("utf-8"), "authorized_by": 1, "public_key": public_key_obj.serial}
    # )  # FIXME
    # await csr_internal_obj.save()
    #
    # # Save cert
    # cert_obj = Certificate(
    #     {
    #         "pem": signed_cert,
    #         "authorized_by": 1,  # FIXME
    #         "csr": csr_internal_obj.serial,
    #         "serial_number": str(cert_pem_serial_number(signed_cert)),
    #         "public_key": public_key_obj.serial,
    #         "issuer": issuer.serial,
    #     }
    # )
    # await cert_obj.save()
    # if cert_is_ca(signed_cert):
    #     print("Warning: Treating CA as a certificate since we dont have the private key")
    #
    # return asn1crypto.x509.Certificate.load(asn1crypto.pem.unarmor(signed_cert.encode("utf-8"))[2])


def cmc_revoke(revoke_data: bytes) -> None:
    """Revoke a certificate based on the CMC RevokeRequest"""
    # set_of_revoke_request = cmc.SetOfRevokeRequest.load(revoke_data)
    # revoked_certs = 0
    #
    # for revoke_request in set_of_revoke_request:
    #     # Try certs
    #     db_certificate_objs = await db_load_data_class(
    #         Certificate, CertificateInput(serial_number=str(revoke_request["serial_number"].native))
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

    for _, control_value in enumerate(controls):
        if control_value["attrType"].native == "id-cmc-senderNonce":
            nonce = control_value["attrValues"].dump()

    for _, control_value in enumerate(controls):
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


def create_cmc_response(  # pylint: disable-msg=too-many-locals
    controls: cmc.Controls,
    created_certs: dict[int, asn1crypto.x509.Certificate],
    failed: bool,
) -> bytes:
    """Create a CMS response containing a CMC package"""
    # signer_pkcs11_key = pkcs11_key_request(Pkcs11KeyInput(key_label=CMC_SIGNING_KEY_LABEL))
    # signer = ca_request(CaInput(pkcs11_key=signer_pkcs11_key.serial))
    #
    # # FIXME make this into a recursive chain instead of assuming next is root and
    # # Dont issue all certs are issued by the same issuer
    # chain: list[asn1crypto.x509.Certificate] = [
    #     asn1crypto.x509.Certificate.load(asn1crypto.pem.unarmor(signer.pem.encode("utf-8"))[2])
    # ]
    #
    # for req_id in created_certs:
    #     chain.append(created_certs[req_id])
    #
    # packet = create_cmc_response_packet(controls, created_certs, failed)
    #
    # eci = asn1crypto.cms.EncapsulatedContentInfo()
    # eci["content_type"] = asn1crypto.cms.ContentType("1.3.6.1.5.5.7.12.3")
    # packet_data = asn1crypto.core.ParsableOctetString()
    # packet_data.set(packet.dump())
    # eci["content"] = packet_data
    #
    # signed_data = asn1crypto.cms.SignedData()
    # signed_data["version"] = 2
    # signed_data["digest_algorithms"] = asn1crypto.cms.DigestAlgorithms(
    #     {
    #         asn1crypto.algos.DigestAlgorithm(
    #             {"algorithm": asn1crypto.algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
    #         )
    #     }
    # )
    # signed_data["encap_content_info"] = eci
    #
    # signer_info = asn1crypto.cms.SignerInfo()
    # signer_info["version"] = 1
    # signer_info["sid"] = asn1crypto.cms.SignerIdentifier(
    #     {"subject_key_identifier": pem_cert_to_key_hash(signer.pem)}
    # )
    #
    # cms_attributes = asn1crypto.cms.CMSAttributes()
    # cms_attributes.append(
    #     asn1crypto.cms.CMSAttribute(
    #         {
    #             "type": asn1crypto.cms.CMSAttributeType("1.2.840.113549.1.9.3"),
    #             "values": asn1crypto.cms.SetOfContentType(
    #                 [asn1crypto.cms.ContentType("1.3.6.1.5.5.7.12.3")]
    #             ),
    #         }
    #     )
    # )
    #
    # # The message digest
    # hash_module = hashlib.sha256()
    # hash_module.update(signed_data["encap_content_info"]["content"].contents)
    # digest = hash_module.digest()
    #
    # cms_attributes.append(
    #     asn1crypto.cms.CMSAttribute(
    #         {
    #             "type": asn1crypto.cms.CMSAttributeType("1.2.840.113549.1.9.4"),
    #             "values": asn1crypto.cms.SetOfOctetString([digest]),
    #         }
    #     )
    # )
    #
    # cms_attributes.append(
    #     asn1crypto.cms.CMSAttribute(
    #         {
    #             "type": asn1crypto.cms.CMSAttributeType("1.2.840.113549.1.9.5"),
    #             "values": asn1crypto.cms.SetOfTime([asn1crypto.core.UTCTime(datetime.now(UTC))]),
    #         }
    #     )
    # )
    #
    # cms_attributes.append(
    #     asn1crypto.cms.CMSAttribute(
    #         {
    #             "type": asn1crypto.cms.CMSAttributeType("1.2.840.113549.1.9.52"),
    #             "values": asn1crypto.cms.SetOfCMSAlgorithmProtection(
    #                 [
    #                     asn1crypto.cms.CMSAlgorithmProtection(
    #                         {
    #                             "digest_algorithm": asn1crypto.algos.DigestAlgorithm(
    #                                 {
    #                                     "algorithm": asn1crypto.algos.DigestAlgorithmId(
    #                                         "2.16.840.1.101.3.4.2.1"
    #                                     )
    #                                 }
    #                             ),
    #                             "signature_algorithm": signed_digest_algo(CMC_KEYS_TYPE),
    #                         }
    #                     )
    #                 ]
    #             ),
    #         }
    #     )
    # )
    #
    # signer_info["signed_attrs"] = cms_attributes
    #
    # signer_info["digest_algorithm"] = asn1crypto.algos.DigestAlgorithm(
    #     {"algorithm": asn1crypto.algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
    # )
    # signer_info["signature_algorithm"] = signed_digest_algo(CMC_KEYS_TYPE)
    # signer_info["signature"] = await PKCS11Session().sign(
    #     CMC_SIGNING_KEY_LABEL, signer_info["signed_attrs"].retag(17).dump(), key_type=CMC_KEYS_TYPE
    # )
    #
    # signed_data["signer_infos"] = asn1crypto.cms.SignerInfos({signer_info})
    # signed_data["certificates"] = asn1crypto.cms.CertificateSet(chain)
    #
    # cmc_resp = asn1crypto.cms.ContentInfo()
    # cmc_resp["content_type"] = asn1crypto.cms.ContentType("1.2.840.113549.1.7.2")
    # cmc_resp["content"] = signed_data
    #
    # ret: bytes = cmc_resp.dump()
    #
    # # print("cmc response for debugging")
    # # print(ret.hex())
    #
    # return ret
