"""Utility functions for unit tests."""

import hashlib
from datetime import UTC, datetime
from importlib import resources

import asn1crypto.cms
import asn1crypto.csr
import asn1crypto.util
import asn1crypto.x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from python_cmc import cmc

from tests import files


def load_file(path: str) -> bytes:
    """Utility function to load a file from ``tests.files``."""
    full_path = resources.files(files) / path
    with full_path.open("rb") as stream:
        return stream.read()


def create_tagged_csr_message(csr: x509.CertificateSigningRequest) -> bytes:
    """Create a tagged CSR message for use in a CMC request."""
    encoded_csr = csr.public_bytes(Encoding.DER)

    tcr = cmc.TaggedCertificationRequest()
    tcr["bodyPartID"] = 1185658366
    tcr["certificationRequest"] = asn1crypto.csr.CertificationRequest.load(encoded_csr)
    tagged_request = cmc.TaggedRequest(name="tcr", value=tcr)

    controls = cmc.Controls()
    controls.append(
        asn1crypto.util.OrderedDict(
            {
                "bodyPartID": 340570457,
                "attrType": "id-cmc-senderNonce",
                "attrValues": [
                    b'S\xc3f\xa5O/\x15\xb6\xfe\x07"\x04\xfe\xba\xf2\x94H\xf4\x04\xac\xedv\x96\x95'
                    b"\xe7Y\xcf\xcc]T\xe0d\x80\x9a\xd8\x87\xdejb\xb1\xef.\x90\xda\x96#O\x90\xb4Z"
                    b"\xec~\xb2\xad\xc4Z\xcb\xb5\xbe\n\x8c\x9a\xa8\xcd\x04\xf01Y\xa4\xf0\ng\x03>"
                    b"\xa5\x97\xa9\x1f\x95\x15\x07\x84\x9bF\x90\x12\xb0\x15+&\x80F\xeb\x17xX\x17"
                    b"\x04l\xf6\xf2\xc4\xca\x89\\\xb4\xf2\x0b#v{\xdd_@\x15\xfe\x99\x11\xf10o\xb9"
                    b"\xf2\r\xf8`\x89\x91"
                ],
            }
        )
    )
    controls.append(
        asn1crypto.util.OrderedDict(
            {"bodyPartID": 937138838, "attrType": "id-cmc-regInfo", "attrValues": [b"pkcs10"]}
        ),
    )

    pki_data = cmc.PKIData()
    pki_data["reqSequence"] = cmc.TaggedRequests([tagged_request])
    pki_data["controlSequence"] = controls
    pki_data["cmsSequence"] = []
    pki_data["otherMsgSequence"] = []

    return pki_data.dump()  # type: ignore[no-any-return]


def create_cmc_request(
    private_key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate, data: bytes
) -> bytes:
    """Create a signed CMC request with the given data."""
    certificate_der = certificate.public_bytes(Encoding.DER)
    asn1crypto_certificate = asn1crypto.x509.Certificate.load(certificate_der)

    # Start creating SignedData instance (equals content_info['content'])
    signed_data = asn1crypto.cms.SignedData()
    signed_data["version"] = asn1crypto.cms.CMSVersion("v3")  # tested
    signed_data["encap_content_info"] = asn1crypto.util.OrderedDict(
        [("content_type", "1.3.6.1.5.5.7.12.2"), ("content", data)]
    )
    signed_data["digest_algorithms"] = [  # tested
        asn1crypto.util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])
    ]
    signed_data["certificates"] = asn1crypto.cms.CertificateSet([asn1crypto_certificate])

    # Setting signer info section
    signer_info = asn1crypto.cms.SignerInfo()
    signer_info["version"] = "v1"  # tested
    signer_info["digest_algorithm"] = asn1crypto.util.OrderedDict(  # tested
        [("algorithm", "sha256"), ("parameters", None)]
    )
    signer_info["signature_algorithm"] = asn1crypto.util.OrderedDict(  # tested
        [("algorithm", "sha256_ecdsa"), ("parameters", None)]
    )

    # Finding subject_key_identifier from certificate (asn1crypto.x509 object)
    key_id = asn1crypto_certificate.key_identifier_value.native
    signer_info["sid"] = asn1crypto.cms.SignerIdentifier({"subject_key_identifier": key_id})

    # Adding CMS attributes to singer_infos
    cms_attributes = asn1crypto.cms.CMSAttributes()
    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("content_type"),
                "values": asn1crypto.cms.SetOfContentType(
                    [asn1crypto.cms.ContentType("1.3.6.1.5.5.7.12.2")]
                ),
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
                                "digest_algorithm": asn1crypto.util.OrderedDict(  # tested
                                    [("algorithm", "sha256"), ("parameters", None)]
                                ),
                                "signature_algorithm": asn1crypto.util.OrderedDict(  # tested
                                    [("algorithm", "sha256_ecdsa"), ("parameters", None)]
                                ),
                            }
                        )
                    ]
                ),
            }
        )
    )

    # compute and set message digest
    message_digest = hashlib.sha256(signed_data["encap_content_info"]["content"].contents).digest()
    cms_attributes.append(
        asn1crypto.cms.CMSAttribute(
            {
                "type": asn1crypto.cms.CMSAttributeType("message_digest"),
                "values": asn1crypto.cms.SetOfOctetString([message_digest]),
            }
        )
    )
    signer_info["signed_attrs"] = cms_attributes

    # Creating a signature using a private key object from pkcs11
    sign_data = signer_info["signed_attrs"].retag(17).dump()
    signer_info["signature"] = private_key.sign(sign_data, ec.ECDSA(hashes.SHA256()))

    # Add signer infos to signed data
    signed_data["signer_infos"] = asn1crypto.cms.SignerInfos({signer_info})

    # Create top-level ContentInfo object.
    content_info = asn1crypto.cms.ContentInfo()
    content_info["content_type"] = "signed_data"  # NOTE: must be BEFORE content
    content_info["content"] = signed_data

    return content_info.dump()  # type: ignore[no-any-return]
