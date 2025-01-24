import asn1crypto.pem
import asn1crypto.x509
from asn1crypto import cms
from cryptography.exceptions import InvalidSignature


def check_request_signature(
    request_signers: cms.CertificateSet, signer_infos: cms.SignerInfos
) -> None:
    for request_signer in request_signers:
        for valid_cert in CMC_REQUEST_CERTS:
            _, _, valid_cert_pem = asn1crypto.pem.unarmor(valid_cert.encode("UTF-8"))
            if (
                request_signer.chosen.native
                == asn1crypto.x509.Certificate.load(valid_cert_pem).native
            ):
                for signer_info in signer_infos:
                    signer_cert: bytes = pem.armor("CERTIFICATE", request_signer.chosen.dump())
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
