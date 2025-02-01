# django-ca-cmc

A plugin for [django-ca](https://django-ca.readthedocs.io/) implementing a subset of
[RFC 5272 - Certificate Management over CMS (CMC)](https://www.rfc-editor.org/rfc/rfc5272).

The CMC parts of the code are based on [SUNET/pkcs11_ca](https://github.com/SUNET/pkcs11_ca).

## Open questions

* Can URL endpoints change (see `urls.py` for config, but can be changed at will)?
* Should CMC client certificates be tied to one or more CAs?
  (Currently, every client certificate works for every CA, as in the original implementation).
* Is there a minimum required Python version (Docker image is built with 3.13).
* Extensions from the CSR is currently copied to the certificate, which is considered dangerous.
  Trace of this claim:
  * [post_cmc() calls cmc_handle_request()](https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/main.py#L725):
    This is the FastAPI endpoint.
  * [cmc_handle_request() calls create_cert_from_csr()](https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/cmc.py#L397):
    This parses the raw request body.
  * [create_cert_from_csr() calls sign_csr()](https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/cmc.py#L86):
    `sign_csr()` creates a signed certificate. This function does **not** pass `keep_csr_extensions=False`.
  * [sign_csr() calls _request_to_tbs_certificate()](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py#L351)
    `keep_csr_extensions` has not been passed and is thus ``None``.
  * [_request_to_tbs_certificate()](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py#L65-L69)
    copies CSR extensions to `tbs`, which is the certificate.
  
  As an example, I see no reason why this code would not happily pass a `BasicConstraints` extension
  to signed certificate, potentially making it a Certificate Authority.
* `not_after` is hardcoded to three years
  ([source](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py#L159)).
  Current implementation is default CA_DEFAULT_EXPIRES, which is also the default for the admin
  interface, command line and REST API (but not ACMEv2).
* https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/cmc.py#L177
  --> failed is True if an exception was raised. Is this maybe the opposite of what you would want?
* convert_rs_ec_signature() -- are we sure this actually works? it seems to be somewhat
  changing the value, but unclear in what way. r & s values are different from what cryptograph
  produces
* digest_algorithm in response: upstream it's alwasy sha256 (via oid), but
  https://www.rfc-editor.org/rfc/rfc5753.html, section 2.1.1 says digest algorithm must match
  signatureAlgorithm, which depends on curve used.
* get_signed_digest_algorithm(): I cannot see actual relation between curve and hash documented 
  anywhere. Can we just use SHA-512? 

## Noted improvements/changes over existing solution

* Client certificate management via CLI/admin interface.
* Client certificate expiration taken into account.
* CMC certificate chain now includes full bundle (first FIXME in create_cmc_response)
* RSA keys: Decoupling of key length and signature algorithm

## Links

* [django-ca](https://django-ca.readthedocs.io/en/latest/)
* [SUNET/pkcs11_ca](https://github.com/SUNET/pkcs11_ca)
* [RFC 5272](https://www.rfc-editor.org/rfc/rfc5272)