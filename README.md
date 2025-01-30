## Open questions

* Can URLs change?
* Should CMC client certs be tied to one or more CAs?
* Minimum required Python version
* Data in CSR is currently kept, which is normally considered dangerous:
  * extensions are added from CSR
  * valid_after is hardcoded to three years, it seems
* https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/cmc.py#L177
  --> failed is True if an exception was raised. Is this maybe the opposite of what you would want?

## Noted improvements over existing solution

* Client certificate management via CLI/admin interface.
* Client certificate expiration taken into account.
* CMC certificate chain now includes full bundle (first FIXME in create_cmc_response)
* RSA keys: Decoupling of key length and signature algorithm