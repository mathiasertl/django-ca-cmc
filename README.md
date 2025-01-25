## Open questions

* Can URLs change?
* Should CMC client certs be tied to one or more CAs?
* Minimum required Python version
* Data in CSR is currently kept, which is normally considered dangerous:
  * extensions are added from CSR
  * valid_after is hardcoded to three years, it seems

## Noted improvements over existing solution

* Client certificate management via CLI/admin interface.
* Client certificate expiration taken into account.
* CMC certificate chain now includes full bundle (first FIXME in create_cmc_response)
* RSA keys: Decoupling of key length and signature algorithm