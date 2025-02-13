# django-ca-cmc

A plugin for [django-ca](https://django-ca.readthedocs.io/) implementing a subset of
[RFC 5272 - Certificate Management over CMS (CMC)](https://www.rfc-editor.org/rfc/rfc5272).

The CMC parts of the code are based on [SUNET/pkcs11_ca](https://github.com/SUNET/pkcs11_ca).

## Current deployment scenario

At present, you need both django-ca-cmc and django-ca checked out, to build the necessary images.
This is at present pretty convoluted (primarily because we require a release of django-ca first),
but will get better soon:

### Initial setup

Follow the [Docker Compose quickstart guide]
(https://django-ca.readthedocs.io/en/latest/quickstart/docker_compose.html).

If you do not want to enable TLS:

* Skip generating DH parameters.
* Don't set `NGINX_*` variables in `.env`.

#### Configuration file

Nothing special required.

#### Add `compose.yaml`

Get it from [this branch](https://github.com/mathiasertl/django-ca/tree/feature/eu-0001-cmc-support).

#### Add `compose.override.yaml`

Nothing special is needed (everything is included in the Docker image).

#### Add `.env` file

**Important:** You need to set

```
DJANGO_CA_VERSION=cmc
```

### CMC setup

Add a CMC client certificate:

```
cat client.pem | docker compose exec -T frontend manage cmc_add_client -
```

You can access CMC for any CA at `/cmc/<serial>/` (get serials with `manage list_cas`). To enable the 
`/cmc01` endpoint you need to tell it which CA to use by serial: Add the  `CA_DEFAULT_CMC_SERIAL` to
`localsettings.yaml` and update your setup. 

Verify setup (a GET request will simply confirm that you reach the right endpoint):

```
curl http://localhost/cmc01
```

## Settings

CA_CMC_COPY_CSR_EXTENSIONS (default: `[]`)
: List of extensions that will be copied from the CSR, if present, as dotted string OID. For
: example:
:
: ```python
: CA_CMC_COPY_CSR_EXTENSIONS = ["2.5.29.32"]
: ```

CA_CMC_DIGEST_ALGORITHM (default: `"sha256"`)
: Algorithm used for message digest generation. Valid values are any SHA2 or SHA3 algorithms from the
: [hashlib](https://docs.python.org/3/library/hashlib.html) module (e.g. `"sha3_256"`)

## Open questions

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
* [RFC 5272: Certificate Management over CMS (CMC)](https://www.rfc-editor.org/rfc/rfc5272)
* [RFC 5753: (ECC) Algorithms in Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5753.html)
* [RFC 7773: Authentication Context Certificate Extension](https://www.rfc-editor.org/rfc/rfc7773.html)