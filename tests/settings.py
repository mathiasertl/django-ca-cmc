"""Django settings for unit tests."""

from cryptography.x509.oid import ExtensionOID

SECRET_KEY = "dummy"
ROOT_URLCONF = "tests.urls"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django_ca",
    "django_ca_cmc",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

CA_MIN_KEY_SIZE = 1024
CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.db.DBBackend",
    },
}

CA_CMC_COPY_CSR_EXTENSIONS = (ExtensionOID.CERTIFICATE_POLICIES.dotted_string,)
