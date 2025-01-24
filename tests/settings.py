"""Django settings for unit tests."""

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

CMC_REQUEST_CERTS = [
    """-----BEGIN CERTIFICATE-----
MIIBJDCByqADAgECAgRhfDUqMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD1Rlc3Qg
Q01DIENsaWVudDAeFw0yMTEwMjkxNzUzNDZaFw0yNjEwMjkxNzUzNDZaMBoxGDAW
BgNVBAMMD1Rlc3QgQ01DIENsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BJuWGZFY9U8KD8RsIALCJYElSH4GgI6/nY6L5RTPGdYl5xzF2yYKRlFQBNVbB359
HBmaVuhuKbTkLiKsTTy0qRMwCgYIKoZIzj0EAwIDSQAwRgIhAIitbkx60TsqHZbH
k9ko+ojFQ3XWJ0zTaKGQcfglrTU/AiEAjJs3LuO1F6GxDjgpLVVp+u750rVCwsUJ
zIqw8k4ytIY=
-----END CERTIFICATE-----"""
]

CA_MIN_KEY_SIZE = 1024
CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.db.DBBackend",
    },
}
