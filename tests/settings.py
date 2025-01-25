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

CA_MIN_KEY_SIZE = 1024
CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.db.DBBackend",
    },
}
