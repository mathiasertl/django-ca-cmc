"""django-ca-cmc provides CMC support for django-ca."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("django-ca-cmc")
except PackageNotFoundError:
    # package is not installed
    pass
