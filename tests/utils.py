"""Utility functions for unit tests."""

from importlib import resources

from tests import files


def load_file(path: str) -> bytes:
    """Utility function to load a file from ``tests.files``."""
    full_path = resources.files(files) / path
    with full_path.open("rb") as stream:
        return stream.read()
