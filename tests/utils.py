from importlib import resources

from tests import files


def load_file(path: str) -> bytes:
    full_path = resources.files(files) / path
    with full_path.open("rb") as stream:
        return stream.read()
