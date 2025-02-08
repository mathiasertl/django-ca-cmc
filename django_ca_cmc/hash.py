"""Collect functions related to hashing."""

import hashlib

import asn1crypto.algos


def digest(data: bytes, algorithm: asn1crypto.algos.DigestAlgorithm) -> bytes:
    """
    Hash arbitrary data using the given digest algorithm.

    This function supports the full range of SHA2 and SHA3 algorithms.
    """
    algorithm = algorithm["algorithm"].native

    if algorithm in ("md5", "sha1"):
        raise ValueError(f"{algorithm}: Cannot hash data using this algorithm")

    hasher = hashlib.new(algorithm, data)
    try:
        return hasher.digest()
    except TypeError as ex:
        raise ValueError(f"{algorithm}: Unable to use algorithm for hashing") from ex
