"""Constants used in various places throughout the code."""

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

#: Tuple of supported public key types
SUPPORTED_PUBLIC_KEY_TYPES = (
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed448.Ed448PublicKey | ed25519.Ed25519PublicKey
)
