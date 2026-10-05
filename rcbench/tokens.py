"""Local access tokens issued by an edge domain.

A token is a JSON Web Token signed with EdDSA by the issuing domain. Besides the
registered claims it carries the lineage that the continuity profile requires:
source credential and issuer, holder key, audience, action scope, policy version,
the status entries of the source credential, the status evidence that was
accepted, the parent token, and the absolute authorization deadline.
"""
import base64
import hashlib

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_raw(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def thumbprint(public_multibase: str) -> str:
    """Short identifier of a holder key used in the confirmation claim."""
    return base64.urlsafe_b64encode(hashlib.sha256(public_multibase.encode()).digest()[:16]).rstrip(b"=").decode()


def sign(claims: dict, key: Ed25519PrivateKey, key_id: str) -> str:
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": key_id, "typ": "at+jwt"})


def verify(token: str, public: bytes) -> dict | None:
    """Return the claims if the signature verifies, otherwise None. Time limits are checked by the caller."""
    try:
        return jwt.decode(token, Ed25519PublicKey.from_public_bytes(public), algorithms=["EdDSA"],
                          options={"verify_exp": False, "verify_aud": False, "verify_iat": False})
    except jwt.PyJWTError:
        return None
