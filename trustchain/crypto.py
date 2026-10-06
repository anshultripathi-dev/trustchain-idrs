"""Cryptographic primitives: canonical JSON, SHA-256, ECDSA P-256 sign/verify."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding so hashes/signatures are reproducible."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class KeyPair:
    """ECDSA P-256 key pair. Public key is exchanged as an uncompressed point (hex)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private = private_key

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes) -> "KeyPair":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("not an EC private key")
        return cls(key)

    def to_pem(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def public_hex(self) -> str:
        return self._private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ).hex()

    def sign(self, data: bytes) -> str:
        return self._private.sign(data, ec.ECDSA(hashes.SHA256())).hex()


_PUB_CACHE: dict[str, ec.EllipticCurvePublicKey] = {}


def _load_public(public_hex: str) -> ec.EllipticCurvePublicKey:
    key = _PUB_CACHE.get(public_hex)
    if key is None:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(public_hex)
        )
        _PUB_CACHE[public_hex] = key
    return key


def verify(public_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        _load_public(public_hex).verify(
            bytes.fromhex(signature_hex), data, ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_or_create_key(path: str | None) -> KeyPair:
    """Persist keys with 0600 permissions. (Prototype: keys live on disk, not in an HSM.)"""
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            return KeyPair.from_pem(fh.read())
    key = KeyPair.generate()
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.to_pem())
    return key
