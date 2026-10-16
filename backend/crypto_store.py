"""Encrypted evidence storage (AES-256-GCM) and SHA-256 fingerprints.

File layout: MAGIC(4) | nonce(12) | ciphertext+GCM tag
The incident id is bound as associated data, so an encrypted file swapped in
from another incident fails to decrypt instead of silently passing.
"""
import base64
import hashlib
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"IDE1"
NONCE_LEN = 12
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class EvidenceTampered(Exception):
    """Ciphertext failed authentication: the file was modified or swapped."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_key_b64() -> str:
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()


class EvidenceStore:
    def __init__(self, directory, key_b64):
        if not key_b64:
            raise RuntimeError("EVIDENCE_KEY is not set - run `python manage.py init`")
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise RuntimeError("EVIDENCE_KEY must decode to 32 bytes (AES-256)")
        self._aes = AESGCM(key)
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, incident_id):
        if not _SAFE_ID.match(incident_id):
            raise ValueError("invalid incident id")
        return self.directory / f"{incident_id}.enc"

    def save(self, incident_id: str, plaintext: bytes) -> str:
        """Encrypt and store evidence. Returns the SHA-256 of the plaintext."""
        nonce = os.urandom(NONCE_LEN)
        ct = self._aes.encrypt(nonce, plaintext, incident_id.encode())
        self._path(incident_id).write_bytes(MAGIC + nonce + ct)
        return sha256_hex(plaintext)

    def load(self, incident_id: str) -> bytes:
        """Decrypt evidence. Raises EvidenceTampered or FileNotFoundError."""
        blob = self._path(incident_id).read_bytes()
        if blob[:4] != MAGIC or len(blob) < 4 + NONCE_LEN + 16:
            raise EvidenceTampered("bad file header")
        nonce, ct = blob[4:4 + NONCE_LEN], blob[4 + NONCE_LEN:]
        try:
            return self._aes.decrypt(nonce, ct, incident_id.encode())
        except InvalidTag as e:
            raise EvidenceTampered("authentication tag mismatch") from e
