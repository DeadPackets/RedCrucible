"""Payload encryption for the polymorphic loader.

Encrypts shellcode payloads with a random rolling XOR key.
The key length determines entropy: 16 bytes for "xor" mode,
32 bytes for "aes" mode (same decryption stub, better entropy).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    key: bytes
    method: str  # "xor" or "aes"


def encrypt_xor_multibyte(payload: bytes, key_len: int = 16) -> EncryptedPayload:
    key = bytearray(os.urandom(key_len))
    # Ensure no null bytes in key (would be XOR identity for null payload bytes)
    for i in range(len(key)):
        while key[i] == 0:
            key[i] = os.urandom(1)[0]
    key = bytes(key)

    ciphertext = bytes(payload[i] ^ key[i % key_len] for i in range(len(payload)))
    method = "aes" if key_len >= 32 else "xor"
    return EncryptedPayload(ciphertext=ciphertext, key=key, method=method)
