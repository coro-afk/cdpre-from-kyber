import hashlib
import hmac
import os
from typing import Tuple

def generate_aes128_key() -> bytes:
    """Generate an AES-128 key using standard os."""
    return os.urandom(16)

def kdf(parent: bytes, direction: int) -> Tuple[bytes, bytes]:
    """Key Derivation Function (KDF) to generate child keys."""
    full_key = hmac.new(parent, str(direction).encode(), hashlib.sha256).digest()
    half_length = len(full_key) // 2
    return full_key[:half_length], full_key[half_length:]

def generate_kdfc_key(e, dk):
    sek, dk = kdf(dk, e)
    return sek, dk

if __name__ == '__main__':
    """Test the KDF chain."""
    n = 8
    dk = generate_aes128_key()
    for i in range(n):
        print('Epoch', i)
        sek, dk = generate_kdfc_key(i, dk)
        print('sek:', sek.hex())
        print('dk:', dk.hex())
        print()