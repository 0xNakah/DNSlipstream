# lib/crypto.py
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
import binascii

def seal(payload: bytes, secret_key: str):
    """
    Encrypt the payload with XSalsa20 + Poly1305.

    Args:
        payload (bytes): The data to encrypt.
        secret_key (str): The 64-character hex-encoded (32-byte) key.

    Returns:
        tuple: (nonce: bytes, ciphertext: bytes)
    """
    # Convert the hex key to 32 bytes
    key_bytes = binascii.unhexlify(secret_key)
    if len(key_bytes) != SecretBox.KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    box = SecretBox(key_bytes)

    # Generate a 24-byte nonce
    nonce = nacl_random(SecretBox.NONCE_SIZE)

    # Encrypt (seal) the payload
    ciphertext = box.encrypt(payload, nonce)
    # PyNaCl prepends the nonce, so we separate it
    return nonce, ciphertext.ciphertext

def open_sealed(payload: bytes, in_nonce: bytes, secret_key: str):
    """
    Decrypt the ciphertext with XSalsa20 + Poly1305.

    Args:
        payload (bytes): The encrypted data (ciphertext).
        in_nonce (bytes): The nonce used during encryption.
        secret_key (str): The 64-character hex-encoded (32-byte) key.

    Returns:
        tuple: (output: bytes, valid: bool)
    """
    key_bytes = binascii.unhexlify(secret_key)
    if len(key_bytes) != SecretBox.KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    box = SecretBox(key_bytes)
    try:
        # PyNaCl expects nonce+ciphertext together for .decrypt(),
        # so we reconstruct it
        from nacl.exceptions import CryptoError
        full_payload = in_nonce + payload
        output = box.decrypt(full_payload)
        return output, True
    except Exception:
        return None, False
