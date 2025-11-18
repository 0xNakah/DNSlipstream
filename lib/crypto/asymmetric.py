# lib/crypto/asymmetric.py
"""
Curve25519 (X25519) asymmetric key exchange for DNSlipstream.
Uses ECDH to establish shared secrets for symmetric encryption.
"""

import os
import binascii
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder, RawEncoder
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


class KeyPair:
    """Represents a Curve25519 keypair for ECDH key exchange."""
    
    def __init__(self, private_key=None):
        """
        Initialize keypair. If private_key is None, generates new keypair.
        
        Args:
            private_key: Optional 32-byte private key or hex string
        """
        if private_key is None:
            # Generate new keypair using PyNaCl
            self._private = PrivateKey.generate()
        elif isinstance(private_key, str):
            # Load from hex string
            key_bytes = binascii.unhexlify(private_key)
            self._private = PrivateKey(key_bytes)
        elif isinstance(private_key, bytes):
            # Load from bytes
            self._private = PrivateKey(private_key)
        else:
            self._private = private_key
            
        self._public = self._private.public_key
    
    @property
    def private_key(self):
        """Get private key as bytes."""
        return bytes(self._private)
    
    @property
    def public_key(self):
        """Get public key as bytes."""
        return bytes(self._public)
    
    @property
    def private_key_hex(self):
        """Get private key as hex string."""
        return binascii.hexlify(self.private_key).decode('ascii')
    
    @property
    def public_key_hex(self):
        """Get public key as hex string."""
        return binascii.hexlify(self.public_key).decode('ascii')
    
    @property
    def public_key_base64(self):
        """Get public key as base64 (for DNS transmission)."""
        return self._public.encode(encoder=Base64Encoder).decode('ascii')
    
    @classmethod
    def from_private_hex(cls, hex_string):
        """Create keypair from hex-encoded private key."""
        return cls(private_key=hex_string)
    
    @classmethod
    def from_public_hex(cls, hex_string):
        """Create public key object from hex string (for peer keys)."""
        key_bytes = binascii.unhexlify(hex_string)
        return PublicKey(key_bytes)
    
    @classmethod
    def from_public_base64(cls, base64_string):
        """Create public key object from base64 string (from DNS)."""
        return PublicKey(base64_string, encoder=Base64Encoder)
    
    def __repr__(self):
        return f"KeyPair(public={self.public_key_hex[:16]}...)"


def generate_keypair():
    """
    Generate a new Curve25519 keypair.
    
    Returns:
        KeyPair: New keypair object
    """
    return KeyPair()


def derive_shared_secret_nacl(my_private_key, peer_public_key):
    """
    Derive shared secret using PyNaCl Box (ECDH + key derivation).
    This uses Curve25519 ECDH and derives a key suitable for XSalsa20-Poly1305.
    
    Args:
        my_private_key: KeyPair or PrivateKey object
        peer_public_key: PublicKey object or bytes
        
    Returns:
        bytes: 32-byte shared secret key (hex string)
    """
    if isinstance(my_private_key, KeyPair):
        private = my_private_key._private
    else:
        private = my_private_key
    
    if isinstance(peer_public_key, bytes):
        peer_public_key = PublicKey(peer_public_key)
    
    # Create Box which performs ECDH and derives shared key
    box = Box(private, peer_public_key)
    
    # Extract the shared key from the box
    # Note: Box._shared_key() is the derived shared secret
    shared_secret = box._shared_key
    
    # Return as hex string (for compatibility with existing symmetric.py)
    return binascii.hexlify(shared_secret).decode('ascii')


def derive_shared_secret_x25519(my_private_key, peer_public_key):
    """
    Derive shared secret using cryptography library X25519.
    Uses ECDH + HKDF for key derivation.
    
    Args:
        my_private_key: 32-byte private key (bytes or hex string)
        peer_public_key: 32-byte public key (bytes or hex string)
        
    Returns:
        str: 64-character hex-encoded shared secret (32 bytes)
    """
    # Convert inputs to bytes if needed
    if isinstance(my_private_key, str):
        my_private_key = binascii.unhexlify(my_private_key)
    if isinstance(peer_public_key, str):
        peer_public_key = binascii.unhexlify(peer_public_key)
    
    # Load keys
    private = x25519.X25519PrivateKey.from_private_bytes(my_private_key)
    public = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
    
    # Perform ECDH
    shared_secret = private.exchange(public)
    
    # Derive 32-byte key using HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'DNSlipstream v1.0 key derivation'
    ).derive(shared_secret)
    
    # Return as hex string
    return binascii.hexlify(derived_key).decode('ascii')


def serialize_private_key(private_key, password=None):
    """
    Serialize private key to PEM format for storage.
    
    Args:
        private_key: KeyPair or bytes (32-byte private key)
        password: Optional password for encryption (bytes)
        
    Returns:
        str: PEM-encoded private key
    """
    if isinstance(private_key, KeyPair):
        key_bytes = private_key.private_key
    else:
        key_bytes = private_key
    
    # Load as X25519 key
    x25519_key = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
    
    # Choose encryption algorithm
    if password:
        from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
        encryption = BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    
    # Serialize
    pem = x25519_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    return pem.decode('utf-8')


def deserialize_private_key(pem_data, password=None):
    """
    Deserialize private key from PEM format.
    
    Args:
        pem_data: PEM-encoded private key (str or bytes)
        password: Optional password for decryption (bytes)
        
    Returns:
        KeyPair: Loaded keypair
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('utf-8')
    
    # Load key
    x25519_key = serialization.load_pem_private_key(
        pem_data,
        password=password
    )
    
    # Extract raw bytes
    key_bytes = x25519_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return KeyPair(private_key=key_bytes)


def perform_key_exchange(my_keypair, peer_public_key_hex):
    """
    High-level key exchange function.
    
    Args:
        my_keypair: Your KeyPair object
        peer_public_key_hex: Peer's public key as hex string
        
    Returns:
        str: 64-character hex symmetric key for use with symmetric.py
    """
    peer_public = KeyPair.from_public_hex(peer_public_key_hex)
    return derive_shared_secret_nacl(my_keypair, peer_public)
