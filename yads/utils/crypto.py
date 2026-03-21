import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants for data-at-rest encryption (NIS2 / DSGVO Compliance)
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100000

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(plain_text: str, master_key: str) -> str:
    """
    Encrypts plain text using AES-256-GCM with a PBKDF2-derived key.
    Format: base64(salt + nonce + ciphertext)
    """
    if not plain_text:
        return ""
    if not master_key:
        raise ValueError("Master encryption key (YADS_ENCRYPTION_KEY) is missing.")

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(master_key, salt)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    
    # Encrypt data (AAD=None)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    
    # Pack everything
    combined = salt + nonce + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(cipher_text: str, master_key: str) -> str:
    """
    Decrypts cipher text using AES-256-GCM.
    Reverse of encrypt_data.
    """
    if not cipher_text:
        return ""
    if not master_key:
        raise ValueError("Master encryption key (YADS_ENCRYPTION_KEY) is missing.")

    try:
        combined = base64.b64decode(cipher_text.encode('utf-8'))
        
        if len(combined) < SALT_SIZE + NONCE_SIZE:
            raise ValueError("Cipher text is too short or corrupted.")

        salt = combined[:SALT_SIZE]
        nonce = combined[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        ciphertext = combined[SALT_SIZE+NONCE_SIZE:]
        
        key = _derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode('utf-8')
    except Exception as e:
        # In production, we might want to log this but not expose exact failure to UI
        raise ValueError(f"Decryption failed: {str(e)}")
