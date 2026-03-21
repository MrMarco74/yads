import pytest
from yads.utils.crypto import encrypt_data, decrypt_data
from yads.config import settings

def test_encryption_decryption_roundtrip():
    """Verify that data can be encrypted and decrypted back to the original."""
    original_text = "Secret Sensor Data"
    encrypted = encrypt_data(original_text, settings.YADS_ENCRYPTION_KEY)
    assert encrypted != original_text
    assert ":" not in encrypted  # Salt:nonce:ciphertext is now binary combined then b64
    
    decrypted = decrypt_data(encrypted, settings.YADS_ENCRYPTION_KEY)
    assert decrypted == original_text

def test_encryption_output_is_deterministic_in_salt_but_random_in_nonce():
    """Verify that multiple encryptions of the same data produce different ciphertexts (due to random nonce)."""
    text = "Important Key"
    enc1 = encrypt_data(text, settings.YADS_ENCRYPTION_KEY)
    enc2 = encrypt_data(text, settings.YADS_ENCRYPTION_KEY)
    assert enc1 != enc2

def test_decryption_with_wrong_key_fails():
    """Verify that decryption fails if the key is different (simulated by changing environment)."""
    original_text = "My Password"
    encrypted = encrypt_data(original_text, settings.YADS_ENCRYPTION_KEY)
    
    # Mock settings change
    old_key = settings.YADS_ENCRYPTION_KEY
    settings.YADS_ENCRYPTION_KEY = "completely-different-key-456!"
    
    with pytest.raises(ValueError):
        decrypt_data(encrypted, settings.YADS_ENCRYPTION_KEY)
    
    settings.YADS_ENCRYPTION_KEY = old_key

def test_encryption_handles_empty_string():
    text = ""
    encrypted = encrypt_data(text, settings.YADS_ENCRYPTION_KEY)
    assert decrypt_data(encrypted, settings.YADS_ENCRYPTION_KEY) == ""
