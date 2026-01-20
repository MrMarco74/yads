
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_keys():
    """
    Generates an Ed25519 private/public key pair.
    Outputs the keys in OpenSSH format (Base64 encoded).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize Private Key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize Public Key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("--- PRIVATE KEY (KEEP SECRET) ---")
    print(base64.b64encode(private_bytes).decode('utf-8'))
    print("\n--- PUBLIC KEY (EMBED IN APP) ---")
    print(base64.b64encode(public_bytes).decode('utf-8'))

if __name__ == "__main__":
    generate_keys()
