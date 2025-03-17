from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Load the public key from a file
def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Encrypt the text
def encrypt_text(public_key, plaintext):
    encrypted = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()  # Encode in base64 for easier copy-paste

# Path to the public key file (Update this to your actual file path)
public_key_file = "public_key.pem"

# Load public key
public_key = load_public_key_from_file(public_key_file)

# Replace with the text you want to encrypt
plaintext = "FirstPass@123"

# Encrypt the text
encrypted_text = encrypt_text(public_key, plaintext)

print("Encrypted text:", encrypted_text)
