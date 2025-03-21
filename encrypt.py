import boto3
import base64

kms_client = boto3.client('kms', region_name="us-east-1")

def encrypt_with_kms(plaintext):
    key_id = "alias/my-app-kms-key"  # Replace with your actual KMS key ID or alias
    response = kms_client.encrypt(
        KeyId=key_id,
        Plaintext=plaintext.encode(),
        EncryptionAlgorithm="RSAES_OAEP_SHA_256"  # Use RSA-compatible algorithm
    )
    return base64.b64encode(response['CiphertextBlob']).decode()

# Example usage:
plaintext_password = "FirstPass@123"
encrypted_password = encrypt_with_kms(plaintext_password)
print("Encrypted Password:", encrypted_password)
