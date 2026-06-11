import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_document(document_path, private_key_path, signature_path=None):
    """
    Signs a document file using RSA-2048 with SHA-256 hash and PKCS1v15 padding.

    Args:
        document_path   : path to the document to be signed
        private_key_path: path to the signer's PEM private key
        signature_path  : output path for the signature file (.sig)

    Returns:
        signature (bytes): the raw digital signature
    """
    # Step 1: Read the document content as raw bytes
    with open(document_path, 'rb') as f:
        document_data = f.read()

    # Step 2: Compute SHA-256 message digest of the document
    # Using hashlib for explicit digest preview (educational purpose)
    digest = hashlib.sha256(document_data).hexdigest()
    print(f'[INFO] SHA-256 digest : {digest}')

    # Step 3: Load the private key from PEM file
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Step 4: Sign the document data using RSA-PKCS1v15 with SHA-256
    # The library internally hashes the data again - this is standard practice
    # PKCS1v15 is deterministic and widely supported (RFC 8017)
    signature = private_key.sign(
        document_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Step 5: Save signature to file
    if signature_path is None:
        signature_path = document_path + '.sig'
    with open(signature_path, 'wb') as f:
        f.write(signature)

    print(f'[OK] Signature saved  : {signature_path}')
    print(f'[OK] Signature size   : {len(signature)} bytes (RSA-2048 = 256 bytes)')
    return signature

if __name__ == '__main__':
    sign_document('test_document.txt', 'private_key.pem')
