from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_signature(document_path, signature_path, public_key_path):
    """
    Verifies a digital signature against a document using the signer's public key.

    Returns:
        True  if signature is valid (document is authentic and unmodified)
        False if signature is invalid (document tampered or wrong key)
    """
    # Step 1: Read the received document (potentially modified by attacker)
    with open(document_path, 'rb') as f:
        document_data = f.read()

    # Step 2: Read the digital signature from file
    with open(signature_path, 'rb') as f:
        signature = f.read()

    # Step 3: Load the signer's public key
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Step 4: Perform cryptographic verification
    # The library re-hashes document_data using SHA-256 internally,
    # then compares it against the decrypted hash in the signature.
    try:
        public_key.verify(
            signature,
            document_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print('[RESULT] Signature VALID   - Document is authentic and unmodified.')
        return True
    except InvalidSignature:
        print('[RESULT] Signature INVALID - Document may have been tampered.')
        return False

if __name__ == '__main__':
    verify_signature('test_document.txt', 'test_document.txt.sig', 'public_key.pem')
