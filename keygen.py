from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair(private_key_path='private_key.pem',
                      public_key_path='public_key.pem'):
    """
    Generates an RSA-2048 key pair and saves both keys to PEM files.
    RSA-2048 is recommended by NIST for digital signatures (FIPS 186-5).
    """
    # Step 1: Generate private key using RSA algorithm
    # public_exponent=65537 is the standard choice (Fermat prime F4)
    # key_size=2048 provides 112-bit security strength (NIST recommendation)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Step 2: Serialize private key to PEM format (PKCS#8 encoding)
    # BestAvailableEncryption would add a passphrase - using NoEncryption for demo
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Step 3: Extract and serialize the corresponding public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Step 4: Save both keys to disk
    with open(private_key_path, 'wb') as f:
        f.write(pem_private)
    with open(public_key_path, 'wb') as f:
        f.write(pem_public)

    print(f'[OK] Private key saved to: {private_key_path}')
    print(f'[OK] Public  key saved to: {public_key_path}')
    return private_key, public_key

if __name__ == '__main__':
    generate_key_pair()
