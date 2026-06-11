"""
keygen.py — Cryptographic key pair generation.

Generates RSA-2048 and ECDSA P-256 key pairs, saves them as PEM files,
and issues a self-signed X.509 certificate for each pair.

Note: RSA-PKCS1v15 and RSA-PSS share the same RSA key pair — only the
padding scheme differs at signing time.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from certificate import create_self_signed_certificate, print_certificate_info
from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256


def _save_pem(data, path):
    """Write PEM-encoded bytes (private key, public key, or certificate) to disk."""
    with open(path, "wb") as f:
        f.write(data)


def generate_rsa_key_pair(private_key_path="private_key_rsa.pem",
                          public_key_path="public_key_rsa.pem",
                          cert_path="certificate_rsa.pem",
                          signer_name="Dean of Faculty"):
    """
    Generate RSA-2048 key pair, save PEM files, and issue a self-signed X.509 cert.
    Used by both RSA-PKCS1v15 and RSA-PSS signing algorithms.
    """
    # public_exponent=65537 (F4) is the industry standard; key_size=2048 = 112-bit security
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize private key in PKCS#8 PEM format (unencrypted for this demo)
    _save_pem(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ), private_key_path)

    # Serialize public key in SubjectPublicKeyInfo PEM format
    _save_pem(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ), public_key_path)

    # Bind the public key to an identity via X.509 certificate
    cert = create_self_signed_certificate(
        private_key, signer_name, cert_path, key_type="RSA-2048"
    )

    print(f"[OK] RSA-2048 private key : {private_key_path}")
    print(f"[OK] RSA-2048 public  key : {public_key_path}")
    print(f"[OK] X.509 certificate    : {cert_path}")
    print_certificate_info(cert)
    return private_key, public_key, cert


def generate_ecdsa_key_pair(private_key_path="private_key_ecdsa.pem",
                            public_key_path="public_key_ecdsa.pem",
                            cert_path="certificate_ecdsa.pem",
                            signer_name="Dean of Faculty"):
    """
    Generate ECDSA P-256 key pair, save PEM files, and issue a self-signed X.509 cert.
    P-256 (secp256r1) provides ~128-bit security with much smaller keys than RSA-2048.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    _save_pem(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ), private_key_path)

    _save_pem(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ), public_key_path)

    cert = create_self_signed_certificate(
        private_key, signer_name, cert_path, key_type="EC-P256"
    )

    print(f"[OK] ECDSA P-256 private key : {private_key_path}")
    print(f"[OK] ECDSA P-256 public  key : {public_key_path}")
    print(f"[OK] X.509 certificate       : {cert_path}")
    print_certificate_info(cert)
    return private_key, public_key, cert


def generate_all_key_pairs(signer_name="Dean of Faculty"):
    """Generate both RSA and ECDSA key pairs (covers all three signing algorithms)."""
    print("=" * 60)
    print("KEY GENERATION: RSA-2048 (shared by PKCS1v15 and PSS)")
    print("=" * 60)
    rsa_keys = generate_rsa_key_pair(signer_name=signer_name)

    print()
    print("=" * 60)
    print("KEY GENERATION: ECDSA P-256")
    print("=" * 60)
    ecdsa_keys = generate_ecdsa_key_pair(signer_name=signer_name)

    return {"rsa": rsa_keys, "ecdsa": ecdsa_keys}


def get_key_paths(algorithm):
    """
    Return (private_key_path, public_key_path, cert_path) for a given algorithm.
    RSA-PKCS1v15 and RSA-PSS share the same key files.
    """
    if algorithm in (RSA_PKCS1V15, RSA_PSS):
        return "private_key_rsa.pem", "public_key_rsa.pem", "certificate_rsa.pem"
    if algorithm == ECDSA_P256:
        return "private_key_ecdsa.pem", "public_key_ecdsa.pem", "certificate_ecdsa.pem"
    raise ValueError(f"Unknown algorithm: {algorithm}")


# Backward-compatible alias for older code that calls generate_key_pair()
def generate_key_pair(private_key_path="private_key.pem",
                      public_key_path="public_key.pem"):
    private_key, public_key, _ = generate_rsa_key_pair(
        private_key_path, public_key_path, cert_path="certificate.pem"
    )
    return private_key, public_key


if __name__ == "__main__":
    generate_all_key_pairs()
