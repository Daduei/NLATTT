"""
certificate.py — X.509 certificate simulation (PKI layer).

In real PKI, a Certificate Authority (CA) binds a public key to an identity.
Here we create self-signed certificates so the public key is tied to a
named signer (e.g. "Dean of Faculty" at NEU) instead of being anonymous raw bytes.
"""

import datetime
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def _email_from_name(subject_name):
    """
    Build a valid RFC 822 email from the certificate subject name.
    Strips special characters so names like 'Alice (NEU Dean)' become valid emails.
    """
    local = re.sub(r"[^a-z0-9.]", "", subject_name.lower().replace(" ", "."))
    local = local.strip(".") or "signer"
    return f"{local}@neu.edu.vn"


def create_self_signed_certificate(private_key, subject_name, cert_path,
                                   key_type="RSA-2048", valid_days=365):
    """
    Generate a self-signed X.509 certificate binding the public key to an identity.
    Subject = Issuer because there is no external CA in this demo.
    Saves the PEM-encoded certificate to cert_path.
    """
    # Extract public key from the private key (works for both RSA and ECDSA)
    if isinstance(private_key, rsa.RSAPrivateKey):
        public_key = private_key.public_key()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        public_key = private_key.public_key()
    else:
        raise TypeError("Unsupported private key type")

    # Distinguished Name (DN) — who this certificate belongs to
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "National Economics University"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Faculty of IT"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)                          # self-signed: issuer == subject
        .public_key(public_key)                       # the key being certified
        .serial_number(x509.random_serial_number())   # unique cert ID
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            # KeyUsage: this cert may only be used for digital signatures
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            # Alternative contact: email address derived from the subject name
            x509.SubjectAlternativeName([
                x509.RFC822Name(_email_from_name(subject_name)),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())  # cert is signed by its own private key
    )

    # Write certificate to PEM file (-----BEGIN CERTIFICATE-----)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, "wb") as f:
        f.write(pem)

    return cert


def load_certificate(cert_path):
    """Load and parse a PEM-encoded X.509 certificate from disk."""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def print_certificate_info(cert):
    """Display certificate fields for educational / demo output."""
    print("\n" + "=" * 60)
    print("X.509 CERTIFICATE")
    print("=" * 60)
    print(f"  Subject    : {cert.subject.rfc4514_string()}")
    print(f"  Issuer     : {cert.issuer.rfc4514_string()}")
    print(f"  Serial     : {cert.serial_number}")
    print(f"  Valid From : {cert.not_valid_before_utc.isoformat()}")
    print(f"  Valid To   : {cert.not_valid_after_utc.isoformat()}")
    print(f"  Signature  : {cert.signature_algorithm_oid._name}")
    # Fingerprint uniquely identifies this certificate (like a thumbprint)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    print(f"  SHA-256 FP : {':'.join(fp[i:i+2] for i in range(0, len(fp), 2))}")
    print("=" * 60)


def get_signer_id_from_cert(cert):
    """Extract the Common Name (CN) from the certificate subject as the signer ID."""
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return cert.subject.rfc4514_string()


def get_cert_fingerprint(cert):
    """Return SHA-256 fingerprint as hex (stored in the .sig JSON envelope)."""
    return cert.fingerprint(hashes.SHA256()).hex()
