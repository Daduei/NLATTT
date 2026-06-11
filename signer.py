"""
signer.py — Document signing with JSON metadata envelope.

Reads a document, computes its SHA-256 digest, signs the bytes with the
chosen algorithm, and writes a .sig JSON file containing:
  timestamp, algorithm, signer ID, certificate fingerprint, digest, and signature.
"""

import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256, get_padding, ALGORITHM_INFO
from certificate import load_certificate, get_signer_id_from_cert, get_cert_fingerprint
from utils import sha256_hex, print_signature_inspection, print_hex_dump


def _load_private_key(path):
    """Load a PEM-encoded private key from disk (RSA or ECDSA)."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _sign_bytes(private_key, data, algorithm):
    """
    Sign raw bytes with the specified algorithm.
    The library hashes data with SHA-256 internally before signing.
    """
    if algorithm in (RSA_PKCS1V15, RSA_PSS):
        return private_key.sign(data, get_padding(algorithm), hashes.SHA256())
    if algorithm == ECDSA_P256:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def sign_document(document_path, private_key_path, signature_path=None,
                  algorithm=RSA_PKCS1V15, cert_path=None, signer_id=None):
    """
    Sign a document and package the result into a JSON .sig metadata envelope.

    Steps:
      1. Read document bytes
      2. Compute SHA-256 digest (for display and envelope storage)
      3. Sign bytes with private key
      4. Build JSON envelope with metadata + base64 signature
      5. Write .sig file and print inspection output
    """
    # --- Step 1: Read the document ---
    with open(document_path, "rb") as f:
        document_data = f.read()

    # --- Step 2: Compute digest (shown in output and stored in envelope) ---
    digest = sha256_hex(document_data)
    print(f"[INFO] Document       : {document_path}")
    print(f"[INFO] Algorithm      : {algorithm} ({ALGORITHM_INFO[algorithm]['description']})")
    print(f"[INFO] SHA-256 digest : {digest}")
    print_hex_dump("Document bytes (first 64 B)", document_data)

    # --- Step 3: Load private key and produce the cryptographic signature ---
    private_key = _load_private_key(private_key_path)
    signature = _sign_bytes(private_key, document_data, algorithm)

    # --- Step 4: Pull signer identity from X.509 certificate (if provided) ---
    if cert_path:
        cert = load_certificate(cert_path)
        signer_id = signer_id or get_signer_id_from_cert(cert)
        cert_fp = get_cert_fingerprint(cert)
    else:
        cert_fp = None
        signer_id = signer_id or "unknown"

    # --- Step 5: Build the JSON metadata envelope ---
    envelope = {
        "format_version": "1.0",
        "algorithm": algorithm,
        "hash_algorithm": "SHA-256",
        "timestamp": datetime.now(timezone.utc).isoformat(),  # when the doc was signed
        "signer_id": signer_id,                               # from cert CN field
        "certificate_fingerprint_sha256": cert_fp,              # ties sig to a specific cert
        "document_digest_sha256": digest,                       # digest at signing time
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signature_size_bytes": len(signature),
        "key_type": ALGORITHM_INFO[algorithm]["key_type"],
    }

    # Default output path: e.g. test_document.txt.rsa_pkcs1v15.sig
    if signature_path is None:
        safe_algo = algorithm.lower().replace("-", "_")
        signature_path = f"{document_path}.{safe_algo}.sig"

    with open(signature_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    print(f"[OK] Signature saved  : {signature_path}")
    print(f"[OK] Signature size   : {len(signature)} bytes")
    print_signature_inspection(signature, algorithm)
    return envelope


if __name__ == "__main__":
    sign_document("test_document.txt", "private_key_rsa.pem",
                  cert_path="certificate_rsa.pem", algorithm=RSA_PKCS1V15)
