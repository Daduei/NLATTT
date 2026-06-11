"""
verifier.py — Signature verification from JSON .sig envelope.

Reads the .sig JSON file, recomputes the document digest, and performs
cryptographic verification with the signer's public key.
Returns True if authentic, False if tampered or wrong key.
"""

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256, get_padding
from certificate import load_certificate, print_certificate_info, get_signer_id_from_cert
from utils import sha256_hex


def _load_public_key(path):
    """Load a PEM-encoded public key from disk."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _verify_bytes(public_key, signature, data, algorithm):
    """
    Verify a signature against data using the correct algorithm/padding.
    Raises InvalidSignature if verification fails.
    """
    if algorithm in (RSA_PKCS1V15, RSA_PSS):
        public_key.verify(signature, data, get_padding(algorithm), hashes.SHA256())
    elif algorithm == ECDSA_P256:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _print_digest_mismatch(stored_digest, current_digest):
    """Print side-by-side digests to show that tampering changed the hash."""
    print("\n" + "=" * 60)
    print("SHA-256 DIGEST COMPARISON")
    print("=" * 60)
    print(f"  At signing time : {stored_digest}")
    print(f"  Current document: {current_digest}")
    match = stored_digest == current_digest
    print(f"  Match           : {'YES' if match else 'NO  (tampering detected)'}")
    if not match:
        diffs = sum(1 for a, b in zip(stored_digest, current_digest) if a != b)
        print(f"  Diff positions  : {diffs} hex chars out of 64")
    print("=" * 60)


def verify_signature(document_path, signature_path, public_key_path,
                     cert_path=None, show_digest_on_fail=True):
    """
    Verify a JSON .sig envelope against a document and public key.

    Verification has two layers:
      1. Digest check  — recompute SHA-256 and compare to stored digest
      2. Crypto check  — decrypt signature with public key and confirm it matches

    Returns True if valid, False otherwise.
    """
    # --- Load the document and parse the .sig JSON envelope ---
    with open(document_path, "rb") as f:
        document_data = f.read()

    with open(signature_path, "r", encoding="utf-8") as f:
        envelope = json.load(f)

    algorithm = envelope["algorithm"]
    stored_digest = envelope["document_digest_sha256"]   # digest recorded at signing
    current_digest = sha256_hex(document_data)            # digest of received document
    signature = base64.b64decode(envelope["signature_b64"])

    print(f"[INFO] Document       : {document_path}")
    print(f"[INFO] Algorithm      : {algorithm}")
    print(f"[INFO] Signed at      : {envelope['timestamp']}")
    print(f"[INFO] Signer ID      : {envelope['signer_id']}")
    print(f"[INFO] Current digest : {current_digest}")
    print(f"[INFO] Stored digest  : {stored_digest}")

    # --- Optional: display X.509 certificate and check signer ID consistency ---
    if cert_path:
        cert = load_certificate(cert_path)
        print_certificate_info(cert)
        expected_signer = get_signer_id_from_cert(cert)
        if envelope["signer_id"] != expected_signer:
            print(f"[WARN] Signer ID mismatch: envelope={envelope['signer_id']}, cert={expected_signer}")

    # --- Layer 1: Digest comparison (fast tamper indicator) ---
    digest_match = current_digest == stored_digest
    if not digest_match:
        print("[RESULT] Digest MISMATCH — document content has changed since signing.")
        if show_digest_on_fail:
            _print_digest_mismatch(stored_digest, current_digest)

    # --- Layer 2: Cryptographic verification with public key ---
    public_key = _load_public_key(public_key_path)

    try:
        _verify_bytes(public_key, signature, document_data, algorithm)
        if digest_match:
            print("[RESULT] Signature VALID   — Document is authentic and unmodified.")
            return True
        # Crypto may pass on edge cases, but digest mismatch still means tampering
        print("[RESULT] Signature INVALID — Digest mismatch proves tampering.")
        return False
    except InvalidSignature:
        print("[RESULT] Signature INVALID — Cryptographic verification failed.")
        if show_digest_on_fail and not digest_match:
            _print_digest_mismatch(stored_digest, current_digest)
        return False


if __name__ == "__main__":
    verify_signature("test_document.txt", "test_document.txt.rsa_pkcs1v15.sig",
                     "public_key_rsa.pem", cert_path="certificate_rsa.pem")
