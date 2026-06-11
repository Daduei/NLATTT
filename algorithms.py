"""
algorithms.py — Central registry of supported signing algorithms.

This module defines the three algorithms we compare in the project:
  - RSA-PKCS1v15 : classic RSA padding (deterministic, widely deployed)
  - RSA-PSS      : probabilistic RSA padding (recommended by PKCS#1 v2.1)
  - ECDSA-P256   : elliptic-curve signatures (smaller keys, faster signing)

Other modules import constants and padding config from here so algorithm
names stay consistent across keygen, signer, verifier, and benchmark.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# --- Algorithm name constants (used as JSON envelope values and CLI labels) ---
RSA_PKCS1V15 = "RSA-PKCS1v15"
RSA_PSS = "RSA-PSS"
ECDSA_P256 = "ECDSA-P256"

# Ordered list used by main.py and benchmark.py to loop over all algorithms
ALL_ALGORITHMS = [RSA_PKCS1V15, RSA_PSS, ECDSA_P256]

# Metadata shown in comparison tables and signing output
ALGORITHM_INFO = {
    RSA_PKCS1V15: {
        "key_type": "RSA-2048",
        "description": "RSA with PKCS#1 v1.5 padding (RFC 8017)",
        "expected_sig_bytes": 256,
    },
    RSA_PSS: {
        "key_type": "RSA-2048",
        "description": "RSA with Probabilistic Signature Scheme (RFC 8017)",
        "expected_sig_bytes": 256,
    },
    ECDSA_P256: {
        "key_type": "EC-P256",
        "description": "Elliptic Curve DSA on NIST P-256 (FIPS 186-5)",
        "expected_sig_bytes": "64-72 (DER-encoded)",
    },
}


def get_padding(algorithm):
    """
    Return the correct RSA padding object for the given algorithm.
    ECDSA does not use RSA padding — it uses ec.ECDSA() directly in signer/verifier.
    """
    if algorithm == RSA_PKCS1V15:
        # PKCS#1 v1.5: deterministic padding, same input always gives same signature
        return padding.PKCS1v15()
    if algorithm == RSA_PSS:
        # PSS: random salt makes each signature unique even for the same document
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )
    raise ValueError(f"Algorithm {algorithm} does not use RSA padding")
