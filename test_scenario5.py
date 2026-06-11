"""
test_scenario5.py — Binary file signing and multi-algorithm roundtrip.

Security properties tested:
  1. Signatures work on binary data (not just text files)
  2. All three algorithms (RSA-PKCS1v15, RSA-PSS, ECDSA-P-256) sign and verify correctly
"""

import os
import tempfile

import pytest

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256
from keygen import generate_rsa_key_pair, generate_ecdsa_key_pair
from signer import sign_document
from verifier import verify_signature


def test_binary_file_signing():
    """Sign a binary file (simulated PDF header) and verify it passes."""
    with tempfile.TemporaryDirectory() as tmp:
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        generate_rsa_key_pair(priv, pub, cert)

        bin_doc = os.path.join(tmp, "report.bin")
        bin_sig = os.path.join(tmp, "report.bin.sig")
        with open(bin_doc, "wb") as f:
            f.write(b"%PDF-1.4\x00\x01\x02\x03" + b"\xFF" * 100)

        sign_document(bin_doc, priv, bin_sig, algorithm=RSA_PKCS1V15, cert_path=cert)
        result = verify_signature(bin_doc, bin_sig, pub, cert_path=cert)
        assert result is True


@pytest.mark.parametrize("algorithm,keygen_fn", [
    (RSA_PKCS1V15, generate_rsa_key_pair),
    (RSA_PSS, generate_rsa_key_pair),
    (ECDSA_P256, generate_ecdsa_key_pair),
])
def test_all_algorithms_roundtrip(algorithm, keygen_fn):
    """Each algorithm must successfully sign and verify a document."""
    with tempfile.TemporaryDirectory() as tmp:
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        doc = os.path.join(tmp, "doc.txt")
        sig = os.path.join(tmp, "doc.sig")

        keygen_fn(priv, pub, cert)
        with open(doc, "w", encoding="utf-8") as f:
            f.write(f"Algorithm test: {algorithm}")
        sign_document(doc, priv, sig, algorithm=algorithm, cert_path=cert)
        assert verify_signature(doc, sig, pub, cert_path=cert) is True
