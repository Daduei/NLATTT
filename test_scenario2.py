"""
test_scenario2.py — Tampered document detection.

Security property tested:
  Modifying even one character in the document MUST cause verification to fail.
  This is the core integrity guarantee of digital signatures.
"""

import os
import tempfile

import pytest

from algorithms import RSA_PKCS1V15
from keygen import generate_rsa_key_pair
from signer import sign_document
from verifier import verify_signature


def test_tampered_document_detected():
    with tempfile.TemporaryDirectory() as tmp:
        doc = os.path.join(tmp, "doc.txt")
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        sig = os.path.join(tmp, "doc.sig")

        # Sign the original document
        with open(doc, "w", encoding="utf-8") as f:
            f.write("Transfer amount: 1,000 VND")
        generate_rsa_key_pair(priv, pub, cert)
        sign_document(doc, priv, sig, algorithm=RSA_PKCS1V15, cert_path=cert)

        # Attacker changes 1,000 -> 9,000 (single digit change)
        tampered = os.path.join(tmp, "tampered.txt")
        with open(tampered, "w", encoding="utf-8") as f:
            f.write("Transfer amount: 9,000 VND")

        result = verify_signature(tampered, sig, pub, cert_path=cert)
        assert result is False
