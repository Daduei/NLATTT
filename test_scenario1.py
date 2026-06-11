"""
test_scenario1.py — Valid signature roundtrip.

Security property tested:
  A correctly signed document MUST pass verification with the matching public key.
"""

import os
import tempfile

import pytest

from algorithms import RSA_PKCS1V15
from keygen import generate_rsa_key_pair
from signer import sign_document
from verifier import verify_signature


def test_valid_signature():
    with tempfile.TemporaryDirectory() as tmp:
        # Set up isolated temp files so tests don't touch project key files
        doc = os.path.join(tmp, "doc.txt")
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        sig = os.path.join(tmp, "doc.sig")

        with open(doc, "w", encoding="utf-8") as f:
            f.write("NEU Official Contract - Amount: 5,000,000 VND")

        generate_rsa_key_pair(priv, pub, cert)
        sign_document(doc, priv, sig, algorithm=RSA_PKCS1V15, cert_path=cert)
        result = verify_signature(doc, sig, pub, cert_path=cert)
        assert result is True
