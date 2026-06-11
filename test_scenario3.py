"""
test_scenario3.py — Wrong public key rejection.

Security property tested:
  A signature created with key pair A MUST NOT verify with key pair B.
  This prevents an attacker from substituting their own public key.
"""

import os
import tempfile

import pytest

from algorithms import RSA_PKCS1V15
from keygen import generate_rsa_key_pair
from signer import sign_document
from verifier import verify_signature


def test_wrong_public_key_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        doc = os.path.join(tmp, "doc.txt")
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        sig = os.path.join(tmp, "doc.sig")

        # Legitimate signer creates and signs a document
        generate_rsa_key_pair(priv, pub, cert)
        with open(doc, "w", encoding="utf-8") as f:
            f.write("Authentic document")
        sign_document(doc, priv, sig, algorithm=RSA_PKCS1V15, cert_path=cert)

        # Attacker generates their own key pair and tries to verify
        fake_priv = os.path.join(tmp, "fake_priv.pem")
        fake_pub = os.path.join(tmp, "fake_pub.pem")
        fake_cert = os.path.join(tmp, "fake_cert.pem")
        generate_rsa_key_pair(fake_priv, fake_pub, fake_cert)

        result = verify_signature(doc, sig, fake_pub, cert_path=fake_cert)
        assert result is False
