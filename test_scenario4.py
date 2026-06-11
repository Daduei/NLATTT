"""
test_scenario4.py — Signature non-reusability across documents.

Security property tested:
  A signature for document A MUST NOT validate document B.
  Signatures are bound to the exact content they were created for.
"""

import os
import tempfile

import pytest

from algorithms import RSA_PKCS1V15
from keygen import generate_rsa_key_pair
from signer import sign_document
from verifier import verify_signature


def test_signature_not_reusable():
    with tempfile.TemporaryDirectory() as tmp:
        priv = os.path.join(tmp, "priv.pem")
        pub = os.path.join(tmp, "pub.pem")
        cert = os.path.join(tmp, "cert.pem")
        generate_rsa_key_pair(priv, pub, cert)

        # Sign document A
        doc_a = os.path.join(tmp, "doc_a.txt")
        sig_a = os.path.join(tmp, "doc_a.sig")
        with open(doc_a, "w", encoding="utf-8") as f:
            f.write("Document A: Approved.")
        sign_document(doc_a, priv, sig_a, algorithm=RSA_PKCS1V15, cert_path=cert)

        # Attacker tries to reuse signature A to authenticate document B
        doc_b = os.path.join(tmp, "doc_b.txt")
        with open(doc_b, "w", encoding="utf-8") as f:
            f.write("Document B: Transfer $1,000,000.")

        result = verify_signature(doc_b, sig_a, pub, cert_path=cert)
        assert result is False
