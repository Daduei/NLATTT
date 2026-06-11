# test_scenario1.py
import pytest
from keygen   import generate_key_pair
from signer   import sign_document
from verifier import verify_signature
import tempfile, os

def test_valid_signature():
    with tempfile.TemporaryDirectory() as tmp:
        doc  = os.path.join(tmp, 'doc.txt')
        priv = os.path.join(tmp, 'priv.pem')
        pub  = os.path.join(tmp, 'pub.pem')
        sig  = os.path.join(tmp, 'doc.sig')

        with open(doc, 'w') as f:
            f.write('NEU Official Contract - Amount: 5,000,000 VND')

        generate_key_pair(priv, pub)
        sign_document(doc, priv, sig)
        result = verify_signature(doc, sig, pub)
        assert result == True, 'Valid signature should pass verification'

# Expected output:
# [RESULT] Signature VALID - Document is authentic and unmodified.
