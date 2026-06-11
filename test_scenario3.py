# test_scenario3.py
def test_wrong_public_key_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        # Generate legitimate key pair and sign
        generate_key_pair(priv, pub)
        with open(doc, 'w') as f:
            f.write('Authentic document')
        sign_document(doc, priv, sig)

        # Generate attacker key pair
        fake_priv = os.path.join(tmp, 'fake_priv.pem')
        fake_pub  = os.path.join(tmp, 'fake_pub.pem')
        generate_key_pair(fake_priv, fake_pub)

        # Attempt verification with wrong public key
        result = verify_signature(doc, sig, fake_pub)
        assert result == False, 'Wrong public key must be rejected'

# Expected output:
# [RESULT] Signature INVALID - Document may have been tampered.
