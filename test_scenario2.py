# test_scenario2.py
def test_tampered_document_detected():
    with tempfile.TemporaryDirectory() as tmp:
        # ... (setup same as Scenario 1) ...

        # Original document: sign it
        with open(doc, 'w') as f:
            f.write('Transfer amount: 1,000 VND')
        generate_key_pair(priv, pub)
        sign_document(doc, priv, sig)

        # Tamper: modify a single character in the document
        tampered = os.path.join(tmp, 'tampered.txt')
        with open(tampered, 'w') as f:
            f.write('Transfer amount: 9,000 VND')  # changed 1 -> 9

        result = verify_signature(tampered, sig, pub)
        assert result == False, 'Tampered document must fail verification'

# Expected output:
# [RESULT] Signature INVALID - Document may have been tampered.
