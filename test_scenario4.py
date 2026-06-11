# test_scenario4.py
def test_signature_not_reusable():
    with tempfile.TemporaryDirectory() as tmp:
        generate_key_pair(priv, pub)

        # Sign document A
        doc_a = os.path.join(tmp, 'doc_a.txt')
        sig_a = os.path.join(tmp, 'doc_a.sig')
        with open(doc_a, 'w') as f:
            f.write('Document A: Approved.')
        sign_document(doc_a, priv, sig_a)

        # Try to use signature A to verify document B
        doc_b = os.path.join(tmp, 'doc_b.txt')
        with open(doc_b, 'w') as f:
            f.write('Document B: Transfer $1,000,000.')

        result = verify_signature(doc_b, sig_a, pub)
        assert result == False, 'Signature from doc A cannot validate doc B'

# Expected output:
# [RESULT] Signature INVALID - Document may have been tampered.
