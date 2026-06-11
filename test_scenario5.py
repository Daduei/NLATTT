# test_scenario5.py
def test_binary_file_signing():
    with tempfile.TemporaryDirectory() as tmp:
        generate_key_pair(priv, pub)

        # Create a fake binary file (simulating a PDF header)
        bin_doc = os.path.join(tmp, 'report.bin')
        bin_sig = os.path.join(tmp, 'report.bin.sig')
        with open(bin_doc, 'wb') as f:
            f.write(b'%PDF-1.4\x00\x01\x02\x03' + b'\xFF' * 100)

        sign_document(bin_doc, priv, bin_sig)
        result = verify_signature(bin_doc, bin_sig, pub)
        assert result == True, 'Binary file signature must be valid'

# Expected output:
# [RESULT] Signature VALID - Document is authentic and unmodified.
