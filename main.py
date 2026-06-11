import os
from keygen   import generate_key_pair
from signer   import sign_document
from verifier import verify_signature

DOCUMENT      = 'test_document.txt'
PRIVATE_KEY   = 'private_key.pem'
PUBLIC_KEY    = 'public_key.pem'
SIGNATURE     = 'test_document.txt.sig'
TAMPERED_DOC  = 'tampered_document.txt'

# --- STEP 1: Key Generation ---
print('='*55)
print('STEP 1: Generating RSA-2048 Key Pair')
print('='*55)
generate_key_pair(PRIVATE_KEY, PUBLIC_KEY)

# --- STEP 2: Create test document ---
print()
print('='*55)
print('STEP 2: Creating Test Document')
print('='*55)
with open(DOCUMENT, 'w') as f:
    f.write('This is an official document issued by NEU.\n')
    f.write('Amount: 1,000,000 VND\n')
    f.write('Authorized by: Dean of Faculty\n')
print(f'[OK] Document created: {DOCUMENT}')

# --- STEP 3: Sign the document ---
print()
print('='*55)
print('STEP 3: Signing Document')
print('='*55)
sign_document(DOCUMENT, PRIVATE_KEY, SIGNATURE)

# --- STEP 4: Verify original (should PASS) ---
print()
print('='*55)
print('STEP 4: Verifying Original Document')
print('='*55)
verify_signature(DOCUMENT, SIGNATURE, PUBLIC_KEY)

# --- STEP 5: Tamper document and verify (should FAIL) ---
print()
print('='*55)
print('STEP 5: Tamper Test - Modifying Document Content')
print('='*55)
with open(TAMPERED_DOC, 'w') as f:
    f.write('This is an official document issued by NEU.\n')
    f.write('Amount: 9,000,000 VND\n')  # <-- malicious change
    f.write('Authorized by: Dean of Faculty\n')
print('[ATTACKER] Document tampered: amount changed from 1M to 9M VND')
verify_signature(TAMPERED_DOC, SIGNATURE, PUBLIC_KEY)
