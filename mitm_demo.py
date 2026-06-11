"""
mitm_demo.py — Man-in-the-Middle (MITM) attack simulation.

Demonstrates how digital signatures detect document tampering in transit:

  Phase 1 — Alice signs an official transfer document
  Phase 2 — Attacker intercepts and changes the amount (keeps original .sig)
  Phase 3 — Bob verifies and the signature correctly fails

Prints forensic evidence: digests, hex dumps, and character-level diffs.
"""

import os
import tempfile

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256
from keygen import generate_rsa_key_pair, generate_ecdsa_key_pair
from signer import sign_document
from verifier import verify_signature
from utils import sha256_hex, print_digest_comparison, print_hex_dump


def _banner(title):
    """Print a section header banner."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def simulate_mitm_attack(algorithm=RSA_PKCS1V15):
    """
    Simulate a MITM attack for one algorithm:
      1. Alice signs an official document
      2. Attacker intercepts and modifies the amount
      3. Bob receives the tampered document with the original signature
      4. Verification fails — digests and evidence are printed
    """
    _banner(f"MITM ATTACK SIMULATION — {algorithm}")

    with tempfile.TemporaryDirectory() as tmp:
        # File paths for Alice's keys, document, and signature
        priv = os.path.join(tmp, "alice_priv.pem")
        pub = os.path.join(tmp, "alice_pub.pem")
        cert = os.path.join(tmp, "alice_cert.pem")
        original_doc = os.path.join(tmp, "contract.txt")
        tampered_doc = os.path.join(tmp, "contract_tampered.txt")
        sig = os.path.join(tmp, "contract.sig")

        # Generate the appropriate key pair for this algorithm
        if algorithm == ECDSA_P256:
            generate_ecdsa_key_pair(priv, pub, cert, signer_name="Alice (NEU Dean)")
        else:
            generate_rsa_key_pair(priv, pub, cert, signer_name="Alice (NEU Dean)")

        # The official document Alice intends to send
        original_content = (
            "OFFICIAL TRANSFER AUTHORIZATION\n"
            "From: National Economics University\n"
            "To:   Student Scholarship Fund\n"
            "Amount: 1,000,000 VND\n"
            "Authorized by: Dean of Faculty\n"
        )
        # Attacker changes only the amount — a realistic fraud scenario
        tampered_content = original_content.replace("1,000,000", "9,000,000")

        # ------------------------------------------------------------------
        # PHASE 1: Alice signs the original document
        # ------------------------------------------------------------------
        _banner("PHASE 1: Alice signs the original document")
        with open(original_doc, "w", encoding="utf-8") as f:
            f.write(original_content)
        print(original_content)
        orig_bytes = original_content.encode()
        print(f"\n[ALICE] SHA-256 digest: {sha256_hex(orig_bytes)}")
        print_hex_dump("Original document bytes", orig_bytes)

        sign_document(original_doc, priv, sig, algorithm=algorithm, cert_path=cert)

        # ------------------------------------------------------------------
        # PHASE 2: Attacker intercepts and modifies the document in transit
        # ------------------------------------------------------------------
        _banner("PHASE 2: Attacker (MITM) intercepts the transmission")
        print("[ATTACKER] Intercepted document in transit (Alice -> Bob)")
        print("[ATTACKER] Modified: Amount changed from 1,000,000 to 9,000,000 VND")
        print("[ATTACKER] Replaced document content, kept original signature file")
        with open(tampered_doc, "w", encoding="utf-8") as f:
            f.write(tampered_content)
        tamper_bytes = tampered_content.encode()
        print(f"\n[ATTACKER] New SHA-256 digest: {sha256_hex(tamper_bytes)}")
        print_hex_dump("Tampered document bytes", tamper_bytes)

        # Show that even a small text change completely alters the digest
        print_digest_comparison(orig_bytes, tamper_bytes)

        # Pinpoint exactly which characters the attacker changed
        print("\n[FORENSIC] Character-level diff in document text:")
        for i, (a, b) in enumerate(zip(original_content, tampered_content)):
            if a != b:
                print(f"  Position {i}: '{a}' -> '{b}'")

        # ------------------------------------------------------------------
        # PHASE 3: Bob verifies the received (tampered) document
        # ------------------------------------------------------------------
        _banner("PHASE 3: Bob verifies the received document")
        print("[BOB] Received tampered document + original signature from attacker")
        result = verify_signature(tampered_doc, sig, pub, cert_path=cert)

        _banner("ATTACK RESULT")
        if result:
            print("[!!] UNEXPECTED: Tampered document passed verification!")
        else:
            print("[OK] Attack BLOCKED — Digital signature detected the tampering.")
            print("     The SHA-256 digest changed, so the signature no longer matches.")
            print("     Bob knows the document was modified in transit.")

        return result


def run_all_mitm_demos():
    """Run the MITM simulation for all three algorithms."""
    for algo in [RSA_PKCS1V15, RSA_PSS, ECDSA_P256]:
        simulate_mitm_attack(algo)


if __name__ == "__main__":
    run_all_mitm_demos()
