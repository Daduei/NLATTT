"""
main.py — Full digital signature security demonstration.

Orchestrates the complete demo pipeline:
  STEP 1: Generate RSA + ECDSA key pairs and X.509 certificates
  STEP 2: Create a test document
  STEP 3: Sign with all three algorithms (RSA-PKCS1v15, RSA-PSS, ECDSA-P-256)
  STEP 4: Verify all signatures (should pass)
  STEP 5: Tamper test — modify document and verify again (should fail)
  STEP 6: Performance benchmark (100 iterations per algorithm)
  STEP 7: Man-in-the-Middle attack simulation

Run:  py main.py
"""

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256, ALL_ALGORITHMS, ALGORITHM_INFO
from keygen import generate_all_key_pairs, get_key_paths
from signer import sign_document
from verifier import verify_signature
from benchmark import run_benchmark
from mitm_demo import simulate_mitm_attack
from utils import print_table

# Output file paths used throughout the demo
DOCUMENT = "test_document.txt"
TAMPERED_DOC = "tampered_document.txt"


def _banner(title):
    """Print a section header banner."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def create_test_document(path):
    """Create a sample official document for signing."""
    content = (
        "This is an official document issued by NEU.\n"
        "Amount: 1,000,000 VND\n"
        "Authorized by: Dean of Faculty\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[OK] Document created: {path}")
    return content


def create_tampered_document(path, original_content):
    """
    Simulate an attacker changing the transfer amount.
    Returns the tampered content so callers can inspect it.
    """
    tampered = original_content.replace("1,000,000", "9,000,000")
    with open(path, "w", encoding="utf-8") as f:
        f.write(tampered)
    print("[ATTACKER] Document tampered: amount changed from 1M to 9M VND")
    return tampered


def demo_algorithm_comparison():
    """
    Steps 1–5: key generation, signing, verification, and tamper detection
    across all three algorithms.
    """
    # STEP 1: Generate keys and issue X.509 certificates
    _banner("STEP 1: Key Generation + X.509 Certificates")
    generate_all_key_pairs(signer_name="Dean of Faculty")

    # STEP 2: Create the document to be signed
    _banner("STEP 2: Create Test Document")
    original = create_test_document(DOCUMENT)

    # STEP 3: Sign the same document with each algorithm
    _banner("STEP 3: Sign with All Three Algorithms")
    sig_files = {}
    for algo in ALL_ALGORITHMS:
        priv, pub, cert = get_key_paths(algo)
        sig_path = f"{DOCUMENT}.{algo.lower().replace('-', '_')}.sig"
        print(f"\n--- Signing with {algo} ---")
        sign_document(DOCUMENT, priv, sig_path, algorithm=algo, cert_path=cert)
        sig_files[algo] = sig_path

    # STEP 4: Verify all signatures against the original document
    _banner("STEP 4: Verify All Signatures (should PASS)")
    for algo in ALL_ALGORITHMS:
        _, pub, cert = get_key_paths(algo)
        print(f"\n--- Verifying {algo} ---")
        verify_signature(DOCUMENT, sig_files[algo], pub, cert_path=cert)

    # STEP 5: Tamper the document and verify again (all should fail)
    _banner("STEP 5: Tamper Test Across All Algorithms")
    create_tampered_document(TAMPERED_DOC, original)
    for algo in ALL_ALGORITHMS:
        _, pub, cert = get_key_paths(algo)
        print(f"\n--- Verifying tampered doc with {algo} signature ---")
        verify_signature(TAMPERED_DOC, sig_files[algo], pub, cert_path=cert)

    # Summary table comparing the three algorithms
    _banner("ALGORITHM COMPARISON SUMMARY")
    print_table(
        ["Algorithm", "Key Type", "Expected Sig Size"],
        [
            (a, ALGORITHM_INFO[a]["key_type"], ALGORITHM_INFO[a]["expected_sig_bytes"])
            for a in ALL_ALGORITHMS
        ],
    )


def main():
    print("=" * 70)
    print("  DIGITAL SIGNATURE SECURITY DEMONSTRATION")
    print("  Algorithms: RSA-PKCS1v15 | RSA-PSS | ECDSA-P-256")
    print("=" * 70)

    demo_algorithm_comparison()

    # STEP 6: Measure signing/verification speed across 100 iterations
    _banner("STEP 6: Performance Benchmark (100 iterations)")
    run_benchmark(iterations=100)

    # STEP 7: Simulate a MITM attack with printed forensic evidence
    _banner("STEP 7: Man-in-the-Middle Attack Simulation")
    simulate_mitm_attack(algorithm=RSA_PKCS1V15)

    print("\n" + "=" * 70)
    print("  DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
