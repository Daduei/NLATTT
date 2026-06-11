"""
benchmark.py — Performance comparison across signing algorithms.

Measures average signing and verification time over N iterations for:
  RSA-PKCS1v15, RSA-PSS, and ECDSA-P-256.

Run standalone:  py benchmark.py
Or via main.py:  STEP 6 of the full demo
"""

import os
import time
import tempfile

from algorithms import RSA_PKCS1V15, RSA_PSS, ECDSA_P256, ALL_ALGORITHMS, ALGORITHM_INFO
from keygen import generate_rsa_key_pair, generate_ecdsa_key_pair
from signer import _sign_bytes, _load_private_key
from verifier import _verify_bytes, _load_public_key
from utils import print_table


# Number of sign/verify operations per algorithm (higher = more stable average)
ITERATIONS = 100

# Fixed-size random payload so all algorithms sign the same amount of data
SAMPLE_DATA = b"NEU benchmark payload: " + os.urandom(256)


def _time_call(func, iterations):
    """
    Run func() repeatedly and return average time per call in milliseconds.
    Uses time.perf_counter() for high-resolution timing.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start
    return (elapsed / iterations) * 1000  # convert seconds to ms


def benchmark_algorithm(algorithm, private_key_path, public_key_path, iterations=ITERATIONS):
    """
    Benchmark one algorithm: measure sign and verify time, record signature size.
    Pre-generates one signature for the verify loop (verify always uses same sig).
    """
    private_key = _load_private_key(private_key_path)
    public_key = _load_public_key(public_key_path)

    # Warm-up signature used by the verify benchmark
    signature = _sign_bytes(private_key, SAMPLE_DATA, algorithm)

    sign_ms = _time_call(
        lambda: _sign_bytes(private_key, SAMPLE_DATA, algorithm), iterations
    )
    verify_ms = _time_call(
        lambda: _verify_bytes(public_key, signature, SAMPLE_DATA, algorithm), iterations
    )

    key_bits = 2048 if "RSA" in ALGORITHM_INFO[algorithm]["key_type"] else 256
    return {
        "algorithm": algorithm,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "sig_bytes": len(signature),
        "key_bits": key_bits,
    }


def run_benchmark(iterations=ITERATIONS):
    """
    Run the full benchmark suite:
      1. Generate temporary RSA and ECDSA key pairs
      2. Benchmark all three algorithms
      3. Print results table and highlight winners
    """
    print("=" * 70)
    print(f"PERFORMANCE BENCHMARK ({iterations} iterations per operation)")
    print("=" * 70)

    # Use a temp directory so benchmark keys don't overwrite project key files
    with tempfile.TemporaryDirectory() as tmp:
        rsa_priv = os.path.join(tmp, "rsa_priv.pem")
        rsa_pub = os.path.join(tmp, "rsa_pub.pem")
        rsa_cert = os.path.join(tmp, "rsa_cert.pem")
        ecdsa_priv = os.path.join(tmp, "ecdsa_priv.pem")
        ecdsa_pub = os.path.join(tmp, "ecdsa_pub.pem")
        ecdsa_cert = os.path.join(tmp, "ecdsa_cert.pem")

        generate_rsa_key_pair(rsa_priv, rsa_pub, rsa_cert, signer_name="Benchmark RSA")
        generate_ecdsa_key_pair(ecdsa_priv, ecdsa_pub, ecdsa_cert, signer_name="Benchmark ECDSA")

        results = []
        # Map each algorithm to its key file paths
        key_map = {
            RSA_PKCS1V15: (rsa_priv, rsa_pub),   # RSA keys
            RSA_PSS: (rsa_priv, rsa_pub),         # same RSA keys, different padding
            ECDSA_P256: (ecdsa_priv, ecdsa_pub),  # separate EC key pair
        }

        for algo in ALL_ALGORITHMS:
            priv, pub = key_map[algo]
            print(f"\n[...] Benchmarking {algo}...")
            results.append(benchmark_algorithm(algo, priv, pub, iterations))

    # --- Print formatted results table ---
    print("\n")
    print_table(
        ["Algorithm", "Sign (ms)", "Verify (ms)", "Sig Size (B)", "Key (bits)"],
        [
            (r["algorithm"], f"{r['sign_ms']:.3f}", f"{r['verify_ms']:.3f}",
             r["sig_bytes"], r["key_bits"])
            for r in results
        ],
    )

    # Highlight which algorithm wins in each category
    fastest_sign = min(results, key=lambda r: r["sign_ms"])
    fastest_verify = min(results, key=lambda r: r["verify_ms"])
    print(f"\nFastest signing  : {fastest_sign['algorithm']} ({fastest_sign['sign_ms']:.3f} ms)")
    print(f"Fastest verify   : {fastest_verify['algorithm']} ({fastest_verify['verify_ms']:.3f} ms)")
    smallest = min(results, key=lambda r: r["sig_bytes"])
    print(f"Smallest sig     : {smallest['algorithm']} ({smallest['sig_bytes']} bytes)")

    return results


if __name__ == "__main__":
    run_benchmark()
