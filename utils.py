"""
utils.py — Visual output helpers for demos and attack simulations.

Provides hex dumps, digest comparisons, and formatted tables so the
console output is readable and useful for presentations / grading.
"""

import hashlib
import textwrap


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_hex(data):
    """Compute SHA-256 digest and return as a 64-character hex string."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hex dump (like xxd / hexdump — shows raw bytes in human-readable form)
# ---------------------------------------------------------------------------

def hex_dump(data, width=16, max_bytes=64):
    """Return a formatted hex dump of binary data (first max_bytes shown)."""
    lines = []
    truncated = data[:max_bytes]
    for offset in range(0, len(truncated), width):
        chunk = truncated[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Printable ASCII on the right; non-printable bytes shown as '.'
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


def print_hex_dump(label, data, max_bytes=64):
    """Print a labeled hex dump to stdout."""
    print(f"\n{label}:")
    print(hex_dump(data, max_bytes=max_bytes))


# ---------------------------------------------------------------------------
# Tamper detection visuals
# ---------------------------------------------------------------------------

def print_digest_comparison(original_data, tampered_data):
    """
    Show SHA-256 digests side-by-side.
    Even a one-character change produces a completely different digest (avalanche effect).
    """
    orig_digest = sha256_hex(original_data)
    tamper_digest = sha256_hex(tampered_data)

    print("\n" + "=" * 60)
    print("SHA-256 DIGEST COMPARISON")
    print("=" * 60)
    print(f"  Original : {orig_digest}")
    print(f"  Tampered : {tamper_digest}")
    print(f"  Match    : {'YES (unexpected!)' if orig_digest == tamper_digest else 'NO  (tampering detected)'}")

    # Count how many hex characters differ (out of 64 total)
    diffs = [i for i, (a, b) in enumerate(zip(orig_digest, tamper_digest)) if a != b]
    if diffs:
        print(f"  Diff at  : {len(diffs)} hex character positions out of 64")
    print("=" * 60)


def print_signature_inspection(sig_bytes, algorithm):
    """Print signature size, first/last bytes, and a hex dump preview."""
    print(f"\n--- Signature Inspection ({algorithm}) ---")
    print(f"  Size       : {len(sig_bytes)} bytes")
    print(f"  First 16 B : {sig_bytes[:16].hex()}")
    print(f"  Last  16 B : {sig_bytes[-16:].hex()}")
    print_hex_dump("  Full dump (first 64 B)", sig_bytes)


# ---------------------------------------------------------------------------
# Table formatting (used by benchmark and algorithm comparison)
# ---------------------------------------------------------------------------

def print_table(headers, rows):
    """Print a simple aligned text table with auto-sized columns."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "  ".join("-" * w for w in col_widths)
    print(fmt.format(*headers))
    print(separator)
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


def wrap_text(text, width=70):
    """Wrap long text lines for console output."""
    return textwrap.fill(text, width=width)
