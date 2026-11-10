"""Benchmark for RSA-PSS/SHA-256 signing and verification (report, Section 3.5).

Measures average in-memory sign/verify time for 1 KB, 1 MB and 10 MB inputs,
10 repetitions each. Disk I/O and network transfer are not included.
Results depend on hardware, OS, Python and cryptography versions.
"""
from __future__ import annotations

import platform
import time

import cryptography

from signer import generate_key_pair, sign, verify

SIZES = (1024, 1024 * 1024, 10 * 1024 * 1024)
REPEATS = 10


def benchmark(private_key, public_key, sizes=SIZES, repeats=REPEATS):
    rows = []
    for size in sizes:
        data = b"A" * size
        sign_times, verify_times = [], []
        for _ in range(repeats):
            start = time.perf_counter()
            signature = sign(data, private_key)
            sign_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            valid = verify(data, signature, public_key)
            verify_times.append(time.perf_counter() - start)
            if not valid:
                raise RuntimeError("Benchmark verification unexpectedly failed")
        rows.append((size, sum(sign_times) / repeats, sum(verify_times) / repeats))
    return rows


def main() -> int:
    private_key, public_key = generate_key_pair()
    print(f"Platform: {platform.platform()}")
    print(f"Python: {platform.python_version()}  cryptography: {cryptography.__version__}")
    print(f"Average in-memory timing ({REPEATS} repetitions):")
    print("Size (bytes) | Signing (ms) | Verification (ms)")
    for size, sign_s, verify_s in benchmark(private_key, public_key):
        print(f"{size:>12} | {sign_s * 1000:>12.3f} | {verify_s * 1000:>16.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
