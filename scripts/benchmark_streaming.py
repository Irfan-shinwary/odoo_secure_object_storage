#!/usr/bin/env python3
"""Bounded-memory AES-GCM streaming benchmark for the Odoo secure storage addon.

This benchmark measures the addon's streaming encryption/decryption engine.
It deliberately does not claim to measure Odoo, PostgreSQL, MinIO network,
Vault Transit latency, or concurrent production traffic.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path


ADDON_ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = ADDON_ROOT / "services" / "streaming_encryption.py"
SPEC = importlib.util.spec_from_file_location(
    "secure_storage_streaming_encryption", ENGINE_PATH
)
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)


def write_random_file(path, size, block_size):
    digest = hashlib.sha256()
    remaining = size
    with path.open("wb") as output:
        while remaining:
            block = os.urandom(min(block_size, remaining))
            output.write(block)
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def hash_file(path, block_size):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def write_encrypted(source_path, encrypted_path, key, object_id, size, digest, chunk_size):
    started = time.perf_counter()
    with source_path.open("rb") as source, encrypted_path.open("wb") as output:
        for block in ENGINE.encrypt_stream(
            source=source,
            key=key,
            document_id=object_id,
            plaintext_size=size,
            plaintext_sha256=digest,
            chunk_size=chunk_size,
        ):
            output.write(block)
    return time.perf_counter() - started


def write_decrypted(encrypted_path, output_path, key, object_id, size, digest):
    started = time.perf_counter()
    with encrypted_path.open("rb") as source, output_path.open("wb") as output:
        for block in ENGINE.decrypt_stream(
            source=source,
            key=key,
            document_id=object_id,
            expected_size=size,
            expected_sha256=digest,
        ):
            output.write(block)
    return time.perf_counter() - started


def run_case(size_bytes, iteration, chunk_size, workdir, io_block_size):
    source_path = workdir / "source.bin"
    encrypted_path = workdir / "encrypted.bin"
    restored_path = workdir / "restored.bin"
    object_id = "benchmark-" + os.urandom(8).hex()
    key = os.urandom(32)

    digest = write_random_file(source_path, size_bytes, io_block_size)

    tracemalloc.start()
    encryption_seconds = write_encrypted(
        source_path, encrypted_path, key, object_id,
        size_bytes, digest, chunk_size,
    )
    _current, encryption_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    decryption_seconds = write_decrypted(
        encrypted_path, restored_path, key, object_id,
        size_bytes, digest,
    )
    _current, decryption_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if restored_path.stat().st_size != size_bytes:
        raise RuntimeError("Restored file size does not match source.")
    if hash_file(restored_path, io_block_size) != digest:
        raise RuntimeError("Restored file SHA-256 does not match source.")

    encrypted_size = encrypted_path.stat().st_size
    return {
        "size_bytes": size_bytes,
        "iteration": iteration,
        "chunk_size_bytes": chunk_size,
        "encrypted_size_bytes": encrypted_size,
        "encryption_seconds": round(encryption_seconds, 6),
        "decryption_seconds": round(decryption_seconds, 6),
        "encryption_mib_per_second": round(
            size_bytes / (1024 * 1024) / encryption_seconds, 3
        ) if encryption_seconds else None,
        "decryption_mib_per_second": round(
            size_bytes / (1024 * 1024) / decryption_seconds, 3
        ) if decryption_seconds else None,
        "encryption_python_peak_bytes": encryption_peak,
        "decryption_python_peak_bytes": decryption_peak,
        "integrity_verified": True,
    }


def parse_sizes(value):
    try:
        sizes = [int(item.strip()) for item in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Sizes must be comma-separated integers in MiB.") from exc
    if not sizes or any(size < 0 for size in sizes):
        raise argparse.ArgumentTypeError("Sizes must be non-negative MiB values.")
    return sizes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes-mib", type=parse_sizes, default=[1, 16, 64, 256],
                        help="Comma-separated plaintext sizes in MiB (default: 1,16,64,256).")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--chunk-size-mib", type=int, default=4)
    parser.add_argument("--io-block-size-mib", type=int, default=1)
    parser.add_argument("--output", default="secure-storage-benchmark.json")
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be at least 1.")
    if args.chunk_size_mib < 1 or args.chunk_size_mib > 16:
        parser.error("--chunk-size-mib must be between 1 and 16.")
    if args.io_block_size_mib < 1:
        parser.error("--io-block-size-mib must be at least 1.")

    chunk_size = args.chunk_size_mib * 1024 * 1024
    io_block_size = args.io_block_size_mib * 1024 * 1024
    results = []

    print("Secure Storage Streaming Benchmark")
    print(f"Python: {sys.version.split()[0]} | OS: {platform.platform()}")
    print(f"Chunk size: {args.chunk_size_mib} MiB | Iterations: {args.iterations}")

    with tempfile.TemporaryDirectory(prefix="odoo-secure-benchmark-") as temp:
        workdir = Path(temp)
        for size_mib in args.sizes_mib:
            size_bytes = size_mib * 1024 * 1024
            for iteration in range(1, args.iterations + 1):
                result = run_case(
                    size_bytes, iteration, chunk_size, workdir, io_block_size
                )
                results.append(result)
                print(
                    f"{size_mib:>6} MiB run {iteration}: "
                    f"enc={result['encryption_mib_per_second']} MiB/s, "
                    f"dec={result['decryption_mib_per_second']} MiB/s, "
                    f"integrity={'PASS' if result['integrity_verified'] else 'FAIL'}"
                )

    summaries = []
    for size_mib in args.sizes_mib:
        group = [row for row in results if row["size_bytes"] == size_mib * 1024 * 1024]
        summaries.append({
            "size_mib": size_mib,
            "runs": len(group),
            "encryption_mib_per_second_median": round(
                statistics.median(row["encryption_mib_per_second"] for row in group), 3
            ),
            "decryption_mib_per_second_median": round(
                statistics.median(row["decryption_mib_per_second"] for row in group), 3
            ),
            "max_python_peak_bytes": max(
                max(row["encryption_python_peak_bytes"], row["decryption_python_peak_bytes"])
                for row in group
            ),
        })

    report = {
        "benchmark": "odoo_secure_object_storage_streaming_crypto",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "chunk_size_bytes": chunk_size,
        "iterations": args.iterations,
        "scope": "AES-GCM streaming engine only; excludes Odoo, PostgreSQL, MinIO and Vault.",
        "all_integrity_checks_passed": all(row["integrity_verified"] for row in results),
        "summaries": summaries,
        "results": results,
    }

    output_path = Path(args.output).resolve()
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nJSON report: {output_path}")
    if not report["all_integrity_checks_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
