#!/usr/bin/env python3
"""End-to-end benchmark for the real Odoo ir.attachment secure-storage path.

This is an opt-in staging tool. It creates temporary ir.attachment records,
reads their datas back through Odoo, verifies SHA-256, and deletes the records.
Use a dedicated disposable database and a non-production Odoo instance.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import platform
import statistics
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path


def load_project_env():
    """Load simple KEY=VALUE entries from the Odoo project-root .env.

    Existing process environment variables take precedence. This deliberately
    supports plain dotenv assignments only; it does not execute shell syntax,
    expand variables, or print secret values.
    """
    configured = os.getenv("ODOO_BENCH_ENV_FILE")
    if configured:
        env_path = Path(configured).expanduser()
    else:
        # scripts/ -> addon -> server_custom -> Odoo-17 project root
        env_path = Path(__file__).resolve().parents[3] / ".env"

    if not env_path.is_file():
        return None

    for raw_line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)

    return str(env_path)


class BenchmarkError(RuntimeError):
    pass


class OdooClient:
    def __init__(self, base_url, database, username, password, timeout):
        self.base_url = base_url.rstrip("/")
        self.database = database
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self._request_id = 0
        self._lock = threading.Lock()
        self.uid = None

    def _post_json(self, path, payload):
        self._request_id += 1
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise BenchmarkError(
                "Odoo HTTP {} at {}: {}".format(exc.code, path, detail)
            ) from exc
        except Exception as exc:
            raise BenchmarkError(
                "Odoo request failed at {}: {}".format(path, exc)
            ) from exc

        if body.get("error"):
            error = body["error"]
            data = error.get("data") or {}
            raise BenchmarkError(
                "Odoo RPC error at {}: {}".format(
                    path, data.get("message") or error.get("message") or error
                )
            )
        return body.get("result")

    def login(self):
        result = self._post_json(
            "/web/session/authenticate",
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "db": self.database,
                    "login": self.username,
                    "password": self.password,
                },
                "id": self._request_id + 1,
            },
        )
        if not result or not result.get("uid"):
            raise BenchmarkError("Odoo authentication failed.")
        self.uid = result["uid"]
        return self.uid

    def call_kw(self, model, method, args, kwargs=None):
        if not self.uid:
            self.login()
        path = "/web/dataset/call_kw/{}/{}".format(model, method)
        return self._post_json(
            path,
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "model": model,
                    "method": method,
                    "args": args,
                    "kwargs": kwargs or {},
                },
                "id": self._request_id + 1,
            },
        )


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def build_payload(size_bytes, seed):
    # Deterministic non-sensitive bytes; generation time is excluded from API timings.
    block = hashlib.sha256(seed.encode("utf-8")).digest() * 1024
    repeats, remainder = divmod(size_bytes, len(block))
    return block * repeats + block[:remainder]


def run_case(base_url, database, username, password, timeout,
             size_mib, concurrency, worker_index, run_index):
    client = OdooClient(base_url, database, username, password, timeout)
    client.login()

    size_bytes = size_mib * 1024 * 1024
    payload = build_payload(
        size_bytes, "odoo-secure-benchmark-{}-{}".format(worker_index, run_index)
    )
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    encoded = base64.b64encode(payload).decode("ascii")
    name = "secure-storage-benchmark-{}-{}-{}.bin".format(
        os.getpid(), worker_index, uuid.uuid4().hex[:12]
    )
    attachment_id = None
    result = {
        "size_mib": size_mib,
        "concurrency": concurrency,
        "worker": worker_index,
        "run": run_index,
        "expected_sha256": expected_sha256,
        "integrity_passed": False,
    }

    try:
        started = time.perf_counter()
        attachment_id = client.call_kw(
            "ir.attachment",
            "create",
            [{
                "name": name,
                "type": "binary",
                "mimetype": "application/octet-stream",
                "datas": encoded,
            }],
        )
        upload_elapsed = time.perf_counter() - started
        if not isinstance(attachment_id, int):
            raise BenchmarkError("Odoo did not return an attachment ID.")

        started = time.perf_counter()
        records = client.call_kw(
            "ir.attachment",
            "read",
            [[attachment_id], ["datas", "file_size", "store_fname"]],
        )
        download_elapsed = time.perf_counter() - started
        if not records:
            raise BenchmarkError("Odoo returned no attachment during download.")

        downloaded = base64.b64decode(records[0].get("datas") or "", validate=True)
        actual_sha256 = hashlib.sha256(downloaded).hexdigest()
        integrity = (
            len(downloaded) == size_bytes and actual_sha256 == expected_sha256
        )
        result.update({
            "attachment_id": attachment_id,
            "upload_seconds": upload_elapsed,
            "download_seconds": download_elapsed,
            "upload_mib_per_second": size_mib / upload_elapsed if upload_elapsed else None,
            "download_mib_per_second": size_mib / download_elapsed if download_elapsed else None,
            "downloaded_bytes": len(downloaded),
            "actual_sha256": actual_sha256,
            "integrity_passed": integrity,
            "store_fname_prefix": (records[0].get("store_fname") or "")[:24],
        })
        if not integrity:
            raise BenchmarkError(
                "Integrity mismatch for attachment {}.".format(attachment_id)
            )
        return result
    finally:
        if attachment_id is not None:
            client.call_kw("ir.attachment", "unlink", [[attachment_id]])


def summarize(rows):
    output = {}
    cases = sorted({(row["size_mib"], row["concurrency"]) for row in rows})
    for size, concurrency in cases:
        selected = [
            row for row in rows
            if row["size_mib"] == size and row["concurrency"] == concurrency
        ]
        for operation in ("upload", "download"):
            samples = [row[operation + "_seconds"] for row in selected]
            throughput = [
                row[operation + "_mib_per_second"]
                for row in selected
                if row.get(operation + "_mib_per_second") is not None
            ]
            output["{}MiB_c{}_{}".format(size, concurrency, operation)] = {
                "samples": len(samples),
                "latency_seconds_p50": statistics.median(samples),
                "latency_seconds_p95": percentile(samples, 0.95),
                "latency_seconds_p99": percentile(samples, 0.99),
                "throughput_mib_per_second_median": statistics.median(throughput),
            }
    return output


def main():
    env_file = load_project_env()
    if env_file:
        print("Loaded benchmark environment from: {}".format(env_file), flush=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("ODOO_BENCH_URL", "http://127.0.0.1:8069"))
    parser.add_argument("--database", default=os.getenv("ODOO_BENCH_DB"))
    parser.add_argument("--username", default=os.getenv("ODOO_BENCH_USERNAME"))
    parser.add_argument("--password", default=os.getenv("ODOO_BENCH_PASSWORD"))
    parser.add_argument("--sizes-mib", default="1,16,64")
    parser.add_argument("--concurrency", default="1,5")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--output", default="benchmark-results/odoo-e2e.json")
    parser.add_argument(
        "--confirm-dedicated-db", action="store_true",
        help="Required because this benchmark creates and deletes ir.attachment records.",
    )
    args = parser.parse_args()

    if not args.confirm_dedicated_db:
        parser.error("Refusing to run without --confirm-dedicated-db.")
    if not all((args.database, args.username, args.password)):
        parser.error("Provide database, username and password via flags or ODOO_BENCH_* environment variables.")
    if args.iterations < 1 or args.timeout < 1:
        parser.error("--iterations and --timeout must be positive.")

    sizes = [int(item) for item in args.sizes_mib.split(",") if item.strip()]
    concurrencies = [int(item) for item in args.concurrency.split(",") if item.strip()]
    if not sizes or any(size < 1 for size in sizes):
        parser.error("--sizes-mib must contain positive integers.")
    if not concurrencies or any(value < 1 for value in concurrencies):
        parser.error("--concurrency must contain positive integers.")

    # Authenticate before generating load so configuration errors fail fast.
    OdooClient(args.url, args.database, args.username, args.password, args.timeout).login()

    rows = []
    failures = []
    for size in sizes:
        for concurrency in concurrencies:
            jobs = [
                (size, worker, iteration)
                for iteration in range(args.iterations)
                for worker in range(concurrency)
            ]
            started = time.perf_counter()
            case_successes = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [
                    pool.submit(
                        run_case, args.url, args.database, args.username,
                        args.password, args.timeout, case_size, concurrency, worker, iteration
                    )
                    for case_size, worker, iteration in jobs
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        rows.append(future.result())
                        case_successes += 1
                    except Exception as exc:
                        failures.append({
                            "size_mib": size,
                            "concurrency": concurrency,
                            "error": str(exc),
                        })
            elapsed = time.perf_counter() - started
            print(
                "size={}MiB concurrency={} completed={} failed={} wall={:.2f}s".format(
                    size, concurrency,
                    case_successes,
                    len(failures), elapsed
                ),
                flush=True,
            )

    report = {
        "benchmark": "odoo-ir-attachment-secure-storage-e2e",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": platform.platform(),
        "python": platform.python_version(),
        "odoo_url": args.url,
        "database": args.database,
        "sizes_mib": sizes,
        "concurrency": concurrencies,
        "iterations_per_worker": args.iterations,
        "successful_operations": len(rows),
        "failed_operations": len(failures),
        "all_integrity_checks_passed": bool(rows) and not failures and all(
            row["integrity_passed"] for row in rows
        ),
        "summary": summarize(rows),
        "results": sorted(rows, key=lambda row: (
            row["size_mib"], row["worker"], row["run"]
        )),
        "failures": failures,
        "notes": [
            "Measures Odoo JSON-RPC ir.attachment create/read, including API/base64 overhead.",
            "The addon path logs Vault, MinIO and crypto stage timings in the Odoo server log.",
            "This client does not measure Odoo worker RSS; collect worker RSS/CPU with OS monitoring.",
            "Each successful test attachment is deleted after verification.",
            "Use only a dedicated staging database and bucket; never run against production.",
        ],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "successful_operations": len(rows),
        "failed_operations": len(failures),
        "all_integrity_checks_passed": report["all_integrity_checks_passed"],
        "summary": report["summary"],
    }, indent=2))
    if failures or not report["all_integrity_checks_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
