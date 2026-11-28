# Streaming performance benchmark

## Scope

The benchmark script measures the existing AES-256-GCM chunked streaming engine using files on local disk. It verifies restored file size and SHA-256 after every run and records encryption/decryption throughput plus Python-traced peak allocations.

It does **not** measure Odoo HTTP/controller overhead, PostgreSQL, MinIO network/disk latency, Vault Transit latency, concurrent users, or production hardware behavior. Do not present its results as end-to-end production capacity.

## Run

Run from the addon directory using the same Python environment as Odoo. The script loads the encryption engine directly and does not initialize an Odoo registry.

Windows PowerShell:

~~~powershell
cd D:\Code\Odoo\Odoo-17\server_custom\odoo_secure_object_storage
..\..\.venv\Scripts\python.exe .\scripts\benchmark_streaming.py --sizes-mib 1,16,64,256 --iterations 3 --chunk-size-mib 4 --output .\benchmark-results\windows-dev.json
~~~

Linux (adjust the virtualenv path to the deployment):

~~~bash
cd /opt/odoo17/server_custom/odoo_secure_object_storage
/opt/odoo17/venv/bin/python scripts/benchmark_streaming.py \
  --sizes-mib 1,16,64,256 --iterations 3 --chunk-size-mib 4 \
  --output benchmark-results/linux-staging.json
~~~

The output directory must exist before running. For example:

~~~powershell
New-Item -ItemType Directory -Force .\benchmark-results
~~~

Start with the default 4 MiB chunk size. Repeat with 1, 8 and 16 MiB only as a controlled comparison. Use the same host, Python version, storage device, power profile and workload sizes when comparing results. Run at least three iterations; use medians rather than the fastest result.

## Required benchmark matrix

Record results for at least:

- 1 MiB: small-file overhead.
- 16 MiB: several chunks at the default chunk size.
- 64 MiB: sustained multi-chunk processing.
- 256 MiB or larger: sustained throughput and allocation behavior.

For a production qualification, also test the largest expected attachment and a representative concurrent workload in staging. Capture CPU utilization, resident memory, disk I/O, MinIO request latency, Vault Transit latency, Odoo worker count and HTTP response latency using the organization's monitoring stack.

## End-to-end staging measurements

Use non-sensitive files and a dedicated staging bucket/database. For each size and concurrency level, perform actual Odoo upload and download operations and verify the downloaded SHA-256 against the source. Record separate timings for:
1. Odoo request duration.
2. DEK generation and Vault wrap/unwrap.
3. AES-GCM encryption/decryption.
4. MinIO PUT/GET duration and bytes transferred.
5. PostgreSQL transaction duration.
6. End-to-end upload/download duration.

Test concurrency levels 1, 5 and 10 initially, then increase only within the staging resource limits. Include warm-up runs, at least 3 measured runs per case, and report p50/p95/p99 where sample volume supports percentiles. Do not run load tests against production without an approved change window.

## Acceptance record

Keep the JSON benchmark report with the exact addon commit, host specifications, Odoo/Python/cryptography/MinIO versions, chunk size, test date, file sizes, iterations and integrity results. A benchmark is invalid if any integrity check fails. Establish throughput and latency thresholds with the infrastructure team before claiming acceptance.
