# End-to-end Odoo attachment benchmark

## What this measures

The scripts/benchmark_odoo_e2e.py tool drives the real Odoo 17 ir.attachment JSON-RPC create/read/unlink workflow. With secure storage enabled, this exercises the addon's current attachment integration, including DEK generation, Vault Transit wrap/unwrap, AES-GCM encryption/decryption, MinIO PUT/GET, PostgreSQL attachment metadata and Odoo RPC/base64 overhead.

The script verifies the downloaded byte count and SHA-256 for every operation and deletes each successfully created attachment in a finally block. It writes a machine-readable JSON report.

**Important implementation limitation:** the current models/ir_attachment.py implementation accepts the attachment as a complete bytes value and reconstructs downloads with b"".join(plaintext_stream). Therefore this benchmark measures the current ir.attachment integration, but it does not establish bounded-memory HTTP streaming for ordinary Odoo attachments. The separate secure.document controller uses a streaming response path. Do not conflate these two paths or claim that this benchmark proves constant-memory attachment delivery.

The script does not instrument Odoo worker RSS itself. Collect worker process RSS and CPU externally on the Odoo host. Per-stage Vault, MinIO and attachment timings are available in the Odoo server logs under the existing SECURE_UPLOAD_PERFORMANCE, SECURE_STORAGE_PERFORMANCE and MINIO_* events. Database timing should be collected from PostgreSQL monitoring/logging if required; request duration is not a direct measurement of transaction duration.

## Safety requirements

- Run only against a disposable staging database and dedicated staging MinIO bucket.
- Use non-sensitive generated data. Never point this at production.
- Enable secure storage in the Odoo process environment and verify the expected bucket and Vault Transit key before testing.
- Use a staging Odoo account that can create, read and delete the test attachments.
- The benchmark requires explicit --confirm-dedicated-db because it creates and deletes records.
- The script deletes records it successfully creates. If a process is forcibly terminated, inspect and remove any remaining secure-storage-benchmark-* attachments from the staging database.
- Start with concurrency 1. Increase to 5 and 10 only after confirming the staging host has sufficient Odoo workers, RAM, CPU, MinIO and Vault capacity.
- Do not run concurrent benchmark processes against the same staging database/bucket.

## Windows PowerShell (development/staging)

Run from the addon directory:

~~~powershell
cd D:\Code\Odoo\Odoo-17\server_custom\odoo_secure_object_storage

$env:ODOO_BENCH_URL = "http://127.0.0.1:8040"
$env:ODOO_BENCH_DB = "secure_storage_benchmark"
$env:ODOO_BENCH_USERNAME = "admin"
$env:ODOO_BENCH_PASSWORD = Read-Host "Staging Odoo password" -AsSecureString |
    ForEach-Object { [System.Net.NetworkCredential]::new("", $_).Password }

New-Item -ItemType Directory -Force .\benchmark-results | Out-Null

..\..\.venv\Scripts\python.exe .\scripts\benchmark_odoo_e2e.py `
    --sizes-mib 1,16,64 `
    --concurrency 1 `
    --iterations 3 `
    --timeout 900 `
    --confirm-dedicated-db `
    --output .\benchmark-results\odoo-e2e-c1.json
~~~

Then, only after reviewing the first report, repeat with --concurrency 5 and --concurrency 10, writing to separate output files. To compare chunk sizes, change the Odoo process's configured chunk size only through the supported addon configuration mechanism (if/when exposed); do not patch source code during a benchmark run. The current production candidate remains 4 MiB.

Clear the password variable after testing:

~~~powershell
Remove-Item Env:ODOO_BENCH_PASSWORD
~~~

## Ubuntu staging

Set the benchmark environment variables in the invoking shell or a protected environment file readable only by the operator. Do not put credentials in shell history or commit them.

~~~bash
cd /opt/odoo17/server_custom/odoo_secure_object_storage
export ODOO_BENCH_URL='http://127.0.0.1:8069'
export ODOO_BENCH_DB='secure_storage_benchmark'
export ODOO_BENCH_USERNAME='admin'
read -rsp 'Staging Odoo password: ' ODOO_BENCH_PASSWORD
export ODOO_BENCH_PASSWORD
echo
mkdir -p benchmark-results

/opt/odoo17/venv/bin/python scripts/benchmark_odoo_e2e.py \
  --sizes-mib 1,16,64 --concurrency 1 --iterations 3 \
  --timeout 900 --confirm-dedicated-db \
  --output benchmark-results/odoo-e2e-c1.json

unset ODOO_BENCH_PASSWORD
~~~

Run concurrency 5 and 10 as separate controlled runs. The exact virtualenv path must match the deployed Odoo Python environment.

## Metrics and interpretation

The JSON report includes per-operation upload/download latency samples, p50/p95/p99 estimates, median MiB/s, byte counts, SHA-256 values, and failures. Each size/concurrency case runs iterations × concurrency independent attachment workflows.

For the Odoo host, capture at least:
- Odoo worker RSS (per process and total) and CPU during each case.
- Odoo worker count, configured memory limits and request limits.
- MinIO PUT/GET latency, throughput, errors and disk/network utilization.
- Vault Transit encrypt/decrypt request latency, errors and CPU.
- PostgreSQL query/transaction latency, connections and resource utilization.
- Odoo request duration and server log stage timings.

For useful p95/p99 values, increase the number of samples (for example, at least 20-30 per case); the default three iterations are a smoke/performance baseline, not a statistically robust tail-latency study. Record host specs, exact addon commit, Odoo/Python/MinIO/Vault/PostgreSQL versions, chunk size, test date and environment configuration alongside the JSON.

A case passes only when every operation succeeds and every downloaded payload matches its source SHA-256. Any integrity failure invalidates the run. Establish acceptance thresholds with the infrastructure team before declaring production capacity.
