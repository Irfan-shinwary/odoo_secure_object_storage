# Failure injection and restart recovery

This phase validates the secure `ir.attachment` path under dependency failures and service restarts. Run all destructive or outage tests only in a disposable development/staging database with a dedicated non-production MinIO bucket and Vault instance. Never stop production dependencies or run failure injection against production.

## Scope and safety

- Vault Transit unavailable before an upload: no encrypted object should be written.
- MinIO interruption during an upload: a possibly partial object is removed on a best-effort basis.
- MinIO unavailable during download: Odoo fails closed; after MinIO recovers, the same attachment is readable.
- Vault sealed/unavailable during download: Odoo fails closed; after Vault is unsealed/recovered, the same attachment is readable.
- Odoo process restart: an encrypted attachment remains readable, with the same object reference and SHA-256.
- Database transaction rollback and post-commit deletion: covered by the existing attachment workflow tests.

A remote object-store cleanup request can itself fail while MinIO is unavailable. The orphan-cleanup cron is the secondary reconciliation mechanism; verify it in the target deployment and retain a grace period that exceeds the maximum expected transaction duration and outage window.

## 1. Upgrade and run automated Odoo tests

From the Odoo 17 project root, activate the project's Python 3.10 virtual environment and run the test suite against a disposable test database:

```powershell
cd D:\Code\Odoo\Odoo-17
.\.venv\Scripts\python.exe .\odoo\odoo-bin `
    -c .\configuration\odoo.conf `
    -d secure_storage_test5 `
    -u odoo_secure_object_storage `
    --test-enable `
    --stop-after-init `
    --log-level=test
```

If the database contains important data, do not use it for module tests. Create a fresh disposable database first. Review the Odoo test summary and confirm that the attachment workflow tests pass. The tests mock MinIO and Vault; they validate application behavior, not actual service restart behavior.

## 2. Create a real encrypted attachment before restart

Keep the normal Odoo server running, with secure-storage environment variables set in the Odoo server process. The benchmark utility's `.env` loading configures only the client script; it does not inject variables into an already-running Odoo server.

From the addon directory:

```powershell
cd D:\Code\Odoo\Odoo-17\server_custom\odoo_secure_object_storage
D:\Code\Odoo\Odoo-17\.venv\Scripts\python.exe .\scripts\restart_recovery_probe.py create `
    --manifest .\benchmark-results\restart-probe.json `
    --url http://127.0.0.1:8040 `
    --database secure_storage_test5 `
    --username admin `
    --size-mib 2
```

Supply the password through `ODOO_BENCH_PASSWORD` in the local project `.env` or process environment. Do not put credentials in command history or the manifest.

The script creates a random 2 MiB attachment, confirms its `store_fname` uses the `secure-minio://` scheme, and saves the record ID, object reference, size, and SHA-256 digest. The manifest contains no plaintext or credentials.

## 3. Restart Odoo and verify the attachment

1. Stop the Odoo server cleanly (Ctrl+C in its terminal, or stop its Windows service if applicable).
2. Leave PostgreSQL, MinIO and Vault running.
3. Start Odoo again with the same configuration, database, addon version and secure-storage environment.
4. Run:

```powershell
D:\Code\Odoo\Odoo-17\.venv\Scripts\python.exe .\scripts\restart_recovery_probe.py verify `
    --manifest .\benchmark-results\restart-probe.json `
    --url http://127.0.0.1:8040 `
    --database secure_storage_test5 `
    --username admin
```

Expected result: `PASS: attachment survived restart/recovery`, with the same SHA-256 and secure object reference. This verifies the attachment does not depend on process-local memory or a cached plaintext key.

## 4. Exercise dependency outages and recovery

Use the restart-probe attachment. Keep its ID and expected digest.

### MinIO outage

1. Stop the staging MinIO service using its normal service-management method.
2. Run the verification command. It must fail with an Odoo attachment retrieval error; it must not return partial or unauthenticated content.
3. Restart MinIO and wait until the bucket is healthy.
4. Run verification again. It must pass with the original digest.

### Vault sealed/unavailable

1. Ensure MinIO is healthy.
2. Seal or stop only the staging Vault instance using its supported operational procedure.
3. Run verification. Odoo must fail closed because it cannot unwrap the DEK; no plaintext should be returned.
4. Unseal/restart Vault and verify the Transit mount/key and Odoo token policy.
5. Run verification again. It must pass with the original digest.

Do not delete or rotate the Transit key during this test. Sealing/unavailability is sufficient to test dependency recovery; key loss is a separate disaster-recovery scenario.

## 5. Cleanup

After recording evidence, delete the test attachment and manifest:

```powershell
D:\Code\Odoo\Odoo-17\.venv\Scripts\python.exe .\scripts\restart_recovery_probe.py cleanup `
    --manifest .\benchmark-results\restart-probe.json `
    --url http://127.0.0.1:8040 `
    --database secure_storage_test5 `
    --username admin
```

The cleanup command unlinks the Odoo attachment through the ORM, allowing the post-commit object deletion callback to run. Confirm the object is absent from the dedicated staging bucket. If cleanup is interrupted or MinIO is unavailable, restore MinIO and use orphan cleanup after its grace period; do not manually delete objects that may still be referenced.

## Evidence and acceptance criteria

Record the addon commit, Odoo/Python versions, database name, dependency versions, timestamps, and results. Do not record credentials, plaintext, wrapped DEKs or Vault recovery material.

| Scenario | Acceptance criterion |
|---|---|
| Vault wrap failure before upload | No object is written |
| Interrupted/partial MinIO upload | Partial object cleanup is attempted; no Odoo reference is committed |
| MinIO unavailable on read | Read fails closed; no plaintext returned |
| MinIO restored | Original attachment is readable and SHA-256 matches |
| Vault unavailable/sealed on read | Read fails closed; no plaintext returned |
| Vault restored/unsealed | Original attachment is readable and SHA-256 matches |
| Odoo restart | Same object reference remains readable; SHA-256 matches |
| Transaction rollback | Existing rollback callback removes uploaded object |
| Attachment deletion | Object deletion occurs after database commit |

A scenario is not complete merely because the script exits without a Python exception. Capture Odoo logs and verify the expected state in the database and dedicated object bucket.