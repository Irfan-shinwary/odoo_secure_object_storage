# Testing and migration runbook

Run tests in a disposable development or staging database with non-sensitive files. Do not begin with production data.

## Service checks

- Confirm MinIO is reachable and the configured bucket exists and is private.
- Confirm Vault is reachable, unsealed and the configured Transit key exists.
- Confirm the Odoo runtime token has only the required Transit encrypt/decrypt permissions.
- Confirm the Odoo process has the intended environment variables.
- For legacy compatibility tests only, make the historical `ODOO_SECURE_STORAGE_MASTER_KEY` available if the fixture uses `ODOOENC1` or `ODOOENC2`.

## Automated Odoo tests

Run tests using the same Python environment and Odoo 17 source tree used by the server. Use a disposable database; do not run module test updates against production.

Example PowerShell command (adjust paths, database and config):

```powershell
.\.venv\Scripts\python.exe .\odoo\odoo-bin -c .\configuration\odoo.conf -d secure_storage_test --test-enable --stop-after-init -u odoo_secure_object_storage --log-level=test
```

The repository includes unit tests for streaming encryption and legacy attachment encryption, plus Odoo transaction tests for attachment workflows. The workflow tests use in-memory MinIO and test key-provider substitutes; they do not prove real Vault or MinIO connectivity.

## Attachment functional tests

1. Upload a small text file through Odoo.
2. Confirm the attachment storage reference uses `secure-minio://`.
3. Inspect its MinIO object metadata: the storage format should be `odoo-vault-aesgcm-stream-v1`, and metadata should include a Vault-wrapped key, plaintext size and SHA-256 digest.
4. Confirm the encrypted object begins with `ODSDOC01`.
5. Download it through Odoo and compare the bytes with the original.
6. Test zero-byte, binary, Unicode-named and multi-chunk files.
7. Create two attachments and confirm their wrapped DEKs differ.
8. Restart Odoo and repeat downloads.
9. Test replacement and deletion.
10. Test access with authorized and unauthorized Odoo users.

## Failure and integrity tests

- Tamper with a ciphertext byte and confirm authenticated decryption fails.
- Remove the `wrapped-key` MinIO metadata and confirm the attachment read fails closed.
- Test a truncated object and invalid/missing Vault response.
- Test a Vault outage during upload and read.
- Test an invalid Transit token and a token without the required key permissions.
- Confirm user-facing errors and logs do not expose plaintext keys or Vault tokens.

## Legacy compatibility tests

Use known fixtures for both `ODOOENC1` and `ODOOENC2`.

1. Configure the exact historical Base64 32-byte `ODOO_SECURE_STORAGE_MASTER_KEY`.
2. Read each fixture through the normal attachment read path.
3. Compare plaintext bytes and known checksums.
4. Confirm new uploads use `ODSDOC01`, not either legacy format.
5. Keep the legacy key until every legacy object is migrated, verified and included in a successful restore test.

## Secure document tests

Separately exercise the `secure.document` workflow: DEK generation, Vault Transit wrap/unwrap, encrypted MinIO object creation, authorized download, integrity verification, denied access and invalid/missing Vault token behavior.

The secure document workflow and `ir.attachment` share key-provider and streaming-encryption services, but their wrapped-key metadata and lifecycle handling differ.

## Migration tests

1. Back up the database and original Odoo filestore.
2. Keep automatic migration disabled.
3. Create test attachments in the normal Odoo filestore.
4. Run discovery and inspect migration records.
5. Migrate one record manually.
6. Verify its status is Migrated and its attachment reference points to the secure MinIO object.
7. Download through Odoo and compare the content.
8. Modify a source attachment after discovery; its stale discovery record should be skipped.
9. Test a file above the current 100 MiB limit; the normal migration path should skip it.
10. Only after successful tests, enable automatic migration with a small batch size and observe scheduled-action logs.

## Automatic jobs

The module defines scheduled actions for automatic discovery, automatic migration and orphan cleanup. In Odoo, inspect **Settings → Technical → Automation → Scheduled Actions** (menu labels may vary).

Verify:
- Active is enabled.
- Next Execution Date advances after a run.
- Odoo cron workers are enabled.
- The migration configuration's automatic migration switch is enabled.
- `ODOO_SECURE_STORAGE_ENABLED=1` is present in the Odoo process.
- Logs contain `SECURE_STORAGE_AUTO_MIGRATION` and migration success/failure events.

The migration cron processes eligible pending records and retryable failed records according to configured batch and retry limits. Review failed records before increasing retry counts or batch sizes.

## Acceptance evidence

Record test date, Odoo version, addon commit, environment, file sizes, test results, migration counts, log excerpts, and backup/restore evidence. Do not include secrets or personal data in test reports.
