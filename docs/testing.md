# Testing and migration runbook

Run these tests in a disposable development or staging database with non-sensitive files. Do not begin with production data.

## Service checks

- Confirm MinIO and Vault containers are healthy/running.
- Confirm the configured bucket exists and is private.
- Confirm Vault is unsealed and Transit key `odoo-documents` exists when testing `secure.document`.
- Confirm the Odoo process has the intended environment variables.

## Attachment functional tests

1. Upload a small text file through Odoo.
2. Confirm the attachment's storage reference uses `secure-minio://`.
3. Download it through the normal Odoo interface.
4. Compare downloaded bytes with the original file.
5. Test zero-byte, binary, Unicode-named, and multi-chunk files.
6. Restart Odoo and repeat downloads.
7. Test deletion and verify that application behavior is correct.
8. Test access with authorized and unauthorized Odoo users.

## Secure document tests

Separately exercise the `secure.document` workflow:

- DEK generation.
- Vault Transit wrap/unwrap.
- Encrypted MinIO object creation.
- Authorized download and integrity verification.
- Denied access and invalid/missing Vault token behavior.

These tests do not replace the attachment tests; the implementations use different key-management paths.

## Migration tests

1. Back up the database and the original Odoo filestore.
2. Keep automatic migration disabled.
3. Create several test attachments in the normal Odoo filestore.
4. Run discovery and inspect the resulting migration records.
5. Migrate one record manually.
6. Verify its status is Migrated and the attachment reference points to the secure MinIO object.
7. Download the attachment through Odoo and compare its content.
8. Test a source attachment modified after discovery; the record should be skipped rather than migrate stale content.
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

The migration cron processes eligible pending records and retryable failed records according to the configured batch and retry limits. Review failed records' error details before increasing retry counts or batch sizes.

## Acceptance evidence

Record test date, Odoo version, addon commit, environment, file sizes, test results, migration counts, log excerpts, and backup/restore evidence. Do not include secrets or personal data in test reports.
