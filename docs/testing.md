# Testing and migration runbook

Run automated and manual tests in a disposable development or staging database with non-sensitive files. Do not begin with production data.

## 1. Automated Odoo tests

Run the addon tests using the exact Python interpreter and Odoo 17 source tree used by the development environment. Ensure PostgreSQL is running and use a disposable test database.

Example from the Odoo project root on Windows PowerShell:

~~~powershell
.\.venv\Scripts\python.exe .\odoo\odoo-bin -c .\configuration\odoo.conf -d secure_storage_addon_test -i odoo_secure_object_storage --test-tags /odoo_secure_object_storage --stop-after-init --log-level=test
~~~

For an already-installed disposable test database, replace -i with -u. Do not run installation or upgrade tests against a database containing important data.

The automated suite covers the streaming encryption service, secure-document workflow and attachment workflows. Attachment workflow tests use in-memory MinIO and mocked Vault Transit operations; they validate addon behavior but do not prove that live external services are configured correctly.

Record the Odoo version, Python version, addon commit, database name, total tests, failures and errors. Re-run the complete suite after changing Python code, manifest data, security rules or test code.

## 2. Live service checks

- Confirm MinIO and Vault are running and reachable from the Odoo process.
- Confirm the configured bucket exists and is private.
- Confirm Vault is initialized and unsealed.
- Confirm Transit is enabled and the configured Transit key exists.
- Confirm the Odoo application token has only the required Transit encrypt/decrypt permissions.
- Confirm the Odoo process has all required environment variables. A Compose .env file does not automatically populate a separately launched PyCharm/Windows process.

## 3. Attachment end-to-end tests

Use non-sensitive files and verify:

1. Upload a small text file through Odoo.
2. Confirm its ir.attachment.store_fname begins with secure-minio://.
3. Confirm the referenced object exists in the configured MinIO bucket.
4. Confirm object metadata includes storage-format=odoo-vault-aesgcm-stream-v1, wrapped-key, plaintext-size and plaintext-sha256. Never print the wrapped key value.
5. Read the first eight object bytes and confirm the format magic is ODSDOC01.
6. Download through the normal Odoo interface and compare the downloaded bytes with the original file.
7. Test zero-byte, binary, Unicode-named and larger-than-4-MiB files.
8. Test attachment replacement/update and deletion.
9. Restart Odoo and repeat a download to verify the service dependencies remain available.
10. Verify authorized and unauthorized Odoo users have the expected access.

## 4. Secure document tests

Separately exercise the secure.document model:

- DEK generation and Vault Transit wrap/unwrap.
- Encrypted MinIO object creation.
- Authorized download and integrity verification.
- Denied access and invalid/missing Vault token behavior.

The secure-document model is a separate Odoo workflow. Passing its tests does not replace the ir.attachment tests.

## 5. Migration tests

The migration feature moves eligible existing Odoo filestore attachments to the encrypted MinIO format. It is not a legacy ciphertext compatibility mechanism.

1. Back up a disposable database and its original Odoo filestore.
2. Keep automatic migration disabled.
3. Create several test attachments in the normal Odoo filestore.
4. Run discovery and inspect the migration records.
5. Migrate one record manually.
6. Verify its status is Migrated and its attachment reference points to the secure MinIO object.
7. Download the attachment through Odoo and compare its content.
8. Modify a source attachment after discovery; verify stale discovery records are not migrated.
9. Test a file above the current 100 MiB migration limit; verify the normal migration path skips it with a clear reason.
10. Test retry behavior after a simulated MinIO or Vault failure.
11. Only after successful manual tests, enable automatic migration with a small batch size and observe scheduled-action logs.

## 6. Scheduled actions

The module defines scheduled actions for automatic discovery, automatic migration and orphan cleanup. In Odoo, inspect Settings → Technical → Automation → Scheduled Actions (menu labels may vary).

Verify:
- The intended scheduled actions are active.
- Next Execution Date advances after a run.
- Odoo cron workers are enabled.
- The migration configuration's automatic migration switch is enabled only when intended.
- ODOO_SECURE_STORAGE_ENABLED=1 is present in the Odoo process.
- Logs contain the expected migration start, completion and failure events.

Review failed migration records before increasing retry counts or batch sizes. Do not enable unattended bulk migration until the manual workflow and rollback plan are validated.

## 7. Acceptance evidence

Record the test date, Odoo version, Python version, addon commit, environment, file sizes, test results, migration counts and sanitized log excerpts. Do not include credentials, wrapped-key values, personal data or document contents in test reports.
