# Changelog

All notable addon changes are documented here.

## 17.0.3.0.0 - 2026-11-26

### Security and encryption
- Standardize Odoo attachment encryption on random per-object 32-byte DEKs protected by HashiCorp Vault Transit.
- Use the ODSDOC01 chunked AES-256-GCM stream format for secure attachments.
- Remove the static attachment master-key configuration and ODOOENC1/ODOOENC2 compatibility readers. This is intentional; this project release does not provide backward compatibility for those historical encrypted formats.
- Keep Vault-wrapped DEK, storage format, plaintext size and plaintext SHA-256 in MinIO object metadata.

### Tests
- Add explicit per-attachment wrapped-DEK uniqueness coverage.
- Invalidate Odoo attachment field cache before successful read assertions so tests exercise the storage read/decryption path.
- Add rollback cleanup coverage for newly uploaded objects.
- Retain tests for tampered ciphertext, invalid wrapped keys, Vault/MinIO read failures, multi-chunk files, empty files, updates and post-commit deletion.

### Documentation and repository
- Align installation, architecture, configuration, Vault, MinIO, testing, security, backup/recovery and troubleshooting guides with the Vault-only attachment design.
- Add the LGPL-3.0 license text.
- Remove tracked Python bytecode artifacts.
- Prepare the addon manifest version as 17.0.3.0.0.

### Validation
- Odoo 17 addon test suite: 18 tests passed, 0 failures and 0 errors on the disposable `secure_storage_addon_test` database.
- Live Odoo/MinIO/Vault attachment upload and download verified successfully using the ODSDOC01 format.
- PostgreSQL migration uniqueness constraint verified: `UNIQUE (attachment_id)`.
- `git diff --check` completed without errors.
