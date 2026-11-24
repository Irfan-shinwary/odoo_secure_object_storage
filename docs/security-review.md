# Security Review and Repository Hardening Assessment

**Review scope:** source files inspected on `hardening/repository-security-review` against the current Odoo 17 implementation.

**Review status:** static source review only. No Odoo server, MinIO, Vault, database, penetration test, or end-to-end test suite was executed as part of this review.

## Executive summary

The addon contains two distinct storage paths:

1. **`ir.attachment`:** Odoo attachment content is encrypted with AES-256-GCM in 4 MiB chunks. A 32-byte application master key is decoded from `ODOO_SECURE_STORAGE_MASTER_KEY`; HKDF-SHA256 derives an object-specific AES key using the object identifier as salt. The encrypted object is stored in MinIO and the database stores a `secure-minio://` reference. The current attachment path does **not** wrap a random per-object DEK with Vault Transit.
2. **`secure.document`:** a random 32-byte DEK is generated for each document, wrapped using Vault Transit, and used for chunked AES-GCM encryption. The wrapped key is stored in the Odoo database alongside document metadata.

The second path demonstrates a per-object DEK pattern, but it should not be copied into `ir.attachment` without a versioned format, metadata design, rollback plan, and tested migration. Existing attachment ciphertext must remain readable throughout any future transition.

## Findings and recommendations

### High priority — protect and recover the attachment master key

The attachment implementation requires `ODOO_SECURE_STORAGE_MASTER_KEY` to decode from Base64 to exactly 32 bytes. It is used to derive the encryption keys for the current `ODOOENC2` format and the legacy `ODOOENC1` format.

- Keep the exact key in a managed secret store or protected secret file; never commit it to Git, a Docker image, a database field, or an ordinary backup accessible to all operators.
- Back it up independently using an approved, access-controlled recovery process.
- Restrict who can read, rotate, or restore it.
- Do not generate a replacement key and overwrite the old one: doing so makes existing ciphertext unreadable unless a tested re-encryption or key-versioning process exists.
- Perform a restore test using a copy of the database, filestore/object bucket, and the exact historical key material.

### High priority — harden Vault authentication and policy

The Vault client currently sends `ODOO_VAULT_TOKEN` in the `X-Vault-Token` header and calls the configured Transit encrypt/decrypt endpoints.

For production:

- Do not use the Vault root token in Odoo.
- Use a dedicated machine identity (for example, AppRole or an available platform identity method) to obtain a short-lived token.
- Give that identity only the Transit permissions required for the configured key; do not grant broad administrative or key-management permissions to the Odoo runtime.
- Keep key creation, rotation, deletion, and policy administration separate from the application runtime identity.
- Use HTTPS with certificate validation. Configure `ODOO_VAULT_CA_BUNDLE` when a private CA is required; do not disable certificate verification.
- Restrict Vault network access to Odoo and authorized administrators.
- Test Vault restart, seal/unseal, token renewal/expiry, Transit key rotation, and disaster recovery before production.

### High priority — production MinIO isolation

The attachment storage client checks that the configured bucket exists, but bucket existence alone does not prove that the bucket is private or that credentials have least privilege.

- Use a dedicated MinIO service identity for Odoo, not the root administrator.
- Grant only the required operations on the dedicated bucket (object read, write, and delete as required by the addon).
- Keep anonymous/public bucket access disabled.
- Enforce TLS between Odoo and MinIO in production.
- Restrict the MinIO API and console to trusted network segments; do not expose the console publicly.
- Enable versioning/object-lock only if the operational retention design requires it, and document the consequences for deletion and storage costs.
- Monitor failed authorization, object deletion, capacity, and service availability.

### High priority — attachment DEK architecture is not yet Vault-backed

The current `ir.attachment` encryption derives keys from one long-lived application master key. This differs from `secure.document`, which uses a random per-document DEK wrapped by Vault Transit.

A future attachment design should:

1. Introduce an explicit, versioned ciphertext format (do not reinterpret `ODOOENC1` or `ODOOENC2`).
2. Generate a cryptographically random 32-byte DEK per attachment object.
3. Wrap the DEK with Vault Transit and persist the wrapped value as authenticated object metadata or a database field with clear ownership and lifecycle semantics.
4. Bind the attachment identity, object identifier, format version, and relevant immutable metadata into AES-GCM additional authenticated data (AAD).
5. Ensure upload failure, database rollback, object replacement, attachment copy, and deletion cannot orphan or mis-associate ciphertext and wrapped keys.
6. Preserve readers for both existing formats and the new format.
7. Implement resumable, idempotent re-encryption with before/after checksum verification, retry tracking, concurrency control, and rollback/recovery.
8. Test Vault outage behavior, key rotation, restore from backups, tampered headers/chunks, truncated objects, and concurrent attachment updates.

**Do not implement this change as a one-step replacement of the master-key code.** It is a data-format and key-lifecycle migration. The current review branch deliberately does not change the attachment encryption implementation.

### Medium priority — legacy format compatibility

The attachment reader accepts both `ODOOENC1` and `ODOOENC2`. The V2 path authenticates the complete header as part of each chunk's AAD; V1 uses the older AAD construction and is retained for compatibility.

- Keep V1 read-only; do not create new V1 objects.
- Inventory remaining V1 objects before planning retirement.
- Keep compatibility tests with known fixtures and expected plaintext hashes.
- Do not remove legacy decryption until all objects have been verified as migrated and a restore test proves the new format is recoverable.

### Medium priority — large attachment memory behavior

The attachment decryption helper uses a temporary file during chunk processing, but ultimately returns the complete plaintext as bytes because the Odoo attachment read contract expects the complete value. This means large downloads can still require substantial process memory.

The migration model also declares a 100 MiB maximum migration size. Document this limit operationally and test worker memory/timeouts with representative files. A future streaming integration would require a deliberate Odoo HTTP/attachment API design, not just changing the crypto helper.

### Medium priority — migration safety and operations

The migration model uses attachment-row locking and guarded reference updates. Continue to preserve these safeguards.

Before enabling automatic migration in production:

- Take and verify database and object-storage backups.
- Run discovery and migration against a staging database copy.
- Confirm source and target checksums and downloadability.
- Confirm retry behavior after MinIO/Vault/network interruption.
- Verify scheduled actions run with sufficient cron workers.
- Monitor pending, processing, failed, and completed records.
- Keep a documented rollback plan; do not delete source filestore objects until the migrated objects have been independently verified and the retention policy allows deletion.

### Medium priority — repository hygiene

The repository contains two additional files whose names look like backup/older copies:

- `models/ir_attachment 1.py`
- `services/object_storage1.py`

They are **not byte-for-byte duplicates** of the active files. The normal package initializer imports `models.ir_attachment` and does not import either file by its unusual backup-style name; the service file is also not imported by the package initializer. However, the files contain different historical implementations, so they were not deleted automatically. A maintainer should compare their useful changes with the active implementation, preserve any required history, then remove them in a separately reviewed cleanup if confirmed obsolete.

The repository's `.gitignore` now excludes Python cache files and common local secret/data files, but ignore rules do not untrack files already committed. A complete generated-artifact cleanup requires enumerating tracked `__pycache__` and `.pyc` paths and removing only those generated artifacts. This review did not guess paths or delete files without a verified repository listing.

### Low priority — manifest and license consistency

The current manifest declares `LGPL-3` twice. Remove the duplicate key in a small manifest-only cleanup. The manifest declares LGPL-3, but a root `LICENSE` file was not found during this review. Add the appropriate license text only after confirming the project owner's licensing intent and the exact license version.

## Validation checklist before production

- [ ] Run the addon test suite on the exact supported Odoo 17 build.
- [ ] Install the addon on a clean database.
- [ ] Verify normal attachment upload, read, download, replacement, and deletion.
- [ ] Verify existing `ODOOENC1` and `ODOOENC2` fixtures.
- [ ] Verify MinIO bucket privacy and least-privilege credentials.
- [ ] Verify Vault TLS, policy scope, token lifecycle, Transit key availability, and seal/unseal recovery.
- [ ] Verify migration discovery, manual migration, scheduled migration, retries, and concurrency.
- [ ] Verify object/database consistency after simulated failures.
- [ ] Restore a database and object bucket from backup and read representative documents.
- [ ] Conduct an independent security review before handling sensitive production records.

## Files reviewed

The static review included the attachment integration, migration model, secure document model, binary download integration, streaming encryption service, Vault key provider, MinIO object storage service, package initializers, manifest, README, and ignore rules.

This report records source-level observations and recommendations; it is not a certification or a claim that the listed operational controls have already been deployed.
