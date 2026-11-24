# Security Review and Repository Hardening Assessment

**Review scope:** static source review of the merged Odoo 17 implementation on `main`.

**Review status:** source review only. No Odoo server, MinIO, Vault, database, penetration test, or end-to-end test suite was executed as part of this review.

## Executive summary

The active `ir.attachment` implementation already uses per-object random DEKs wrapped by Vault Transit. New writes use AES-256-GCM chunked encryption in the `ODSDOC01` format. The wrapped DEK and integrity metadata are stored as MinIO object metadata. The reader retains compatibility with legacy `ODOOENC1` and `ODOOENC2` objects, which use the Base64 32-byte `ODOO_SECURE_STORAGE_MASTER_KEY` through HKDF-SHA256.

The separate `secure.document` model also uses a random per-document DEK wrapped by Vault Transit, but stores the wrapped key in PostgreSQL rather than MinIO object metadata.

## Findings and recommendations

### High priority — Vault key lifecycle

- Keep the Transit key persistent and include it in a tested Vault backup/recovery process.
- Do not use the Vault root token in Odoo. Use a dedicated machine identity and limited runtime token.
- Restrict the runtime policy to Transit encrypt/decrypt operations for the configured key.
- Keep key creation, rotation, deletion and Vault policy administration separate from the Odoo runtime identity.
- Use HTTPS and certificate validation in production. Configure `ODOO_VAULT_CA_BUNDLE` for a private CA.
- Test Vault seal/unseal, token expiry/renewal, Transit key rotation, backup restore and recovery before production.
- Understand Transit key-version rotation semantics before rotating or deleting old key versions; existing wrapped DEKs must remain decryptable.

### High priority — MinIO isolation and object metadata

- Use a dedicated MinIO service identity for Odoo, not the root administrator.
- Grant only required object read, write and delete operations on the dedicated bucket.
- Keep anonymous/public bucket access disabled.
- Enforce TLS between Odoo and MinIO in production.
- Restrict MinIO API and console access to trusted network segments.
- Protect object metadata: it contains the Vault-wrapped DEK and plaintext integrity metadata. The wrapped DEK is not plaintext key material, but it is sensitive operational data.
- Monitor authorization failures, object deletion, capacity and service availability.

### High priority — legacy key retention

The legacy master key is required only for objects that still use `ODOOENC1` or `ODOOENC2`. Do not delete it until all such objects have been inventoried, migrated and independently verified. A restore exercise must prove that the new Vault-backed objects are readable without the legacy key before removing it from the deployment environment.

### Medium priority — attachment read memory behavior

The encryption/decryption service processes authenticated chunks, but the `ir.attachment` integration ultimately assembles and returns the full plaintext bytes because of the Odoo attachment API contract. Large downloads can therefore still require substantial worker memory. Load-test representative sizes and configure worker limits accordingly.

### Medium priority — migration safety

The legacy filestore migration model uses row locks, source snapshot checks, savepoints, size checks and post-upload read-back verification before updating the Odoo reference. Preserve these controls.

Before production migration:
- Take and verify database and source filestore backups.
- Run discovery and migration on a staging copy.
- Confirm downloaded content and checksums.
- Test retry behavior after MinIO, Vault or network failures.
- Verify cron worker availability and monitor pending, processing, failed and completed records.
- Do not delete original filestore objects until migrated objects are independently verified and retention policy permits deletion.

The current normal migration path skips files larger than 100 MiB.

### Medium priority — repository hygiene

Historical files `models/ir_attachment 1.py` and `services/object_storage1.py` differ from the active files. They were not removed because they may contain useful historical code and need maintainer comparison. The `.gitignore` does not untrack Python cache files already committed; enumerate and remove only confirmed generated artifacts in a separate cleanup.

### Validation checklist

- [ ] Run the addon test suite on the exact supported Odoo 17 build.
- [ ] Install the addon on a clean database.
- [ ] Test new attachment upload, read, download, replacement and deletion using a real Vault/MinIO test environment.
- [ ] Test missing Vault token, denied Transit policy, Vault outage and unsealed/sealed states.
- [ ] Test tampered header, ciphertext, missing wrapped-key metadata, truncated stream and wrong object identity.
- [ ] Verify legacy `ODOOENC1` and `ODOOENC2` fixtures.
- [ ] Verify MinIO bucket privacy and least-privilege credentials.
- [ ] Verify migration discovery, manual migration, scheduled migration, retries and concurrency.
- [ ] Restore database, object bucket and Vault from backups; read representative old and new documents.
- [ ] Conduct an independent security review before handling sensitive production records.

This report records source-level observations and recommendations; it is not a certification or a claim that deployment controls or runtime tests have passed.
