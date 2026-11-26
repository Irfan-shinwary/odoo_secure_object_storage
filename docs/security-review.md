# Security Review and Release Readiness Assessment

**Scope:** static review of the current main-branch Odoo 17 addon implementation and its operator documentation.

**Purpose:** record the implemented security architecture, operational controls and remaining validation requirements. This document is not an independent penetration test, formal audit, security certification or production approval.

## 1. Current architecture

The addon uses one Vault-backed encryption architecture for both Odoo attachment storage and the separate secure.document workflow.

For ir.attachment:

1. Odoo generates a cryptographically random 32-byte Data Encryption Key (DEK) for each newly written object.
2. Vault Transit wraps the DEK. The Odoo application identity is restricted to the configured Transit encrypt/decrypt operations.
3. The attachment is encrypted using AES-256-GCM in authenticated chunks. The current stream format identifier is ODSDOC01; the default chunk size is 4 MiB.
4. MinIO stores the encrypted object and custom metadata containing the storage-format identifier, Vault-wrapped DEK, plaintext size and plaintext SHA-256.
5. PostgreSQL stores Odoo attachment metadata and a secure-minio:// reference to the object.
6. On read, Odoo fetches the object and metadata, asks Vault Transit to unwrap the DEK, authenticates/decrypts the chunks and verifies the plaintext digest and expected size.

The secure.document model is a separate business workflow. It also uses a random DEK, Vault Transit and the streaming encryption service, with its own metadata and access-control model.

The static attachment master-key setting and ODOOENC1/ODOOENC2 compatibility readers have been removed by maintainer decision. The maintainer has confirmed that no legacy ciphertext compatibility requirement remains. The release format for new secure attachment objects is ODSDOC01.

## 2. Security controls implemented

### Per-object key separation

- Each new attachment object receives a fresh 32-byte random DEK.
- Vault Transit wraps and unwraps the DEK; the application does not need a long-lived static attachment master key.
- The Vault application token should not have key-management or broad administrative permissions.
- The wrapped DEK is stored with the MinIO object metadata, not as plaintext key material.

### Authenticated encryption and integrity

- AES-256-GCM provides authenticated encryption for each chunk.
- The stream carries format, chunk-size, plaintext-size and SHA-256 information.
- The read path verifies chunk authentication and final plaintext integrity and rejects malformed/truncated data.
- The attachment format identifier is explicit; legacy formats are not silently interpreted as the current format.

### Object storage separation

- MinIO stores encrypted object bytes.
- PostgreSQL stores attachment references and business metadata.
- Vault protects the Transit key material used to unwrap per-object DEKs.
- These services have separate credentials and trust boundaries. Compromise of one service should not be treated as equivalent to compromise of all services, but an attacker with Odoo runtime access may be able to request decrypt operations using the application identity.

### Lifecycle handling

- New objects are uploaded before the Odoo reference is committed.
- The attachment write path registers rollback cleanup for newly uploaded objects.
- Secure-object deletion is deferred until transaction commit.
- A scheduled orphan cleanup job removes eligible old objects that are not referenced by Odoo and match the current storage format. Its grace period and operational behavior must be monitored.

## 3. Operational requirements and residual risks

### Vault

- Protect Vault persistent storage and the Transit key material. Losing the relevant Transit key material can make encrypted objects unreadable even if PostgreSQL and MinIO backups remain intact.
- Protect unseal/recovery material separately from the Odoo application token.
- Use a dedicated limited application token; never configure the root token in Odoo.
- Use TLS with certificate validation in production.
- Plan token expiry/renewal and Transit key rotation. Retain old Transit key versions for as long as existing wrapped DEKs require them.
- Test Vault restart, unseal, token replacement and restoration using isolated copies before production.

### MinIO

- Use a private bucket and a dedicated least-privilege Odoo service account.
- The application configuration checks bucket existence; operators must separately configure and verify bucket privacy and IAM policy.
- Use TLS in production and restrict API/console network access.
- Keep object data backups coordinated with PostgreSQL backups.
- Pin and scan a maintained MinIO image for production. The repository Compose file is development-only and currently uses a third-party image tagged latest.

### Odoo and application process

- Environment variables must be available to the Odoo server process. Docker Compose .env parsing does not automatically populate a separately launched Windows/PyCharm process.
- Restrict access to Odoo process configuration, environment variables, logs and the host.
- The Odoo attachment read interface ultimately returns the requested attachment content to the application process. Chunked encryption reduces crypto working-set size, but large reads can still consume substantial memory.
- The normal migration path has a 100 MiB per-file limit. Confirm this limit and worker capacity before planning bulk migration.
- Validate Odoo group/record access for both attachment and secure.document workflows.

### Metadata and confidentiality

- MinIO object metadata includes the Vault-wrapped DEK, plaintext size, plaintext SHA-256 and format identifier. The wrapped DEK is ciphertext from Vault Transit, but object metadata and file sizes remain visible to principals allowed to inspect objects.
- Do not log or expose plaintext DEKs, Vault tokens, unseal keys, or wrapped-key metadata in support output.
- Consider whether object names, timestamps, file sizes and plaintext digests are sensitive in the deployment context.

### Development infrastructure

- The supplied Docker Compose file binds ports to loopback and uses Vault HTTP without TLS. It is not a production deployment template.
- Replace all example credentials. Do not use MinIO root credentials as the Odoo application identity.
- Use separate credentials, buckets, Vault keys and persistent storage for development, test/staging and production.

## 4. Validation evidence and status

The maintainer reported the following development-environment validation before the legacy-removal consolidation was merged into main:

- The automated addon suite completed with 15 tests and no failures or errors.
- Live Odoo upload and download succeeded.
- A recent attachment was confirmed in PostgreSQL with a secure-minio:// reference.
- The corresponding MinIO object existed and had the expected storage-format, plaintext-size, plaintext-SHA-256 and wrapped-key metadata.
- The object header matched ODSDOC01.

These checks validate the implemented Vault-backed write/read path in the maintainer's development environment. They do not constitute an independent security assessment.

**Required after the final main-branch consolidation:** rerun the complete automated test suite against the merged main branch, including the updated cache-invalidation assertions and per-attachment wrapped-DEK uniqueness test. Repeat the live Odoo upload/download check after pulling the final main commit.

## 5. Release checklist

- [ ] Run the full addon test suite on the final main commit in a disposable Odoo 17 test database.
- [ ] Install the addon on a clean Odoo 17 database.
- [ ] Verify upload, uncached read/download, update, empty file, multi-chunk file and deletion.
- [ ] Verify Vault-unavailable and MinIO-unavailable failure handling.
- [ ] Verify ciphertext tampering and invalid wrapped-DEK rejection.
- [ ] Verify migration discovery, manual migration, retries, scheduled jobs and the 100 MiB limit.
- [ ] Verify MinIO bucket privacy and the exact least-privilege service-account policy.
- [ ] Verify Vault token scope, TLS, Transit key availability and key-version retention.
- [ ] Verify rollback cleanup and post-commit deletion behavior.
- [ ] Verify the final installation procedure on a clean developer environment.
- [ ] Conduct a separate production security review and recovery drill before storing sensitive production records.

## 6. Scope limitations

This review does not claim:
- penetration testing or independent cryptographic review;
- production deployment or production-grade high availability;
- automated CI validation of the final merged commit;
- complete migration testing across every possible Odoo attachment type or workload;
- a tested production disaster-recovery design.

Use this assessment as an engineering handover and release checklist, not as a security certification.
