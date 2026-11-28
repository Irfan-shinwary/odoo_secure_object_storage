# Backup and recovery validation

A successful backup job is not proof of recoverability. This runbook defines a repeatable restore drill. Execute it in an isolated recovery environment using non-production access credentials. Never overwrite production during a drill.

## Recovery set

A recoverable set must include all of the following, captured within an agreed consistency window:

1. PostgreSQL database: attachment metadata, secure object references, secure-document metadata and migration records.
2. MinIO object data: every encrypted object referenced by the restored database, including object metadata containing the wrapped DEKs and format identifiers.
3. Vault persistent storage and Transit key material: required to unwrap the DEKs.
4. Vault unseal/auto-unseal dependencies, recovery material and configuration.
5. Odoo configuration, Python dependency lock/version inventory, exact addon commit and service unit/environment configuration (secrets must be restored through the approved secret manager, not copied into a report).
6. Any Odoo filestore data still referenced by the database, including unmigrated attachments.

A database-only backup, MinIO-only backup, or Vault-only backup is incomplete.

## Capture and protect backups

- Define an application-consistent backup window and document the target recovery point.
- Record the PostgreSQL backup identifier and timestamp.
- Use the deployed MinIO version's supported replication/versioning/backup mechanism; record the bucket, replication/backup job and completion marker.
- Back up Vault using the procedure for its actual storage backend. For Integrated Storage (Raft), use a Vault-supported Raft snapshot procedure. For a file backend, take a consistent protected copy while Vault is safely quiesced according to the backend's operational requirements. Do not assume these methods are interchangeable.
- Preserve Vault recovery/unseal dependencies separately from the backup set.
- Encrypt backup artifacts, restrict access, and retain checksums/manifests. Never put tokens, unseal keys, recovery keys or plaintext DEKs in the manifest.
- Retain the exact addon Git commit and deployment configuration version.

## Isolated restore drill

Create an isolated recovery network and restore into new database, bucket/object namespace, Vault instance and Odoo service identity. Ensure the restored Odoo cannot write to production resources.

1. **Restore Vault first.** Restore the Vault storage snapshot/copy using the backend-specific supported procedure. Start Vault, complete unseal or auto-unseal, verify the Transit mount and key are present, and confirm the restored Odoo recovery identity has only required encrypt/decrypt permissions.
2. **Restore MinIO.** Restore the bucket and object versions/metadata. Verify the bucket is private and the expected object count/size or inventory matches the backup manifest.
3. **Restore PostgreSQL.** Restore to a new database. Confirm attachment references and secure-document records are present. Restore the corresponding Odoo filestore if the database references it.
4. **Restore Odoo.** Deploy the exact recorded addon commit and compatible Python dependencies. Configure isolated endpoints and secrets. Confirm the service starts and scheduled migration/cleanup jobs are disabled during validation.
5. **Verify encrypted attachments.** Select representative objects across small, multi-chunk and largest-size classes. Download through Odoo's normal access-controlled path and compare the resulting SHA-256 with the pre-backup test manifest. Verify unauthorized users remain denied.
6. **Verify secure documents separately.** Exercise secure.document download and verify integrity; this is a separate workflow from ir.attachment.
7. **Verify write recovery.** Upload and download a new test attachment to prove the restored environment can both unwrap old DEKs and wrap new DEKs.
8. **Verify restart recovery.** Restart Vault and Odoo in the documented operational sequence, complete unseal/auto-unseal, and repeat downloads. Confirm no dependency on an in-memory-only token or manually cached key.
9. **Record RPO/RTO.** Measure elapsed time from recovery start to service-ready and the age of the latest restored consistent point. Compare with the organization's approved RPO/RTO objectives.
10. **Clean up.** Securely remove the isolated recovery environment and temporary plaintext test files according to policy.

## Failure-injection cases

Perform these only in the isolated recovery environment:

- Restore PostgreSQL without one referenced MinIO object; verify the affected download fails safely and the discrepancy is detected.
- Restore MinIO without the matching Vault Transit key material; verify decryption fails closed and no plaintext is returned.
- Replace the Odoo Vault application token while retaining the Transit key; verify a replacement least-privilege token restores service.
- Restart Vault in a sealed state; verify Odoo reports dependency failure without leaking secrets, then unseal and confirm recovery.
- Interrupt an upload and verify no database reference is committed to a partial encrypted object.

## Evidence and sign-off

For every drill, record:

- Date, operator, environment and approved change/drill reference.
- Source backup identifiers, timestamps and checksums.
- PostgreSQL, MinIO, Vault, Odoo and addon versions/commit.
- Object inventory counts and byte totals before/after restore.
- Number and classes of attachments verified; expected and actual SHA-256 results.
- Secure-document validation result.
- Restart and failure-injection results.
- Measured RPO/RTO and deviations.
- Remediation owner and due date for every failure.

Do not include document contents, personal data, credentials, wrapped-key values or Vault recovery material in the evidence report.

## Operational limitation

The exact backup commands and consistency controls depend on the selected PostgreSQL backup tooling, MinIO deployment/version, Vault storage backend and secret manager. Finalize those commands against the actual production topology and vendor-supported procedures; this runbook intentionally does not assume that the development file-backed Vault configuration is the production design.
