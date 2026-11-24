# Backup and recovery

A successful backup is not sufficient; perform scheduled restore exercises.

## What must be protected

1. PostgreSQL database: attachment metadata, secure storage references, migration records and secure-document metadata.
2. MinIO object data: encrypted attachment and secure-document objects.
3. Attachment master key: required to decrypt the current `ir.attachment` encrypted objects.
4. Vault persistent data and Transit key material: required to unwrap DEKs in the `secure.document` workflow.
5. Vault unseal/recovery material and configuration.
6. Odoo configuration and the exact addon version/commit.

A database-only backup is not a complete backup of this system. An object-store-only backup is also insufficient because PostgreSQL contains references and metadata.

## Backup coordination

- Define an application-consistent backup window.
- Coordinate PostgreSQL backup with object-storage backup so references do not point to missing objects.
- Use MinIO's supported replication/versioning/backup facilities appropriate to the deployed version.
- Back up Vault according to its selected storage backend. The development configuration uses the file backend; production backup instructions depend on the chosen backend.
- Store keys and recovery material separately from ordinary application backups.
- Encrypt backups and restrict access.

## Recovery sequence

1. Restore Vault storage and unseal Vault; verify Transit key availability before testing secure documents.
2. Restore MinIO objects and verify bucket/object availability.
3. Restore PostgreSQL to a consistent point.
4. Restore the exact attachment master key into the Odoo secret environment.
5. Restore Odoo configuration and the matching addon version.
6. Start Odoo in a controlled state and test representative downloads from both encrypted workflows.
7. Reconcile missing references or objects before returning service to users.

The exact ordering and consistency mechanism must be adapted to the production storage topology and RPO/RTO requirements.

## Recovery drills

At least periodically, test:
- Database restore.
- MinIO object restore.
- Master-key retrieval and attachment decryption.
- Vault unseal and Transit decrypt.
- Full Odoo restart and document download.
- Recovery after loss of an application token by issuing a replacement limited token.
