# Architecture and cryptographic key handling

## Components

- **Odoo 17:** attachment metadata and storage references remain in PostgreSQL. The addon overrides Odoo attachment file operations to store encrypted object data in MinIO.
- **MinIO:** private S3-compatible object storage. Attachment references use `secure-minio://<bucket>/<32-hex-object-key>`.
- **HashiCorp Vault Transit:** used by the separate `secure.document` workflow to wrap and unwrap randomly generated data-encryption keys.
- **PostgreSQL:** stores Odoo attachment metadata and migration tracking records.

## Two distinct encryption paths

Do not conflate these implementations.

### A. Odoo `ir.attachment`

The current `models/ir_attachment.py` implementation:

1. Reads `ODOO_SECURE_STORAGE_MASTER_KEY` as Base64.
2. Requires the decoded key to be exactly 32 bytes.
3. Derives a 32-byte AES key using HKDF-SHA256, with the object key as salt and a version-specific context string.
4. Encrypts attachment data using AES-GCM in chunks of 4 MiB.
5. Writes an encrypted object to MinIO and records a `secure-minio://` reference in Odoo.

The current source defines `ODOOENC1` and `ODOOENC2` formats. The master key is required to decrypt these objects. The attachment path does **not** currently call Vault Transit to wrap a per-object DEK.

### B. Separate `secure.document` model

The `secure.document` workflow uses:

1. A random 32-byte DEK generated in the application.
2. Vault Transit `encrypt` to wrap the DEK.
3. AES-GCM chunked streaming encryption using the DEK.
4. Vault Transit `decrypt` to unwrap the DEK before download.

The stream format uses the `ODSDOC01` magic header and 4 MiB default chunks. This is a separate model and workflow from the Odoo `ir.attachment` override.

## Trust boundaries

- Odoo requires network access to MinIO and, for `secure.document`, Vault.
- MinIO stores ciphertext for the encrypted paths.
- PostgreSQL stores attachment metadata, storage references, and wrapped-key metadata for secure documents.
- The master key and Vault token must be available to the Odoo process through a secret-management mechanism.
- Administrators who can read application process environments, secrets, PostgreSQL or object storage may have significant access. Apply least privilege and audit access.

## Key-loss implications

- Losing or changing `ODOO_SECURE_STORAGE_MASTER_KEY` can make existing encrypted `ir.attachment` objects unreadable.
- Losing Vault's persistent data or Transit key material can make Vault-wrapped DEKs unusable.
- Losing the Vault token alone is recoverable by issuing a new limited token, provided the Transit key remains available.
- Losing an unseal threshold of keys or the Vault storage itself can prevent Vault recovery. Maintain documented, tested recovery procedures.

## Migration behavior

The migration tracking model discovers eligible legacy Odoo attachments, stores source metadata, then migrates in batches. It verifies uploaded content by reading it back and checking size and SHA-1 before updating the Odoo storage reference. The normal migration path has a 100 MiB per-file limit. Review the current source before changing this limit or migration behavior.
