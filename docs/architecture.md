# Architecture and cryptographic key handling

## Components

- **Odoo 17:** attachment metadata and storage references remain in PostgreSQL. The addon overrides Odoo attachment file operations to store encrypted object data in MinIO.
- **MinIO:** private S3-compatible object storage. Attachment references use `secure-minio://<bucket>/<32-hex-object-key>`.
- **HashiCorp Vault Transit:** wraps and unwraps a randomly generated Data Encryption Key (DEK) for each attachment and secure document.
- **PostgreSQL:** stores Odoo attachment metadata, object references, and migration tracking records.

## Attachment encryption workflow

1. Odoo generates a cryptographically random 32-byte DEK for each new attachment.
2. Odoo sends the DEK to Vault Transit for wrapping. The plaintext DEK remains in the application only for the duration of the encryption operation.
3. Odoo encrypts the attachment using AES-256-GCM in authenticated chunks (4 MiB default) using the DEK.
4. MinIO stores the encrypted stream. Object metadata contains the Vault-wrapped DEK, storage format, plaintext size and SHA-256 digest.
5. PostgreSQL stores a `secure-minio://` reference instead of a local filestore path.
6. On read, Odoo obtains the object and its metadata, asks Vault to unwrap the DEK, and decrypts/authenticates the stream. The implementation verifies chunk authentication, final plaintext SHA-256, expected size and absence of trailing data.

The current attachment format identifier is `ODSDOC01`. There is no static attachment master-key setting in this architecture.

## Separate secure.document workflow

The `secure.document` model also uses a random 32-byte DEK wrapped by Vault Transit and AES-GCM streaming encryption. It is a separate business model from Odoo's `ir.attachment` override, although it reuses the same key-provider and streaming-encryption services.

## Trust boundaries

- Odoo requires network access to MinIO and Vault.
- MinIO stores ciphertext and wrapped DEKs, not plaintext attachment content or plaintext DEKs.
- PostgreSQL stores Odoo metadata and storage references.
- Vault protects Transit key material and performs DEK wrapping/unwrapping.
- Administrators who can read application process environments, secrets, PostgreSQL or object storage may have significant access. Apply least privilege and audit access.

## Key-loss implications

- Losing Vault's persistent data or the relevant Transit key material can make Vault-wrapped DEKs unusable and encrypted documents unreadable.
- Losing the Vault application token alone is recoverable by issuing a new limited token, provided the Transit key remains available.
- Losing an unseal threshold of keys or Vault storage can prevent Vault recovery. Maintain documented, tested recovery procedures.
- MinIO object data and PostgreSQL references must be backed up consistently; a database-only backup is incomplete.

## Migration behavior

The migration tracking model discovers eligible legacy Odoo filestore attachments, stores source metadata, then migrates in batches. It verifies uploaded content by reading it back and checking size and SHA-1 before updating the Odoo storage reference. The normal migration path has a 100 MiB per-file limit. Review the current source before changing this limit or migration behavior.
