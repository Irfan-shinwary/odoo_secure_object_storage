# Architecture and cryptographic key handling

## Components

- **Odoo 17:** attachment metadata and storage references remain in PostgreSQL. The addon overrides Odoo attachment file operations.
- **MinIO:** private S3-compatible object storage. Secure attachment references use `secure-minio://<bucket>/<32-hex-object-key>`.
- **HashiCorp Vault Transit:** wraps and unwraps random data-encryption keys (DEKs) for newly written `ir.attachment` objects and the separate `secure.document` workflow.
- **PostgreSQL:** stores Odoo attachment metadata, migration tracking records and secure-document metadata.
- **Vault object metadata:** MinIO stores the wrapped DEK and plaintext integrity metadata alongside the encrypted attachment object.

## Current Odoo `ir.attachment` encryption path

The active `models/ir_attachment.py` implementation uses the following process for new secure attachment writes:

1. Odoo supplies the attachment bytes.
2. The addon generates a cryptographically random 32-byte DEK using `secrets.token_bytes(32)`.
3. The DEK is wrapped by Vault Transit using the configured Transit key.
4. The plaintext is encrypted with AES-256-GCM using the DEK. The stream uses a 4 MiB default chunk size, a random nonce per chunk, and authenticated additional data binding the stream to the object identifier, chunk index, plaintext size and SHA-256 digest.
5. The encrypted stream is uploaded to MinIO.
6. MinIO object metadata includes the storage format identifier, Vault-wrapped DEK, plaintext size and SHA-256 digest.
7. Odoo stores a `secure-minio://<bucket>/<object-key>` reference in `ir.attachment.store_fname`.

During a read, the addon retrieves the object and its metadata, validates the expected size metadata, unwraps the DEK through Vault, then authenticates and decrypts the stream. The complete plaintext is returned through Odoo's attachment API.

New Vault-backed attachment objects use the `ODSDOC01` format. The 52-byte header contains the magic identifier, chunk size, plaintext size and SHA-256 digest. Each encrypted chunk contains a length field, a 12-byte nonce and AES-GCM ciphertext including its authentication tag.

## Legacy attachment formats

The addon retains read support for `ODOOENC1` and `ODOOENC2`.

- Legacy objects use keys derived from `ODOO_SECURE_STORAGE_MASTER_KEY` using HKDF-SHA256 with version-specific context.
- `ODOO_SECURE_STORAGE_MASTER_KEY` is Base64-encoded and must decode to exactly 32 bytes.
- The legacy reader is used only when the downloaded object begins with `ODOOENC1` or `ODOOENC2`.
- New attachment writes use Vault-wrapped DEKs and `ODSDOC01`; the legacy formats should not be generated again.

Keep the legacy key available until all legacy objects have been migrated, verified and included in a successful restore test. Do not rotate or discard it casually.

## Separate `secure.document` model

The `secure.document` model also generates a random 32-byte DEK, wraps it with Vault Transit, and encrypts content with the streaming AES-GCM service. Its wrapped key is stored in the PostgreSQL `secure.document.wrapped_key` field, whereas the `ir.attachment` integration stores the wrapped DEK as MinIO user metadata.

The two workflows share cryptographic services but have different metadata and lifecycle handling.

## Trust boundaries

- Odoo requires network access to MinIO and Vault for new attachment writes and Vault-backed reads.
- MinIO stores ciphertext and, for attachment objects, the wrapped DEK and integrity metadata.
- PostgreSQL stores attachment metadata and storage references.
- Vault Transit protects DEKs; the Odoo runtime token should have only the required encrypt/decrypt permissions.
- Administrators who can read application process environments, Vault policy/key material, PostgreSQL or object storage may have significant access. Apply least privilege and audit access.

## Key-loss implications

- Losing Vault's persistent data or the Transit key material can make wrapped DEKs unusable and therefore make new-format attachments unreadable.
- Losing the Vault token alone is recoverable by issuing a new limited token, provided the Transit key remains available.
- Losing the legacy master key makes any remaining `ODOOENC1` or `ODOOENC2` objects unreadable.
- Keep Vault recovery material and the legacy master key (while legacy objects remain) in separate, access-controlled backup procedures.

## Migration behavior

The legacy filestore migration model discovers eligible Odoo attachments, stores source metadata, then migrates in batches. It verifies uploaded content by reading it back and checking size and SHA-1 before updating the Odoo storage reference. The normal migration path has a 100 MiB per-file limit. The new secure object is produced by the active Vault-backed `_file_write` implementation.
