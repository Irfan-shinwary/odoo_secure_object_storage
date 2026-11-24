# Odoo Secure Object Storage

Odoo 17 addon for encrypted private MinIO object storage.

Repository: https://github.com/Irfan-shinwary/odoo_secure_object_storage

## Features

- Odoo 17 `ir.attachment` storage in private MinIO.
- A cryptographically random 32-byte data-encryption key (DEK) generated per attachment object.
- Vault Transit wrapping/unwrapping of attachment DEKs.
- AES-256-GCM chunked streaming encryption; 4 MiB default chunks.
- New attachment objects use the `ODSDOC01` stream format.
- Backward-compatible readers for legacy `ODOOENC1` and `ODOOENC2` attachment objects.
- Object references stored in PostgreSQL as `secure-minio://<bucket>/<object-key>`.
- Attachment discovery and migration tracking, including pending, processing, migrated, failed and skipped states.
- Separate `secure.document` model using the same Vault Transit key-provider and streaming-encryption services.
- MinIO and Vault integration services.

## Encryption architecture

### Current `ir.attachment` path

1. Odoo receives attachment bytes.
2. The addon generates a random 32-byte DEK for that object.
3. Vault Transit wraps the DEK; the wrapped value is stored as MinIO object metadata.
4. The plaintext is encrypted using AES-256-GCM in authenticated chunks.
5. The encrypted object is uploaded to MinIO with its format identifier and integrity metadata.
6. Odoo stores a `secure-minio://` reference in `ir.attachment.store_fname`.
7. During reads, the addon fetches object metadata, asks Vault to unwrap the DEK, authenticates/decrypts the stream and returns the plaintext through Odoo's attachment API.

### Legacy compatibility

Existing `ODOOENC1` and `ODOOENC2` objects are still readable using `ODOO_SECURE_STORAGE_MASTER_KEY`, which must be Base64 and decode to exactly 32 bytes. This master key is required for legacy reads; it is not used to encrypt new Vault-backed `ir.attachment` objects.

Do not remove the legacy key or reader until every legacy object has been inventoried, migrated, independently verified and included in a successful restore test.

See [Architecture](docs/architecture.md) for details.

## Requirements

- Odoo 17.
- Python dependencies: `minio`, `cryptography`, `requests`.
- A reachable MinIO server and an existing private bucket.
- A reachable Vault server with Transit enabled and a Transit key configured for the addon.
- A dedicated Vault token with only the required Transit encrypt/decrypt permissions.
- The legacy master key only if the database still contains `ODOOENC1` or `ODOOENC2` objects.

## Quick start

1. Clone this repository into an Odoo addons directory.
2. Install Python dependencies in the same Python environment used by Odoo:
   `pip install minio cryptography requests`
3. Deploy MinIO and create a private bucket.
4. Configure Vault Transit and create the Transit key.
5. Configure the environment variables listed in [Configuration](docs/configuration.md).
6. Restart Odoo, update the Apps list, and install **Secure Encrypted Object Storage**.
7. Test attachment upload, download, replacement and deletion using non-production documents.
8. Follow [Installation](docs/installation.md) and [Testing](docs/testing.md) before enabling migration.

## Development infrastructure

A local-only Docker Compose example is provided in [docker-compose.yml](docker-compose.yml). It is for development and integration testing only. It binds service ports to loopback and uses a Vault HTTP listener without TLS. Do not deploy it unchanged in production.

Copy `.env.example` to a local `.env` for Docker service credentials. Odoo's environment must also receive the addon variables; Docker Compose does not automatically inject variables into a separately running PyCharm/Windows Odoo process. See [PyCharm development](docs/development.md).

## Documentation

- [Architecture and key handling](docs/architecture.md)
- [Installation](docs/installation.md)
- [Configuration reference](docs/configuration.md)
- [Vault setup](docs/vault-setup.md)
- [MinIO setup](docs/minio-setup.md)
- [PyCharm development](docs/development.md)
- [Testing and migration](docs/testing.md)
- [Production deployment](docs/production-deployment.md)
- [Security operations](docs/security.md)
- [Backup and recovery](docs/backup-recovery.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Source-level security review](docs/security-review.md)

## Important operational rules

- Never commit `.env`, Vault tokens, Vault unseal keys, MinIO passwords, legacy master keys, database dumps, MinIO data or Vault data.
- Vault Transit key material and its persistent storage are critical: losing them can make wrapped DEKs unusable.
- Preserve the legacy master key for as long as any `ODOOENC1` or `ODOOENC2` object remains.
- Use separate credentials, buckets, Transit keys and persistent volumes for development, staging and production.
- Do not enable automatic migration until backups, restore procedures and upload/download tests have been verified.
- Test restore procedures, not just backup creation.

## Current implementation limitations to validate before production

- Odoo's attachment API ultimately returns complete attachment bytes; chunked cryptography reduces crypto working-set size but does not make the final Odoo read fully streaming.
- The normal legacy filestore migration path rejects files larger than 100 MiB.
- The supplied Vault listener example is HTTP without TLS and is for local development only.
- The repository contains historical/backup-style files and generated Python cache artifacts that should be reviewed separately.
- No automated deployment or end-to-end production test run is claimed by this documentation.
 
## License

The addon manifest declares LGPL-3.0. Ensure the repository contains the matching license text before redistribution.
