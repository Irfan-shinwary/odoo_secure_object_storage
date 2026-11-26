# Odoo Secure Object Storage

Odoo 17 addon for encrypted private MinIO object storage, using HashiCorp Vault Transit for per-object data-encryption-key (DEK) protection.

Repository: https://github.com/Irfan-shinwary/odoo_secure_object_storage

## Features

- Odoo 17 `ir.attachment` storage in a private MinIO bucket.
- Per-object random 32-byte DEKs wrapped and unwrapped by Vault Transit.
- AES-256-GCM authenticated streaming encryption (4 MiB default chunks).
- Current encrypted attachment format: `ODSDOC01`.
- Object references stored in PostgreSQL as `secure-minio://<bucket>/<object-key>`.
- Wrapped DEK, plaintext size and SHA-256 digest stored as MinIO object metadata.
- Attachment discovery and migration tracking, including pending, processing, migrated, failed and skipped states.
- Automatic discovery and migration through Odoo scheduled actions.
- Separate `secure.document` model using the same Vault-backed DEK architecture.
- MinIO and Vault integration services.

## Requirements

- Odoo 17.
- Python dependencies: `minio`, `cryptography`, `requests`.
- A reachable MinIO server and an existing private bucket.
- A reachable Vault server with Transit enabled, a Transit key created, and a limited application token with encrypt/decrypt permissions.

## Quick start

1. Clone this repository into an Odoo addons directory.
2. Install the Python dependencies in the same Python environment used by Odoo:
   `pip install minio cryptography requests`
3. Deploy MinIO and create a private bucket.
4. Configure Vault Transit and create a limited Odoo application token by following [Vault setup](docs/vault-setup.md).
5. Configure the Odoo process environment variables listed in [Configuration](docs/configuration.md).
6. Restart Odoo, update the Apps list, and install **Secure Encrypted Object Storage**.
7. Test upload, download and deletion with non-production documents before enabling migration.
8. Follow [Installation](docs/installation.md) and [Testing](docs/testing.md) for complete steps.

## Development infrastructure

A local-only Docker Compose example is provided in [docker-compose.yml](docker-compose.yml). It is for development and integration testing only. It binds service ports to loopback and uses Vault with TLS disabled. Do not deploy it unchanged in production.

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

## Important operational rules

- Never commit `.env`, Vault tokens, Vault unseal keys, MinIO passwords, database dumps, MinIO data or Vault data.
- Protect and back up Vault's persistent storage and Transit key material; existing objects depend on Vault to unwrap their DEKs.
- Vault unseal keys and the recovery procedure are separate from the Odoo application token.
- Do not enable automatic migration until upload/download tests and backups have been verified.
- Test restore procedures, not just backup creation.

## Current implementation limitations to validate before production

- The migration implementation rejects files larger than 100 MiB in its normal batch path.
- The supplied Vault listener example is HTTP without TLS and is for local development only.
- Review generated Python bytecode artifacts and remove them from version control in a separate repository-cleanup change.
- No automated deployment or production end-to-end test run is claimed by this documentation.

## License

LGPL-3.0, as declared by the addon manifest.
