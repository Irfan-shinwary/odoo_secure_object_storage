# Odoo Secure Object Storage

Odoo 17 addon for encrypted private MinIO object storage.

Repository: https://github.com/Irfan-shinwary/odoo_secure_object_storage

> **Security and scope notice:** This repository currently contains two distinct encrypted-storage implementations. The `ir.attachment` integration uses AES-256-GCM with a key derived from `ODOO_SECURE_STORAGE_MASTER_KEY`; the separate `secure.document` model uses a random 32-byte data-encryption key (DEK) wrapped by HashiCorp Vault Transit. Do not assume that Vault Transit currently wraps the keys used by the `ir.attachment` path. See [Architecture](docs/architecture.md).

## Features

- Odoo 17 `ir.attachment` storage in private MinIO.
- AES-GCM chunked encryption for attachment objects; 4 MiB chunks.
- Compatibility readers for attachment formats `ODOOENC1` and `ODOOENC2`.
- Object references stored in PostgreSQL as `secure-minio://<bucket>/<object-key>`.
- Attachment discovery and migration tracking, including pending, processing, migrated, failed and skipped states.
- Automatic discovery and migration through Odoo scheduled actions.
- Separate `secure.document` model using streaming AES-GCM and Vault Transit-wrapped DEKs.
- MinIO and Vault integration services.

## Requirements

- Odoo 17.
- Python dependencies: `minio`, `cryptography`, `requests`.
- A reachable MinIO server and an existing private bucket.
- A reachable Vault server with Transit enabled for the `secure.document` feature.
- A stable, securely backed-up 32-byte Base64 master key for the `ir.attachment` encryption path.

## Quick start

1. Clone this repository into an Odoo addons directory.
2. Install the Python dependencies in the same Python environment used by Odoo:
   `pip install minio cryptography requests`
3. Deploy MinIO and create a private bucket.
4. Generate and securely store a 32-byte master key, Base64-encoded. Configure the required environment variables listed in [Configuration](docs/configuration.md).
5. Restart Odoo, update the Apps list, and install **Secure Encrypted Object Storage**.
6. Test upload, download and deletion with non-production documents before enabling migration.
7. Follow [Installation](docs/installation.md) and [Testing](docs/testing.md) for complete steps.

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

- Never commit `.env`, Vault tokens, Vault unseal keys, MinIO passwords, master keys, database dumps, MinIO data or Vault data.
- The attachment master key is critical: losing it makes existing `ir.attachment` objects encrypted by this implementation unreadable.
- Vault unseal keys and the Vault recovery procedure are separate from the application token.
- Do not enable automatic migration until upload/download tests and backups have been verified.
- Test restore procedures, not just backup creation.

## Current implementation limitations to validate before production

- The attachment encryption path currently depends on one configured master key rather than per-object DEKs wrapped by Transit.
- The migration implementation rejects files larger than 100 MiB in its normal batch path.
- The supplied Vault listener example is HTTP without TLS and is for local development only.
- The repository currently contains Python bytecode cache files and duplicate/older source files. Review and remove generated artifacts and obsolete files in a separate code-cleanup change after confirming they are not referenced.
- No automated deployment or end-to-end test run is claimed by this documentation commit.

## License

LGPL-3.0, as declared by the addon manifest. See [LICENSE](LICENSE) if present in the repository; confirm the repository's license file before redistributing.
