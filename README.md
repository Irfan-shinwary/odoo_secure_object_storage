# Odoo Secure Object Storage

Odoo 17 addon that stores attachments as authenticated encrypted objects in a private MinIO bucket. Each object uses a unique random Data Encryption Key (DEK), protected by HashiCorp Vault Transit.

Repository: https://github.com/Irfan-shinwary/odoo_secure_object_storage

## Features

- Integrates with Odoo 17 ir.attachment.
- Generates a cryptographically random 32-byte DEK for each new attachment object.
- Wraps and unwraps DEKs through HashiCorp Vault Transit.
- Encrypts attachment content using chunked AES-256-GCM (4 MiB default chunks).
- Uses the single current attachment format, ODSDOC01; legacy ODOOENC1/ODOOENC2 readers and the static attachment master-key setting have been removed.
- Stores ciphertext and wrapped-key metadata in a private MinIO bucket.
- Stores Odoo attachment metadata and secure-minio://<bucket>/<object-key> references in PostgreSQL.
- Supports the separate secure.document workflow using Vault Transit and streaming AES-GCM.
- Includes attachment discovery, migration tracking, scheduled migration and orphan-object cleanup.
- Includes automated tests for encryption workflows, integrity failures, service failures, updates, empty and multi-chunk attachments, and deletion handling.

## Architecture at a glance

1. Odoo generates a random DEK for the attachment.
2. Vault Transit wraps the DEK; Odoo uses the plaintext DEK only for the encryption operation.
3. Odoo encrypts the content in authenticated AES-GCM chunks.
4. MinIO stores the ciphertext and the Vault-wrapped DEK plus format, plaintext-size and SHA-256 metadata.
5. PostgreSQL stores the attachment record and secure MinIO object reference.
6. On download, Odoo retrieves the object, asks Vault to unwrap the DEK, authenticates/decrypts the chunks, and verifies the plaintext digest and size.

Vault Transit key material and MinIO object data are both essential to recovery. A database backup alone is not sufficient.

## Requirements

- Odoo 17.
- Python packages: minio, cryptography, requests.
- PostgreSQL supported by the selected Odoo 17 deployment.
- A reachable MinIO server and an existing private bucket.
- A reachable, initialized and unsealed Vault server with Transit enabled.
- A Transit key and a limited Odoo application token with encrypt/decrypt permissions for that key.

## Quick start

1. Clone the repository into an Odoo addons directory included in addons_path.
2. Install dependencies in the exact Python environment used by Odoo:

~~~bash
python -m pip install minio cryptography requests
~~~

3. Start or provision MinIO, create a private bucket, and create a dedicated least-privilege Odoo service account. See MinIO setup.
4. Start or provision Vault, enable Transit, create the odoo-documents key, and create a limited application policy/token. See Vault setup.
5. Configure the Odoo process environment using the Configuration reference.
6. Restart Odoo, update the Apps list, and install Secure Encrypted Object Storage.
7. Verify a small non-sensitive attachment upload, download, update and deletion before considering migration.
8. Follow the full Installation and Testing guides.

## Local development

The root docker-compose.yml is for local development and integration testing only. It binds Vault and MinIO ports to loopback and configures Vault without TLS. Do not deploy it unchanged in production.

Copy .env.example to .env and replace all placeholders. Docker Compose reads .env for Compose interpolation and configured container variables; it does not automatically inject those variables into an independently launched Windows/PyCharm Odoo process. Configure the Odoo Run/Debug environment separately or load the file explicitly in your own development launcher. See PyCharm development.

## Documentation

- Architecture and key handling: docs/architecture.md
- Installation: docs/installation.md
- Configuration reference: docs/configuration.md
- Vault Transit setup: docs/vault-setup.md
- MinIO setup: docs/minio-setup.md
- PyCharm development: docs/development.md
- Automated testing and migration: docs/testing.md
- Production deployment considerations: docs/production-deployment.md
- Security operations: docs/security.md
- Backup and recovery: docs/backup-recovery.md
- Troubleshooting: docs/troubleshooting.md
- Security review: docs/security-review.md

## Important operational rules

- Never commit .env, Vault tokens, Vault unseal/recovery keys, MinIO passwords, database dumps, private certificates, or storage data.
- Never configure the Vault root token in Odoo. Use a dedicated limited application identity.
- Protect and back up Vault persistent storage and Transit key material. Existing objects depend on Vault to unwrap their DEKs.
- Keep the MinIO bucket private and restrict the Odoo service account to the required bucket operations.
- Keep automatic migration disabled until upload/download tests and an application-consistent backup have been verified.
- Test recovery procedures, not just backup creation.

## Known limitations and deployment considerations

- The normal attachment migration path has a 100 MiB per-file limit; see Testing and migration.
- Odoo's attachment read API returns the requested content to the application process. Large downloads can therefore consume substantial worker memory even though encryption/decryption is chunked.
- The included Vault listener uses HTTP without TLS and is local-development-only. Production requires TLS and an approved Vault storage/HA/recovery design.
- The supplied MinIO Compose image is a development convenience. Verify its provenance, maintenance status and tested version; pin a supported image by immutable version/digest before production.
- The repository's automated tests use test doubles for Vault and MinIO. They validate addon logic but do not replace the live Odoo/MinIO/Vault integration checks documented in Testing.
- This project has not been represented as penetration-tested, independently security-certified, or production-deployed.

## License

This addon is distributed under the GNU Lesser General Public License v3.0. See LICENSE.
