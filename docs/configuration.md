# Configuration reference

Set the required variables in the **environment of the Odoo server process**. A Docker Compose `.env` file supplies variables to Compose and containers explicitly configured to receive them; it does not automatically configure a separately launched Odoo process.

The attachment storage backend is opt-in. Set `ODOO_SECURE_STORAGE_ENABLED=1` to enable it. MinIO and Vault settings must be available to the Odoo process when the corresponding storage workflows are used.

| Variable | Requirement | Default | Purpose |
|---|---|---|---|
| `ODOO_SECURE_STORAGE_ENABLED` | Required to enable attachment storage/migration | `false` | Boolean: `1`, `true`, `yes`, `on` enable storage |
| `ODOO_SECURE_MINIO_ENDPOINT` | Required for MinIO storage | — | MinIO host and port, without URL scheme |
| `ODOO_SECURE_MINIO_ACCESS_KEY` | Required for MinIO storage | — | MinIO access key |
| `ODOO_SECURE_MINIO_SECRET_KEY` | Required for MinIO storage | — | MinIO secret key |
| `ODOO_SECURE_MINIO_BUCKET` | Required for MinIO storage | — | Existing private bucket name |
| `ODOO_SECURE_MINIO_TLS` | Optional | `true` | Enable HTTPS for MinIO; use `false` only for trusted local development |
| `ODOO_VAULT_ADDR` | Required for Vault operations | — | Vault URL, e.g. `https://vault.example.internal:8200` |
| `ODOO_VAULT_TOKEN` | Required for Vault operations | — | Limited token with the required Transit encrypt/decrypt permissions |
| `ODOO_VAULT_TRANSIT_KEY` | Optional | `odoo-documents` | Vault Transit key name |
| `ODOO_VAULT_TRANSIT_MOUNT` | Optional | `transit` | Vault Transit secrets-engine mount |
| `ODOO_VAULT_CA_BUNDLE` | Optional | System CA verification | Path to a CA bundle used to verify Vault TLS |
| `ODOO_SECURE_STORAGE_ORPHAN_GRACE_HOURS` | Optional | `24` | Minimum age, in hours, before an unreferenced encrypted object can be considered for orphan cleanup. The implementation enforces a minimum of 24 hours. |

## Encryption and key management

Odoo attachments use a randomly generated 32-byte Data Encryption Key (DEK) per object. Vault Transit wraps the DEK; AES-256-GCM encrypts the attachment in authenticated chunks. The wrapped DEK is stored as MinIO object metadata. The application does not require a static attachment master-key environment variable.

The streaming encryption implementation uses a default chunk size of 4 MiB and accepts chunk sizes up to 16 MiB.

Keep Vault's persistent data and Transit key material backed up. Losing the Transit key material can make objects encrypted under its wrapped DEKs unreadable. Losing an Odoo application token is recoverable by issuing a replacement limited token while preserving the Transit key.

## Migration limit

The normal attachment migration workflow has an initial per-file limit of 100 MiB. Files larger than this limit are skipped by that workflow. This limit is separate from the streaming encryption chunk-size limit.

## Boolean values and TLS

Use explicit boolean values such as `1` or `0`. For MinIO TLS, the default is `true`. Set it to `false` only for local development on a trusted loopback interface. Production deployments should use HTTPS with certificate verification.

## Environment separation

Maintain separate MinIO credentials, buckets, Vault Transit keys/tokens and persistent volumes for development, test/staging and production. Never copy production secrets into developer workstations.
