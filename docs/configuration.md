# Configuration reference

All variables must be present in the **environment of the Odoo server process**. A Docker Compose `.env` file supplies variables to Compose and containers explicitly configured to receive them; it does not automatically configure a separately launched Odoo process.

| Variable | Required | Purpose |
|---|---:|---|
| `ODOO_SECURE_STORAGE_ENABLED` | Yes for attachment storage/migration | Boolean: `1`, `true`, `yes`, `on` enables storage |
| `ODOO_SECURE_MINIO_ENDPOINT` | Yes | MinIO host:port, without URL scheme |
| `ODOO_SECURE_MINIO_ACCESS_KEY` | Yes | MinIO access key |
| `ODOO_SECURE_MINIO_SECRET_KEY` | Yes | MinIO secret key |
| `ODOO_SECURE_MINIO_BUCKET` | Yes | Existing private bucket name |
| `ODOO_SECURE_MINIO_TLS` | Yes | `true` for HTTPS, `false` for local HTTP development |
| `ODOO_VAULT_ADDR` | Yes | Vault URL, e.g. `https://vault.example.internal:8200` |
| `ODOO_VAULT_TOKEN` | Yes | Limited token with Transit encrypt/decrypt permissions |
| `ODOO_VAULT_TRANSIT_KEY` | Yes | Transit key name; default is `odoo-documents` |
| `ODOO_VAULT_TRANSIT_MOUNT` | Yes | Transit mount; default is `transit` |
| `ODOO_VAULT_CA_BUNDLE` | Optional | Path to CA bundle used to verify Vault TLS |

## Encryption and key management

Odoo attachments use a randomly generated 32-byte Data Encryption Key (DEK) per object. Vault Transit wraps the DEK; AES-256-GCM encrypts the attachment in authenticated chunks. The wrapped DEK is stored as MinIO object metadata. The application does not require a static attachment master-key environment variable.

Keep Vault's persistent data and Transit key material backed up. Losing the Transit key material can make objects encrypted under its wrapped DEKs unreadable. Losing an Odoo application token is recoverable by issuing a replacement limited token while preserving the Transit key.

## Boolean values

Use explicit values such as `1` or `0`. For MinIO TLS, set `false` only for local development on a trusted loopback interface. Production should use HTTPS.

## Environment separation

Maintain separate MinIO credentials, buckets, Vault Transit keys/tokens and persistent volumes for development, test/staging and production. Never copy production secrets into developer workstations.
