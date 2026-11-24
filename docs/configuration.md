# Configuration reference

All variables must be present in the **environment of the Odoo server process**. A Docker Compose `.env` file only supplies variables to Compose interpolation and containers explicitly configured to receive them; it does not automatically configure a separately launched Odoo process.

| Variable | Required | Purpose |
|---|---:|---|
| `ODOO_SECURE_STORAGE_ENABLED` | Yes for attachment storage/migration | Boolean: `1`, `true`, `yes`, `on` enables storage |
| `ODOO_SECURE_MINIO_ENDPOINT` | Yes | MinIO host:port, without URL scheme |
| `ODOO_SECURE_MINIO_ACCESS_KEY` | Yes | MinIO access key |
| `ODOO_SECURE_MINIO_SECRET_KEY` | Yes | MinIO secret key |
| `ODOO_SECURE_MINIO_BUCKET` | Yes | Existing bucket name |
| `ODOO_SECURE_MINIO_TLS` | Yes | `true` for HTTPS, `false` for local development only |
| `ODOO_VAULT_ADDR` | Yes for Vault-backed attachment writes and reads | Vault URL, e.g. `https://vault.example.internal:8200` |
| `ODOO_VAULT_TOKEN` | Yes for Vault-backed attachment writes and reads | Limited token with Transit encrypt/decrypt permissions |
| `ODOO_VAULT_TRANSIT_KEY` | Yes | Transit key name; default in code is `odoo-documents` |
| `ODOO_VAULT_TRANSIT_MOUNT` | Yes | Transit mount; default in code is `transit` |
| `ODOO_VAULT_CA_BUNDLE` | Optional | CA bundle path used to verify Vault TLS |
| `ODOO_SECURE_STORAGE_MASTER_KEY` | Only for legacy `ODOOENC1`/`ODOOENC2` reads | Base64 string decoding to exactly 32 bytes |

## Vault Transit setup

Enable the Transit secrets engine and create the configured key before using Vault-backed attachment storage. The runtime token must be allowed to call the Transit `encrypt` and `decrypt` endpoints for that key. It should not receive broad Vault administration or key-management permissions.

Use a separate administrative identity for key creation, rotation and policy administration. Do not configure Odoo with a Vault root token.

## Legacy master key

Only configure `ODOO_SECURE_STORAGE_MASTER_KEY` if the Odoo database still references legacy `ODOOENC1` or `ODOOENC2` encrypted objects. It must be Base64 and decode to exactly 32 bytes. Preserve the exact historical value in a protected backup until no legacy objects remain and restore testing proves it is no longer needed.

## Environment separation

Maintain separate credentials, buckets, Vault Transit keys/tokens and persistent volumes for development, test/staging and production. Never copy production secrets into developer workstations.
