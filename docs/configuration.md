# Configuration reference

All variables must be present in the **environment of the Odoo server process**. A Docker Compose `.env` file only supplies variables to Compose interpolation and the containers explicitly configured to receive them; it does not automatically configure a separately launched Odoo process.

| Variable | Required | Purpose |
|---|---:|---|
| `ODOO_SECURE_STORAGE_ENABLED` | Yes for attachment storage/migration | Boolean: `1`, `true`, `yes`, `on` enables storage |
| `ODOO_SECURE_MINIO_ENDPOINT` | Yes | MinIO host:port, without URL scheme |
| `ODOO_SECURE_MINIO_ACCESS_KEY` | Yes | MinIO access key |
| `ODOO_SECURE_MINIO_SECRET_KEY` | Yes | MinIO secret key |
| `ODOO_SECURE_MINIO_BUCKET` | Yes | Existing bucket name |
| `ODOO_SECURE_MINIO_TLS` | Yes | `true` for HTTPS, `false` for HTTP |
| `ODOO_SECURE_STORAGE_MASTER_KEY` | Yes for encrypted attachment reads/writes | Base64 string decoding to exactly 32 bytes |
| `ODOO_VAULT_ADDR` | Yes for Vault-backed secure documents | Vault URL, e.g. `https://vault.example.internal:8200` |
| `ODOO_VAULT_TOKEN` | Yes for Vault-backed secure documents | Limited token with Transit encrypt/decrypt permissions |
| `ODOO_VAULT_TRANSIT_KEY` | Yes for Vault-backed secure documents | Transit key name; default in code is `odoo-documents` |
| `ODOO_VAULT_TRANSIT_MOUNT` | Yes for Vault-backed secure documents | Transit mount; default in code is `transit` |
| `ODOO_VAULT_CA_BUNDLE` | Optional | Path to CA bundle used to verify Vault TLS |

## Generate the attachment master key

Generate 32 cryptographically random bytes and Base64-encode them. Example using Python:

```python
import base64
import secrets
print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
```

Run this once per environment. Store the result in a secret manager and secure offline backup. Do not regenerate it on every restart or deployment. Do not use the same value across development, test and production.

## Boolean values

Use explicit values such as `1` or `0`. For MinIO TLS, set `false` only for local development on a trusted loopback interface. Production should use HTTPS.

## Environment separation

Maintain separate credentials, buckets, master keys, Vault Transit keys/tokens and persistent volumes for development, test/staging and production. Never copy production secrets into developer workstations.
