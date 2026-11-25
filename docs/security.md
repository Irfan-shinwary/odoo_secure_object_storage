# Security operations

## Secrets

Never commit or distribute:
- `.env` files containing real credentials.
- Vault root tokens, application tokens or unseal/recovery keys.
- MinIO root passwords or application secret keys.
- Database passwords, dumps, private TLS keys or certificate private material.

Use a secrets manager or protected service environment. Restrict read access to the Odoo service account and authorized administrators.

## Key separation

- **DEKs:** each attachment receives a cryptographically random 32-byte data-encryption key. The DEK encrypts that one object using AES-256-GCM.
- **Vault Transit key:** wraps and unwraps DEKs. Keep its persistent storage protected and backed up.
- **Vault unseal/recovery keys:** unlock Vault's storage; they are not application encryption keys.
- **Vault application token:** authenticates Odoo to Transit; it is not an encryption key. Give it only the Transit encrypt/decrypt permissions required by the addon.

Do not substitute one for another. Do not log plaintext DEKs, Vault tokens, or wrapped-key metadata.

## Network and TLS

- Do not expose MinIO or Vault administration interfaces publicly.
- Use TLS for production connections.
- Restrict network access by source and destination.
- Use separate administrative and application identities.
- Rotate service credentials through a planned process and validate application behavior after rotation.

## Access control and auditing

Review Odoo groups and record access rules. Review Vault audit-device configuration and MinIO audit/logging capabilities for your deployment. Protect logs because they may reveal identifiers, paths, operational metadata or error details.

## Key rotation and recovery

Vault Transit key rotation and key-version retention must be planned around existing wrapped DEKs. Do not delete old Transit key versions or destroy Transit key material while objects still depend on them. Back up Vault's persistent data and test recovery before production.
