# Security operations

## Secrets

Never commit or distribute:
- `.env` files containing real credentials.
- Vault root tokens, application tokens or unseal/recovery keys.
- MinIO root passwords or application secret keys.
- `ODOO_SECURE_STORAGE_MASTER_KEY`.
- Database passwords, dumps, private TLS keys or certificate private material.

Use a secrets manager or protected service environment. Restrict read access to the Odoo service account and authorized administrators.

## Key separation

- Attachment master key: 32 random bytes encoded as Base64; required by the current `ir.attachment` encryption implementation.
- Vault Transit key: protects wrapped DEKs for the separate `secure.document` workflow.
- Vault unseal keys: unlock Vault's storage; they are not application encryption keys.
- Vault application token: authenticates Odoo to Transit; it is not an encryption key.

Do not substitute one for another.

## Network and TLS

- Do not expose MinIO or Vault administration interfaces publicly.
- Use TLS for production connections.
- Restrict network access by source and destination.
- Use separate administrative and application identities.
- Rotate service credentials through a planned process and validate application behavior after rotation.

## Access control and auditing

Review Odoo groups and record access rules. Review Vault audit-device configuration and MinIO audit/logging capabilities for your deployment. Protect logs because they may reveal identifiers, paths, operational metadata or error details.

## Key rotation

Do not rotate the attachment master key without a tested re-encryption/multi-key migration design. Existing objects are derived from that key. For Vault Transit, understand key-version retention and the effect on existing ciphertext before rotating or deleting key versions. Back up and test recovery first.
