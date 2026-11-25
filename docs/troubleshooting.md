# Troubleshooting

## MinIO connection failure

Check:
- `ODOO_SECURE_MINIO_ENDPOINT` is host:port, without `http://`.
- MinIO is running and reachable from the Odoo host/container.
- Access key and secret match.
- Bucket exists and is private.
- TLS setting matches the endpoint.
- If Odoo runs in Docker, do not use `127.0.0.1` to refer to another container.

## Vault Transit errors

Attachment uploads and downloads require Odoo to reach Vault Transit. Confirm that Vault is initialized and unsealed, the configured Transit mount and key exist, and the Odoo application token has `update` capability on the key's `encrypt` and `decrypt` endpoints. Do not use the Vault root token as the Odoo application token.

## Vault Transit errors

For the `secure.document` workflow:
- Confirm Vault is running and unsealed.
- Confirm `ODOO_VAULT_ADDR` is reachable from Odoo.
- Confirm Transit is enabled at the configured mount.
- Confirm the key name matches `ODOO_VAULT_TRANSIT_KEY`.
- Confirm the application token has `update` capability on the encrypt and decrypt endpoints.
- Confirm TLS trust and `ODOO_VAULT_CA_BUNDLE` when using a private CA.

The Odoo Transit integration logs performance/error metadata. Never log or paste actual tokens, unseal keys or key material into support tickets.

## Attachment download fails after restart

Check that the Vault Transit key material is intact, MinIO objects and bucket exist, Odoo can reach both MinIO and Vault, and PostgreSQL references match object names.

## Migration cron does not execute

Check:
- Scheduled action is active.
- Odoo cron workers are enabled.
- Next Execution Date advances.
- The secure storage configuration has automatic migration enabled.
- `ODOO_SECURE_STORAGE_ENABLED=1` is present in the Odoo process.
- MinIO settings and bucket are correct.
- Odoo logs show the cron job start/completion and `SECURE_STORAGE_AUTO_MIGRATION` messages.

## Migration record is failed or skipped

Read the migration record's Error Details. Failed records may be retried within the configured retry limit. Skipped records can indicate the source attachment changed after discovery, was already migrated, or exceeded the current 100 MiB migration limit. Run discovery again for changed source attachments and review the record before retrying.

## Vault is sealed after restart

This is expected unless an approved auto-unseal mechanism is configured. An authorized operator must unseal it using the protected key shares. Do not put unseal keys in startup scripts or the Odoo environment.

## Preserve evidence

When escalating, provide sanitized Odoo logs, addon commit, Odoo version, relevant status/error text and environment variable *names*. Remove tokens, passwords, unseal shares, personal data and private document content.
