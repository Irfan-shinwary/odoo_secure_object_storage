# Production deployment guide

This is a deployment checklist, not a claim that production infrastructure has been tested. Have the organization's infrastructure and security teams approve the final design.

## Do not deploy the development Compose configuration unchanged

The included Compose file uses:
- Vault HTTP with TLS disabled.
- A local file storage backend.
- Local loopback port publishing.
- Development credentials supplied through a local environment file.
- A MinIO image tag of `:latest`.

Production must use a supported, pinned and scanned image, TLS, network restrictions, dedicated service identities and an approved persistent storage/HA design.

## Recommended topology

- Odoo application nodes in a private application network.
- MinIO in a private storage network, reachable only from authorized application/administration hosts.
- Vault in a protected security-services network, reachable only from authorized clients and administrators.
- PostgreSQL protected independently with encryption, backups and restricted access.
- Centralized logs, monitoring, alerting and time synchronization.
- Separate development, test/staging and production resources and credentials.

## Deployment sequence

1. Provision production hosts, storage, DNS, firewall rules, TLS certificates and monitoring.
2. Deploy a supported MinIO version with persistent, resilient storage. Create a private bucket and least-privilege Odoo identity.
3. Deploy Vault using an approved production storage backend and TLS. Configure HA/auto-unseal only according to organizational requirements.
4. Initialize Vault once, securely distribute unseal/recovery material, enable Transit and create the required key and limited policy.
5. Configure a production Vault Transit key and a dedicated limited Odoo runtime identity/token. Preserve the historical Base64 32-byte attachment master key in a protected secret store only if legacy `ODOOENC1`/`ODOOENC2` objects remain.
6. Configure Odoo service environment through the deployment platform's secret manager, not a committed `.env` file.
7. Install the exact reviewed addon commit and Python dependencies in the Odoo environment.
8. Test upload, download, secure-document Transit operations, access control and restore in staging.
9. Back up production PostgreSQL, filestore and object storage before enabling migration.
10. Start migration with a small batch, monitor logs and errors, then increase only after measuring throughput and resource impact.

## Required environment values

Configure the variables listed in [Configuration](configuration.md). Production examples should use HTTPS endpoints and unique credentials. Do not copy development secrets.

## Odoo scheduled actions

Ensure Odoo cron processing is enabled and monitor the automatic discovery and migration jobs. The Odoo cron thread setting belongs to Odoo's configuration, not the module's environment variables. Validate scheduling after deployment and after every Odoo restart.

## Change and rollback plan

- Deploy to staging first.
- Pin the addon to a reviewed commit/tag.
- Back up PostgreSQL, the original filestore, MinIO object data and Vault persistent storage/Transit key material before migration or upgrade.
- Do not delete source filestore data immediately after migration.
- If migration fails, stop further migration, preserve logs and failed records, and investigate before retrying.
- A rollback of Python code alone may not reverse attachment references already migrated to MinIO. Ensure the previous code can still read secure references or prepare a tested data rollback procedure.
