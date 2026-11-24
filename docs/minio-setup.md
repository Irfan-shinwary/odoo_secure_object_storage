# MinIO setup

## Development

The repository's root `docker-compose.yml` starts MinIO with a persistent Docker volume and binds its API and console ports to localhost:

- S3 API: `127.0.0.1:9000`
- Console: `127.0.0.1:9001`

Create a local `.env` from `.env.example`, replace the MinIO password with a strong unique value, then start the service:

```bash
docker compose up -d minio
docker compose ps
docker compose logs minio
```

Open `http://127.0.0.1:9001` and sign in using the local development credentials from your uncommitted `.env`.

Create a bucket named `odoo-secure-documents` (or use the exact name configured in Odoo). Keep the bucket private; do not enable anonymous/public access.

## Odoo connection

Set:

```dotenv
ODOO_SECURE_MINIO_ENDPOINT=127.0.0.1:9000
ODOO_SECURE_MINIO_ACCESS_KEY=<development-access-key>
ODOO_SECURE_MINIO_SECRET_KEY=<development-secret-key>
ODOO_SECURE_MINIO_BUCKET=odoo-secure-documents
ODOO_SECURE_MINIO_TLS=false
```

The endpoint is a host:port value, not a URL. If Odoo runs in another container, `127.0.0.1` refers to that Odoo container, not the MinIO container. Use the Compose service DNS name and internal port on a shared Docker network.

## Production

- Use a supported, maintained MinIO distribution/version and pin the image to a tested immutable version; do not rely on `:latest`.
- Use HTTPS/TLS and restrict network access to Odoo application hosts.
- Create a dedicated least-privilege MinIO identity for the application rather than using the root account.
- Restrict bucket access to the required bucket and operations.
- Enable encryption-at-rest at the infrastructure/storage layer where required; this is additional to application-level encryption.
- Monitor capacity, availability and audit logs.
- Back up object data and validate restore procedures.

The development Compose file uses the image supplied during project setup. Verify its provenance, maintenance status and version before adopting it in production.
