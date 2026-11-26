# Developer setup – PyCharm and local Odoo

## 1. Project layout

Example Windows paths from the project maintainer's development environment:

- Odoo root: `D:\Code\Odoo\Odoo-17`
- Addons directory: `D:\Code\Odoo\Odoo-17\server_custom`
- Addon: `D:\Code\Odoo\Odoo-17\server_custom\odoo_secure_object_storage`
- Odoo config: `D:\Code\Odoo\Odoo-17\configuration\odoo.conf`

Use your own paths if different. Ensure the custom addons directory is included in `addons_path`.

## 2. Python interpreter and dependencies

In PyCharm, select the same virtual environment used by Odoo. Install:

```powershell
python -m pip install minio cryptography requests
```

Confirm the packages are installed in that interpreter, not a global Python installation.

## 3. Start infrastructure

From the directory containing `docker-compose.yml`:

```powershell
Copy-Item .env.example .env
docker compose up -d vault minio
docker compose ps
```

Edit the local `.env` first and set strong development credentials. Initialize/unseal Vault and create its Transit key/policy using [Vault setup](vault-setup.md). Create the MinIO bucket using [MinIO setup](minio-setup.md).

## 4. Configure PyCharm Run/Debug

Open **Run → Edit Configurations** and select the Odoo run configuration.

- Script: path to `odoo-bin`, e.g. `D:/Code/Odoo/Odoo-17/odoo/odoo-bin`
- Script parameters: `-c D:\Code\Odoo\Odoo-17\configuration\odoo.conf -d <development_database>`
- Working directory: Odoo root directory.
- Python interpreter: the Odoo virtual environment.

Under **Environment variables**, add each variable as a separate name/value entry. Do not paste a multi-line shell export statement into the field. Example values:

```text
ODOO_SECURE_STORAGE_ENABLED=1
ODOO_SECURE_MINIO_ENDPOINT=127.0.0.1:9000
ODOO_SECURE_MINIO_ACCESS_KEY=<development-access-key>
ODOO_SECURE_MINIO_SECRET_KEY=<development-secret-key>
ODOO_SECURE_MINIO_BUCKET=odoo-secure-documents
ODOO_SECURE_STORAGE_ORPHAN_GRACE_HOURS=24
ODOO_SECURE_MINIO_TLS=false
ODOO_VAULT_ADDR=http://127.0.0.1:8200
ODOO_VAULT_TOKEN=<limited-development-token>
ODOO_VAULT_TRANSIT_KEY=odoo-documents
ODOO_VAULT_TRANSIT_MOUNT=transit
```

Add `ODOO_VAULT_CA_BUNDLE` only if needed for a private CA certificate. Do not add real production values to PyCharm project files or screenshots.

The variables shown in PyCharm belong to the Odoo process. The Compose `.env` file is read by Docker Compose; it does not automatically populate PyCharm's environment-variable list.

## 5. Odoo configuration

Ensure `odoo.conf` has the correct database connection and addons path. For scheduled actions, ensure cron workers are enabled; Odoo's `max_cron_threads` can be set to a positive value such as `2` in a local development setup. Restart Odoo after editing the config or environment.

## 6. Upgrade the addon

For development, use the Odoo command line with the selected database and addon update option, or upgrade the module through Apps. Back up the database before upgrades that affect migration models or attachment storage.

## 7. Windows path note

When Odoo runs directly on Windows and Docker publishes MinIO/Vault ports to localhost, use `127.0.0.1`. If Odoo runs inside Docker, use the service name on a shared Docker network instead.
