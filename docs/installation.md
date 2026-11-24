# Installation – Odoo 17

## 1. Prerequisites

- Odoo 17 running with a supported Python environment.
- PostgreSQL configured for Odoo.
- MinIO endpoint reachable from the Odoo host.
- A private bucket already created in MinIO.
- Python packages `minio`, `cryptography` and `requests` installed in Odoo's Python environment.
- A configured Vault Transit key and limited application token for new attachment writes and reads.
- The historical Base64-encoded 32-byte attachment master key only if legacy `ODOOENC1` or `ODOOENC2` objects remain.

Vault Transit is required by the current `ir.attachment` encryption path and the separate `secure.document` workflow. See [Architecture](architecture.md) for the new DEK-wrapping flow and legacy compatibility.

## 2. Install the addon source

Clone the repository into an addons directory included in Odoo's `addons_path`:

```bash
git clone https://github.com/Irfan-shinwary/odoo_secure_object_storage.git
```

For an existing Odoo custom-addons directory, ensure the resulting layout is:

```text
<custom_addons>/
  odoo_secure_object_storage/
    __manifest__.py
    models/
    services/
    security/
    data/
    views/
    wizard/
```

Do not clone into an extra nested directory that prevents Odoo from finding `__manifest__.py`.

## 3. Install Python dependencies

Activate the exact virtual environment used to start Odoo, then:

```bash
python -m pip install minio cryptography requests
python -m pip show minio cryptography requests
```

## 4. Configure the Odoo process

Set the variables in [Configuration](configuration.md). At minimum, new attachment storage requires the MinIO variables, `ODOO_SECURE_STORAGE_ENABLED`, and Vault Transit variables. `ODOO_SECURE_STORAGE_MASTER_KEY` is only needed while legacy `ODOOENC1` or `ODOOENC2` objects remain.

Restart Odoo after changing environment variables. Odoo reads process environment at runtime; changing a file does not update an already running process.

## 5. Install through Odoo

1. Start Odoo.
2. Sign in as an administrator.
3. Open Apps and update the Apps list if required.
4. Search for **Secure Encrypted Object Storage**.
5. Install the addon.
6. Confirm the Secure Storage menus are visible.
7. Confirm the scheduled actions **Secure Storage: Automatic Discovery** and **Secure Storage: Automatic Migration** exist.

The manifest declares Python dependencies `minio`, `cryptography`, and `requests`, and depends on Odoo modules `base` and `web`.

## 6. Initial validation – before migration

1. Keep automatic migration disabled.
2. Upload a small non-sensitive test attachment.
3. Confirm the attachment is stored in the configured MinIO bucket.
4. Download it through Odoo and compare its content with the original.
5. Restart Odoo and repeat the download test.
6. Test a zero-byte file and a file larger than one encryption chunk.
7. Verify that unauthorized users cannot access protected documents.

Do not run bulk migration until these checks and a backup/restore test succeed.
