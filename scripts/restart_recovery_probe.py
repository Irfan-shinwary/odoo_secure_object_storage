#!/usr/bin/env python3
"""Create, verify, or clean up a secure attachment across an Odoo restart.

The manifest contains only a record ID, object reference, and SHA-256 digest.
It does not contain attachment plaintext or credentials.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from benchmark_odoo_e2e import OdooClient, build_payload, load_project_env


def settings(args):
    load_project_env()
    url = args.url or os.getenv("ODOO_BENCH_URL")
    database = args.database or os.getenv("ODOO_BENCH_DB")
    username = args.username or os.getenv("ODOO_BENCH_USERNAME")
    password = args.password or os.getenv("ODOO_BENCH_PASSWORD")
    missing = [
        name for name, value in (
            ("URL", url), ("database", database),
            ("username", username), ("password", password),
        ) if not value
    ]
    if missing:
        raise SystemExit("Missing Odoo settings: " + ", ".join(missing))
    return url, database, username, password


def read_attachment(client, attachment_id):
    rows = client.call_kw(
        "ir.attachment", "read", [[attachment_id]],
        {"fields": ["id", "name", "datas", "store_fname", "file_size"]},
    )
    if not rows:
        raise RuntimeError("Attachment record does not exist.")
    return rows[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify", "cleanup"))
    parser.add_argument("--manifest", required=True, help="JSON manifest path")
    parser.add_argument("--url")
    parser.add_argument("--database")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--size-mib", type=int, default=2)
    args = parser.parse_args()

    url, database, username, password = settings(args)
    manifest_path = Path(args.manifest).expanduser().resolve()
    client = OdooClient(url, database, username, password, args.timeout)
    client.login()

    if args.mode == "create":
        if manifest_path.exists():
            raise SystemExit("Manifest already exists; refusing to overwrite it.")
        if args.size_mib < 1 or args.size_mib > 64:
            raise SystemExit("--size-mib must be between 1 and 64.")
        payload = os.urandom(args.size_mib * 1024 * 1024)
        digest = hashlib.sha256(payload).hexdigest()
        name = "secure-storage-restart-probe-" + uuid.uuid4().hex + ".bin"
        attachment_id = client.call_kw(
            "ir.attachment", "create",
            [{
                "name": name,
                "type": "binary",
                "mimetype": "application/octet-stream",
                "datas": base64.b64encode(payload).decode("ascii"),
            }],
        )
        record = read_attachment(client, attachment_id)
        store_fname = record.get("store_fname") or ""
        if not store_fname.startswith("secure-minio://"):
            client.call_kw("ir.attachment", "unlink", [[attachment_id]])
            raise RuntimeError(
                "Attachment did not use secure MinIO storage. "
                "Check ODOO_SECURE_STORAGE_ENABLED in the Odoo server process."
            )
        manifest = {
            "database": database,
            "attachment_id": attachment_id,
            "name": name,
            "store_fname": store_fname,
            "size_bytes": len(payload),
            "sha256": digest,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\\n", encoding="utf-8"
        )
        print("Created secure restart probe.")
        print("Attachment ID: {}".format(attachment_id))
        print("Size: {} bytes".format(len(payload)))
        print("SHA-256: {}".format(digest))
        print("Storage reference: secure-minio:// (full value saved in manifest)")
        print("Manifest: {}".format(manifest_path))
        print("Now restart Odoo and/or MinIO/Vault, then run mode 'verify'.")

    else:
        if not manifest_path.is_file():
            raise SystemExit("Manifest does not exist: {}".format(manifest_path))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("database") != database:
            raise SystemExit("Manifest database does not match selected database.")
        attachment_id = int(manifest["attachment_id"])

        if args.mode == "verify":
            record = read_attachment(client, attachment_id)
            if record.get("store_fname") != manifest.get("store_fname"):
                raise RuntimeError("Attachment storage reference changed.")
            encoded = record.get("datas")
            if not encoded:
                raise RuntimeError("Odoo returned no attachment data.")
            actual = hashlib.sha256(base64.b64decode(encoded)).hexdigest()
            if actual != manifest["sha256"]:
                raise RuntimeError("SHA-256 mismatch after restart/recovery.")
            print("PASS: attachment survived restart/recovery.")
            print("Attachment ID: {}".format(attachment_id))
            print("SHA-256: {}".format(actual))
        else:
            client.call_kw("ir.attachment", "unlink", [[attachment_id]])
            print("Deleted restart probe attachment ID {}.".format(attachment_id))
            manifest_path.unlink()
            print("Deleted manifest: {}".format(manifest_path))


if __name__ == "__main__":
    main()
