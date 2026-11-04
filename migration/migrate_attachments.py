
"""Run inside an Odoo shell.

Example:
    odoo shell -d YOUR_DATABASE
    exec(open(r"D:\path\to\migration\migrate_attachments.py").read())
    report = inventory_attachments(env, dry_run=True)
"""

import hashlib
import json
import os

from odoo.tools import config


def _filestore_path(env, store_fname):
    if not store_fname or store_fname.startswith("secure-minio://"):
        return None

    data_dir = config.get("data_dir")
    if not data_dir:
        return None

    path = os.path.join(
        data_dir,
        "filestore",
        env.cr.dbname,
        store_fname,
    )
    return os.path.abspath(path)


def inventory_attachments(env, dry_run=True, limit=None):
    domain = [
        ("type", "=", "binary"),
        ("store_fname", "!=", False),
    ]
    attachments = env["ir.attachment"].sudo().search(
        domain, limit=limit, order="id"
    )

    report = {
        "dry_run": dry_run,
        "scanned": 0,
        "eligible": 0,
        "missing": [],
        "already_secure": [],
        "database_backed_or_unsupported": [],
        "candidates": [],
    }

    for attachment in attachments:
        report["scanned"] += 1
        fname = attachment.store_fname or ""

        if fname.startswith("secure-minio://"):
            report["already_secure"].append(attachment.id)
            continue

        path = _filestore_path(env, fname)
        if not path or not os.path.isfile(path):
            report["missing"].append(attachment.id)
            continue

        report["eligible"] += 1
        report["candidates"].append({
            "attachment_id": attachment.id,
            "name": attachment.name,
            "size": os.path.getsize(path),
            "path": path,
        })

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def sha256_file(path, chunk_size=4 * 1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def migrate_attachment(env, attachment_id, dry_run=True):
    attachment = env["ir.attachment"].sudo().browse(
        attachment_id
    ).exists()

    if not attachment:
        raise ValueError("Attachment does not exist.")

    existing = env["secure.document"].sudo().search(
        [("source_attachment_id", "=", attachment.id)],
        limit=1,
    )
    if existing:
        return {
            "attachment_id": attachment.id,
            "status": "already_migrated",
            "document_id": existing.id,
        }

    path = _filestore_path(env, attachment.store_fname)
    if not path or not os.path.isfile(path):
        raise ValueError(
            "Attachment is not a readable filestore-backed file."
        )

    size = os.path.getsize(path)
    checksum = sha256_file(path)

    result = {
        "attachment_id": attachment.id,
        "name": attachment.name,
        "size": size,
        "sha256": checksum,
        "status": "dry_run" if dry_run else "pending",
    }

    if dry_run:
        return result

    # Do not silently change ownership or the source record's permissions.
    owner = attachment.create_uid or env.user
    company = getattr(attachment, "company_id", False) or env.company

    document = env["secure.document"].sudo().create({
        "name": attachment.name or "migrated-document",
        "owner_id": owner.id,
        "company_id": company.id,
        "mimetype": attachment.mimetype or "application/octet-stream",
        "source_attachment_id": attachment.id,
    })

    try:
        with open(path, "rb") as source:
            document._stream_upload(
                source,
                attachment.name or "migrated-document",
                attachment.mimetype or "application/octet-stream",
            )

        if document.plaintext_size != size or document.sha256 != checksum:
            raise ValueError("Migration checksum verification failed.")

        env["secure.document.audit"].sudo().create({
            "document_id": document.id,
            "event": "migration",
            "user_id": env.user.id,
            "success": True,
            "details": "Migrated from attachment %s" % attachment.id,
        })

        result.update({
            "status": "migrated",
            "document_id": document.id,
        })
        return result

    except Exception:
        # Keep the original attachment and record the failed migration.
        env.cr.rollback()
        raise

