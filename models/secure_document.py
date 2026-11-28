
import hashlib
import logging

from odoo import fields, models, _
from odoo.exceptions import AccessError, UserError

from ..services import key_provider, object_storage, streaming_encryption

_logger = logging.getLogger(__name__)


class SecureDocument(models.Model):
    _name = "secure.document"
    _description = "Secure Encrypted Document"
    _order = "create_date desc"

    name = fields.Char(required=True, index=True)
    owner_id = fields.Many2one(
        "res.users", required=True, default=lambda self: self.env.user,
        index=True, ondelete="restrict",
    )
    company_id = fields.Many2one(
        "res.company", default=lambda self: self.env.company,
        required=True, index=True, ondelete="restrict",
    )
    mimetype = fields.Char(default="application/octet-stream", required=True)
    plaintext_size = fields.Integer(readonly=True, default=0)
    sha256 = fields.Char(readonly=True, index=True)
    object_name = fields.Char(readonly=True, copy=False, index=True)
    wrapped_key = fields.Text(readonly=True, copy=False)
    state = fields.Selection(
        [("draft", "Draft"), ("ready", "Ready"), ("failed", "Failed")],
        default="draft", required=True, index=True,
    )

    source_attachment_id = fields.Many2one(
        "ir.attachment",
        readonly=True,
        copy=False,
        index=True,
        ondelete="set null",
    )

    def _check_document_access(self, operation="read"):
        self.ensure_one()
        if self.env.su:
            return True

        self.check_access_rights(operation)
        self.check_access_rule(operation)

        if self.env.user.has_group(
            "odoo_secure_object_storage.group_secure_document_manager"
        ):
            return True

        if self.owner_id.id != self.env.user.id:
            raise AccessError(_("You are not authorized to access this document."))

        if self.company_id not in self.env.user.company_ids:
            raise AccessError(_("You are not authorized for this company."))

        return True

    def action_delete_document(self):
        for document in self:
            document._check_document_access("unlink")

            object_name = document.object_name

            if object_name:
                def delete_after_commit(name=object_name):
                    try:
                        object_storage.remove_object(name)
                    except Exception:
                        _logger.exception(
                            "Failed to remove secure object %s", name
                        )

                self.env.cr.postcommit.add(delete_after_commit)

            self.env["secure.document.audit"].sudo().create({
                "document_id": document.id,
                "event": "delete",
                "user_id": self.env.user.id,
                "success": True,
                "details": "Secure document deletion requested",
            })

            # Bypass the public unlink guard only after authorization.
            super(SecureDocument, document).unlink()

    def unlink(self):
        for document in self:
            document._check_document_access("unlink")
            if document.object_name:
                raise UserError(_(
                    "Use the secure document deletion action to delete stored files."
                ))
        return super().unlink()

    def _stream_upload(self, source, name, mimetype):
        """Store a seekable input stream using bounded-memory encryption."""
        self.ensure_one()
        self._check_document_access("write")

        source.seek(0, 2)
        size = source.tell()
        source.seek(0)

        if size < 0:
            raise UserError(_("Invalid document size."))

        digest = hashlib.sha256()
        while True:
            chunk = source.read(streaming_encryption.CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

        checksum = digest.hexdigest()
        source.seek(0)

        data_key = key_provider.generate_data_key()[0]
        wrapped_key = key_provider.wrap_data_key(data_key)

        encrypted = streaming_encryption.encrypt_stream(
            source=source,
            key=data_key,
            document_id=str(self.id),
            plaintext_size=size,
            plaintext_sha256=checksum,
        )

        object_name = object_storage.put_encrypted_stream(
            stream=object_storage.IteratorReader(encrypted),
            plaintext_size=size,
            chunk_size=streaming_encryption.CHUNK_SIZE,
        )

        try:
            super(SecureDocument, self).write({
                "name": name,
                "mimetype": mimetype or "application/octet-stream",
                "plaintext_size": size,
                "sha256": checksum,
                "object_name": object_name,
                "wrapped_key": wrapped_key,
                "state": "ready",
            })

            self.env["secure.document.audit"].sudo().create({
                "document_id": self.id,
                "event": "upload",
                "user_id": self.env.user.id,
                "success": True,
                "details": "Encrypted document uploaded",
            })

        except Exception:
            try:
                object_storage.remove_object(object_name)
            except Exception:
                _logger.exception(
                    "Could not clean up encrypted object %s after upload failure",
                    object_name,
                )
            raise

        # The MinIO object is outside PostgreSQL's transaction. If the
        # metadata/audit transaction is rolled back later, remove the object
        # so a failed upload cannot leave an orphaned encrypted document.
        def cleanup_after_rollback(name=object_name):
            try:
                object_storage.remove_object(name)
            except Exception:
                _logger.exception(
                    "Could not clean up rolled-back secure document object %s",
                    name,
                )

        self.env.cr.postrollback.add(cleanup_after_rollback)

        return self

    def _iter_download(self):
        self.ensure_one()
        self._check_document_access("read")

        if self.state != "ready" or not self.object_name or not self.wrapped_key:
            raise UserError(_("The document is not available."))

        response = object_storage.get_object(self.object_name)

        try:
            data_key = key_provider.unwrap_data_key(self.wrapped_key)

            self.env["secure.document.audit"].sudo().create({
                "document_id": self.id,
                "event": "download",
                "user_id": self.env.user.id,
                "success": True,
                "details": "Download authorized and encrypted stream opened",
            })

        except Exception:
            try:
                response.close()
            finally:
                response.release_conn()
            raise

        expected_size = self.plaintext_size
        expected_sha256 = self.sha256
        document_id = str(self.id)

        def generate():
            try:
                yield from streaming_encryption.decrypt_stream(
                    source=response,
                    key=data_key,
                    document_id=document_id,
                    expected_size=expected_size,
                    expected_sha256=expected_sha256,
                )
            except Exception:
                _logger.exception(
                    "Secure document stream integrity failure: %s",
                    document_id,
                )
                raise
            finally:
                try:
                    response.close()
                finally:
                    response.release_conn()

        return generate()

    def write(self, vals):
        protected_fields = {
            "owner_id",
            "company_id",
            "plaintext_size",
            "sha256",
            "object_name",
            "wrapped_key",
            "state",
        }

        if protected_fields.intersection(vals):
            raise AccessError(
                _("Security-sensitive document fields cannot be modified directly.")
            )

        return super().write(vals)
