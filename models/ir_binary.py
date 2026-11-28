
"""HTTP streaming support for secure MinIO attachments."""

import logging
import os

from odoo import models, _
from odoo.exceptions import UserError
from odoo.http import Stream

from ..services import streaming_file


_logger = logging.getLogger(__name__)

_SECURE_MINIO_PREFIX = "secure-minio://"


class SecureTemporaryPathStream(Stream):
    """Odoo HTTP stream backed by a private temporary plaintext file.

    The temporary file is deleted when the HTTP response is closed.
    """

    def __init__(self, path, **kwargs):
        super().__init__(
            type="path",
            path=path,
            **kwargs,
        )
        self._secure_temporary_path = path
        self._secure_cleanup_done = False

    def cleanup(self):
        """Delete the temporary plaintext file once."""
        if self._secure_cleanup_done:
            return

        self._secure_cleanup_done = True

        try:
            os.unlink(self._secure_temporary_path)
        except FileNotFoundError:
            pass
        except OSError:
            _logger.exception(
                "Could not remove temporary secure attachment file."
            )

    def get_response(self, *args, **kwargs):
        """Attach temporary-file cleanup to the HTTP response lifecycle."""
        try:
            response = super().get_response(*args, **kwargs)
            response.call_on_close(self.cleanup)
            return response
        except Exception:
            self.cleanup()
            raise


class IrBinary(models.AbstractModel):
    _inherit = "ir.binary"

    def _record_to_stream(self, record, field_name):
        """Serve secure attachments through a verified disk-backed stream.

        Odoo performs attachment access checks before calling this method.
        All non-secure attachments retain the standard Odoo behavior.
        """
        if (
            record._name == "ir.attachment"
            and (record.store_fname or "").startswith(_SECURE_MINIO_PREFIX)
            and field_name in ("raw", "datas", "db_datas")
        ):
            record.ensure_one()

            try:
                temporary_path, plaintext_size = (
                    streaming_file.decrypt_attachment_to_tempfile(
                        store_fname=record.store_fname,
                        expected_file_size=record.file_size,
                    )
                )

                return SecureTemporaryPathStream(
                    path=temporary_path,
                    mimetype=record.mimetype or "application/octet-stream",
                    download_name=record.name,
                    etag=record.checksum,
                    last_modified=record.write_date,
                    size=plaintext_size,
                    public=record.public,
                )

            except Exception as exc:
                _logger.exception(
                    "Could not prepare secure attachment HTTP stream. "
                    "attachment_id=%s",
                    record.id,
                )

                raise UserError(
                    _("The attachment could not be retrieved or authenticated. "
                      "Contact the system administrator.")
                ) from exc

        return super()._record_to_stream(record, field_name)


# """HTTP download support for attachments stored in secure MinIO."""
#
# from odoo import models
# from odoo.http import Stream
#
#
# _SECURE_MINIO_PREFIX = "secure-minio://"
#
#
# class IrBinary(models.AbstractModel):
#     _inherit = "ir.binary"
#
#     def _record_to_stream(self, record, field_name):
#         """Read secure MinIO attachments as data instead of local filestore paths.
#
#         Odoo 17's default Stream.from_attachment() assumes every non-empty
#         ``store_fname`` is a local filestore path. Our secure-minio:// reference
#         is a remote object reference, so route these attachments through the
#         attachment's ``raw`` field, which invokes the custom _file_read().
#         """
#         if (
#             record._name == "ir.attachment"
#             and (record.store_fname or "").startswith(_SECURE_MINIO_PREFIX)
#             and field_name in ("raw", "datas", "db_datas")
#         ):
#             record.ensure_one()
#             data = record.raw or b""
#             return Stream(
#                 type="data",
#                 data=data,
#                 mimetype=record.mimetype,
#                 download_name=record.name,
#                 etag=record.checksum,
#                 last_modified=record.write_date,
#                 size=len(data),
#                 public=record.public,
#             )
#
#         return super()._record_to_stream(record, field_name)
