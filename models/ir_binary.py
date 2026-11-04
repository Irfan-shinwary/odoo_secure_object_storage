"""HTTP download support for attachments stored in secure MinIO."""

from odoo import models
from odoo.http import Stream


_SECURE_MINIO_PREFIX = "secure-minio://"


class IrBinary(models.AbstractModel):
    _inherit = "ir.binary"

    def _record_to_stream(self, record, field_name):
        """Read secure MinIO attachments as data instead of local filestore paths.

        Odoo 17's default Stream.from_attachment() assumes every non-empty
        ``store_fname`` is a local filestore path. Our secure-minio:// reference
        is a remote object reference, so route these attachments through the
        attachment's ``raw`` field, which invokes the custom _file_read().
        """
        if (
            record._name == "ir.attachment"
            and (record.store_fname or "").startswith(_SECURE_MINIO_PREFIX)
            and field_name in ("raw", "datas", "db_datas")
        ):
            record.ensure_one()
            data = record.raw or b""
            return Stream(
                type="data",
                data=data,
                mimetype=record.mimetype,
                download_name=record.name,
                etag=record.checksum,
                last_modified=record.write_date,
                size=len(data),
                public=record.public,
            )

        return super()._record_to_stream(record, field_name)
