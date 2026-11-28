"""HTTP upload integration for secure Odoo attachments."""

import json
import logging
import os
import unicodedata

from odoo import _, http
from odoo.addons.web.controllers.binary import Binary, clean
from odoo.http import request
from odoo.exceptions import AccessError


_logger = logging.getLogger(__name__)


def _secure_storage_enabled():
    value = os.getenv("ODOO_SECURE_STORAGE_ENABLED", "0")
    return value.strip().lower() in {"1", "true", "yes", "on"}


class SecureAttachmentBinaryController(Binary):
    """Preserve Odoo's native upload route while streaming secure uploads."""

    @http.route(
        "/web/binary/upload_attachment",
        type="http",
        auth="user",
        methods=["POST"],
        csrf=True,
    )
    def upload_attachment(self, model, id, ufile, callback=None):
        files = request.httprequest.files.getlist("ufile")
        Attachment = request.env["ir.attachment"]

        response_template = (
            '<script language="javascript" type="text/javascript">'
            "var win = window.top.window;"
            "win.jQuery(win).trigger(%s, %s);"
            "</script>"
        )
        results = []

        for uploaded_file in files:
            filename = uploaded_file.filename or "unnamed"
            if request.httprequest.user_agent.browser == "safari":
                filename = unicodedata.normalize("NFD", filename)

            try:
                if _secure_storage_enabled():
                    attachment = Attachment._create_secure_attachment_from_stream(
                        filename=filename,
                        source=uploaded_file.stream,
                        res_model=model,
                        res_id=int(id),
                        mimetype=uploaded_file.mimetype,
                    )
                else:
                    # Preserve Odoo's original behavior when secure storage
                    # is disabled, including its standard ORM processing.
                    attachment = Attachment.create({
                        "name": filename,
                        "raw": uploaded_file.read(),
                        "res_model": model,
                        "res_id": int(id),
                    })

                attachment._post_add_create()

            except AccessError:
                results.append({
                    "error": _("You are not allowed to upload an attachment here.")
                })
            except Exception:
                results.append({"error": _("Something horrible happened")})
                _logger.exception(
                    "Failed to upload attachment %s",
                    uploaded_file.filename,
                )
            else:
                results.append({
                    "filename": clean(filename),
                    "mimetype": attachment.mimetype,
                    "id": attachment.id,
                    "size": attachment.file_size,
                })

        if callback:
            return response_template % (
                json.dumps(clean(callback)),
                json.dumps(results),
            )
        return json.dumps(results)
