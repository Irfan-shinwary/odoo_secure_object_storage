
import logging

from werkzeug.utils import secure_filename

from odoo import http, _
from odoo.exceptions import AccessError, UserError
from odoo.http import request

_logger = logging.getLogger(__name__)


class SecureDocumentController(http.Controller):

    @http.route(
        "/secure-document/upload",
        type="http",
        auth="user",
        methods=["POST"],
        csrf=True,
    )
    def upload(self, **post):
        uploaded = request.httprequest.files.get("file")
        if not uploaded or not uploaded.filename:
            return request.make_response(
                "A file field is required.", status=400
            )

        filename = secure_filename(uploaded.filename) or "document.bin"
        mimetype = uploaded.mimetype or "application/octet-stream"

        document = request.env["secure.document"].create({
            "name": filename,
            "owner_id": request.env.user.id,
            "company_id": request.env.company.id,
            "mimetype": mimetype,
        })

        try:
            document._stream_upload(uploaded.stream, filename, mimetype)
            return request.make_json_response({
                "id": document.id,
                "name": document.name,
                "size": document.plaintext_size,
                "sha256": document.sha256,
                "state": document.state,
            }, status=201)

        except (AccessError, UserError):
            raise
        except Exception:
            _logger.exception("Secure document upload failed")
            request.env.cr.rollback()
            return request.make_response(
                "Document upload failed.", status=500
            )

        # except (AccessError, UserError):
        #     raise
        # except Exception:
        #     _logger.exception("Secure document upload failed")
        #     return request.make_response(
        #         "Document upload failed.", status=500
        #     )

    @http.route(
        "/secure-document/<int:document_id>/download",
        type="http",
        auth="user",
        methods=["GET"],
        csrf=False,
    )
    def download(self, document_id, **kwargs):
        document = request.env["secure.document"].browse(document_id).exists()
        if not document:
            return request.make_response("Not found.", status=404)

        try:
            document._check_document_access("read")
            if document.state != "ready":
                return request.make_response(
                    "Document is not available.", status=409
                )

            # The encrypted object is opened before returning the response.
            # The iterator authenticates every chunk before yielding plaintext.
            stream = document._iter_download()
            headers = [
                ("Content-Type", document.mimetype or
                 "application/octet-stream"),
                ("Content-Disposition",
                 'attachment; filename="%s"' %
                 (secure_filename(document.name) or "document.bin")),
                ("Content-Length", str(document.plaintext_size)),
                ("Cache-Control", "no-store, private"),
                ("X-Content-Type-Options", "nosniff"),
            ]
            return request.make_response(stream, headers=headers)

        except AccessError:
            return request.make_response("Forbidden.", status=403)
        except Exception:
            _logger.exception("Secure document download setup failed")
            return request.make_response(
                "Document download failed.", status=500
            )
