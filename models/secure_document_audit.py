
from odoo import fields, models


class SecureDocumentAudit(models.Model):
    _name = "secure.document.audit"
    _description = "Secure Document Audit Event"
    _order = "create_date desc"
    _log_access = True

    document_id = fields.Many2one(
        "secure.document", index=True, ondelete="set null"
    )
    event = fields.Selection(
        [
            ("upload", "Upload"),
            ("download", "Download"),
            ("delete", "Delete"),
            ("migration", "Migration"),
        ],
        required=True,
        index=True,
    )
    user_id = fields.Many2one("res.users", index=True, ondelete="set null")
    success = fields.Boolean(default=False, required=True, index=True)
    details = fields.Char()
