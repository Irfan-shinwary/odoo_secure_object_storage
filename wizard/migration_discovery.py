from odoo import fields, models, _
from odoo.exceptions import UserError


from odoo import fields, models, _
from odoo.exceptions import UserError


class SecureStorageMigrationDiscovery(models.TransientModel):
    _name = "secure.storage.migration.discovery"
    _description = "Discover Legacy Attachments for Migration"

    batch_size = fields.Integer(
        string="Batch Size",
        default=500,
        required=True,
        help="Number of attachment records to scan in one batch.",
    )

    last_attachment_id = fields.Integer(
        string="Last Scanned Attachment ID",
        default=0,
        readonly=True,
    )

    discovered_count = fields.Integer(
        string="New Migration Records",
        readonly=True,
        default=0,
    )

    message = fields.Text(
        string="Scan Summary",
        readonly=True,
    )

    def action_discover_batch(self):
        self.ensure_one()

        # Validate batch size
        if self.batch_size < 1 or self.batch_size > 5000:
            raise UserError(
                _("Batch size must be between 1 and 5,000.")
            )

        # Discover legacy attachments
        result = self.env[
            "secure.storage.migration"
        ].sudo()._discover_legacy_attachments(
            batch_size=self.batch_size,
            last_attachment_id=self.last_attachment_id,
        )

        # No more attachment records to scan
        if result["scanned"] == 0:
            raise UserError(
                _(
                    "Discovery completed!\n\n"
                    "No more legacy filestore attachments were found.\n\n"
                    "Last scanned attachment ID: %s\n\n"
                    "You can now open Migration Records to review "
                    "and process the discovered attachments."
                ) % self.last_attachment_id
            )

        # Update discovery progress
        last_id = result["last_attachment_id"]

        self.write({
            "last_attachment_id": last_id,
            "discovered_count": result["discovered"],
            "message": _(
                "Batch discovery completed successfully.\n\n"
                "Attachments scanned: %s\n"
                "New migration records created: %s\n"
                "Last scanned attachment ID: %s\n\n"
                "Click 'Scan Next Batch' to continue discovering "
                "remaining attachments."
            ) % (
                result["scanned"],
                result["discovered"],
                last_id,
            ),
        })

        return self._reopen_wizard()

    def action_reset_cursor(self):
        self.ensure_one()

        self.write({
            "last_attachment_id": 0,
            "discovered_count": 0,
            "message": _(
                "Scan progress has been reset successfully.\n\n"
                "The next scan will start from the beginning.\n"
                "Existing migration tracking records will not be deleted."
            ),
        })

        return self._reopen_wizard()

    def _reopen_wizard(self):
        return {
            "type": "ir.actions.act_window",
            "name": _("Legacy Attachment Discovery"),
            "res_model": self._name,
            "view_mode": "form",
            "res_id": self.id,
            "target": "new",
        }
