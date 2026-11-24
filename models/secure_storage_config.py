
from odoo import api, fields, models, _
from odoo.exceptions import ValidationError


class SecureStorageConfig(models.Model):
    _name = "secure.storage.config"
    _description = "Secure Storage Configuration"

    name = fields.Char(
        string="Configuration",
        default="Secure Storage Configuration",
        required=True,
    )

    code = fields.Selection(
        [("main", "Main Configuration")],
        default="main",
        required=True,
    )

    auto_migrate = fields.Boolean(
        string="Enable Automatic Migration",
        default=False,
        help=(
            "Automatically discover legacy attachments and migrate "
            "them to encrypted MinIO storage."
        ),
    )

    discovery_batch_size = fields.Integer(
        string="Discovery Batch Size",
        default=500,
        required=True,
    )

    migration_batch_size = fields.Integer(
        string="Migration Batch Size",
        default=5,
        required=True,
    )

    retry_limit = fields.Integer(
        string="Maximum Retry Attempts",
        default=5,
        required=True,
    )

    last_discovered_attachment_id = fields.Integer(
        string="Last Discovered Attachment ID",
        default=0,
        readonly=True,
    )

    _sql_constraints = [
        (
            "secure_storage_config_unique",
            "UNIQUE(code)",
            "Only one main secure storage configuration is allowed.",
        ),
    ]

    @api.model
    def get_config(self):
        config = self.sudo().search(
            [("code", "=", "main")],
            limit=1,
        )

        if not config:
            config = self.sudo().create({
                "name": "Secure Storage Configuration",
                "code": "main",
            })

        return config

    @api.constrains(
        "discovery_batch_size",
        "migration_batch_size",
        "retry_limit",
    )
    def _check_configuration_values(self):
        for record in self:
            if not 1 <= record.discovery_batch_size <= 5000:
                raise ValidationError(_(
                    "Discovery batch size must be between 1 and 5000."
                ))

            if not 1 <= record.migration_batch_size <= 100:
                raise ValidationError(_(
                    "Migration batch size must be between 1 and 100."
                ))

            if not 1 <= record.retry_limit <= 20:
                raise ValidationError(_(
                    "Retry limit must be between 1 and 20."
                ))
