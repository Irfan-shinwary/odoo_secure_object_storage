
import hashlib
import logging
import os

from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError


_logger = logging.getLogger(__name__)


class SecureStorageMigration(models.Model):
    _name = "secure.storage.migration"
    _description = "Secure Attachment Migration"
    _order = "id desc"

    MAX_MIGRATION_SIZE = 100 * 1024 * 1024  # 100 MiB

    attachment_id = fields.Many2one(
        "ir.attachment",
        string="Attachment",
        required=True,
        ondelete="cascade",
        index=True,
    )

    attachment_name = fields.Char(
        string="Attachment Name",
        required=True,
    )

    source_store_fname = fields.Char(
        string="Original Storage Reference",
        required=True,
        readonly=True,
    )

    source_checksum = fields.Char(
        string="Original Odoo Checksum",
        readonly=True,
    )

    source_file_size = fields.Integer(
        string="Original File Size",
        readonly=True,
    )

    source_write_date = fields.Datetime(
        string="Attachment Last Modified",
        readonly=True,
    )

    mimetype = fields.Char(
        string="MIME Type",
        readonly=True,
    )

    status = fields.Selection(
        [
            ("pending", "Pending"),
            ("processing", "Processing"),
            ("done", "Migrated"),
            ("failed", "Failed"),
            ("skipped", "Skipped"),
        ],
        string="Migration Status",
        default="pending",
        required=True,
        index=True,
    )

    retry_count = fields.Integer(
        string="Retry Count",
        default=0,
    )

    target_object_key = fields.Char(
        string="Target Object Key",
        readonly=True,
    )

    error_message = fields.Text(
        string="Error Details",
        readonly=True,
    )

    started_at = fields.Datetime(
        string="Started At",
        readonly=True,
    )

    completed_at = fields.Datetime(
        string="Completed At",
        readonly=True,
    )

    _sql_constraints = [
        (
            "secure_storage_migration_attachment_unique",
            "unique(attachment_id)",
            "An attachment can only have one migration tracking record.",
        ),
    ]

    # ---------------------------------------------------------
    # CONFIGURATION
    # ---------------------------------------------------------

    @api.model
    def _is_secure_storage_enabled(self):
        value = os.getenv(
            "ODOO_SECURE_STORAGE_ENABLED", ""
        ).strip().lower()

        return value in ("1", "true", "yes", "on")

    @api.model
    def _check_secure_storage_configuration(self):
        if not self._is_secure_storage_enabled():
            raise UserError(_(
                "Secure storage is disabled.\n\n"
                "Set ODOO_SECURE_STORAGE_ENABLED=1 in the "
                "Odoo server environment and restart Odoo "
                "before running migration."
            ))

        bucket = os.getenv(
            "ODOO_SECURE_MINIO_BUCKET", ""
        ).strip()

        if not bucket:
            raise UserError(_(
                "MinIO bucket is not configured. "
                "Set ODOO_SECURE_MINIO_BUCKET in the "
                "Odoo server environment."
            ))

    # ---------------------------------------------------------
    # ATTACHMENT REFERENCE UPDATE
    # ---------------------------------------------------------

    def _update_attachment_reference(
        self,
        attachment,
        old_fname,
        secure_fname,
    ):
        """
        Update the attachment storage reference and verify
        that PostgreSQL actually stores the new reference.

        First use the normal Odoo ORM write.

        If the ORM write does not persist the value, use a
        guarded SQL update. The SQL update only succeeds when
        the attachment still contains the original reference.

        The caller must already hold a FOR UPDATE lock on the
        attachment row and must execute inside a savepoint.
        """

        attachment.ensure_one()

        # 1. Attempt the normal Odoo ORM update.
        write_result = attachment.write({
            "store_fname": secure_fname,
        })

        if write_result is False:
            _logger.warning(
                "ORM attachment reference update returned False: "
                "attachment_id=%s",
                attachment.id,
            )

        # 2. Flush pending ORM changes to PostgreSQL.
        attachment.flush_recordset([
            "store_fname",
            "write_date",
            "write_uid",
        ])

        # 3. Invalidate the cached storage reference.
        attachment.invalidate_recordset([
            "store_fname",
            "write_date",
            "write_uid",
        ])

        # 4. Read the actual database value.
        self.env.cr.execute(
            """
            SELECT store_fname
              FROM ir_attachment
             WHERE id = %s
            """,
            (attachment.id,),
        )

        row = self.env.cr.fetchone()

        if not row:
            raise ValidationError(_(
                "Attachment disappeared while updating its "
                "secure storage reference."
            ))

        actual_fname = row[0]

        # ORM update succeeded.
        if actual_fname == secure_fname:
            _logger.info(
                "SECURE_STORAGE_REFERENCE_UPDATE "
                "method=ORM status=SUCCESS attachment_id=%s",
                attachment.id,
            )
            return True

        # 5. ORM did not persist the reference.
        # Use a guarded SQL update as a migration fallback.
        _logger.warning(
            "ORM did not persist the secure storage reference. "
            "Using guarded SQL fallback. attachment_id=%s",
            attachment.id,
        )

        self.env.cr.execute(
            """
            UPDATE ir_attachment
               SET store_fname = %s,
                   write_date = NOW(),
                   write_uid = %s
             WHERE id = %s
               AND store_fname = %s
            RETURNING store_fname
            """,
            (
                secure_fname,
                self.env.uid,
                attachment.id,
                old_fname,
            ),
        )

        updated_row = self.env.cr.fetchone()

        if not updated_row:
            raise ValidationError(_(
                "Could not update the attachment storage reference. "
                "The original reference may have changed concurrently."
            ))

        # 6. Verify the result directly from PostgreSQL.
        self.env.cr.execute(
            """
            SELECT store_fname
              FROM ir_attachment
             WHERE id = %s
            """,
            (attachment.id,),
        )

        verified_row = self.env.cr.fetchone()

        if not verified_row or verified_row[0] != secure_fname:
            raise ValidationError(_(
                "PostgreSQL did not retain the secure attachment "
                "reference after the update."
            ))

        # 7. Invalidate the ORM cache after direct SQL.
        attachment.invalidate_recordset([
            "store_fname",
            "write_date",
            "write_uid",
        ])

        _logger.warning(
            "SECURE_STORAGE_REFERENCE_UPDATE "
            "method=SQL_FALLBACK status=SUCCESS attachment_id=%s",
            attachment.id,
        )

        return True

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    @api.model
    def get_migration_statistics(self):
        grouped = self.read_group(
            [],
            ["status", "source_file_size:sum"],
            ["status"],
        )

        statistics = {
            "pending": 0,
            "processing": 0,
            "done": 0,
            "failed": 0,
            "skipped": 0,
            "total": 0,
            "total_size": 0,
        }

        for item in grouped:
            status = item.get("status")
            count = item.get("status_count", 0)

            if status in statistics:
                statistics[status] = count

            statistics["total"] += count
            statistics["total_size"] += (
                item.get("source_file_size", 0) or 0
            )

        return statistics

    # ---------------------------------------------------------
    # SINGLE RECORD MIGRATION
    # ---------------------------------------------------------

    def action_migrate_one(self):
        self.ensure_one()

        self._check_secure_storage_configuration()

        if self.status not in ("pending", "failed"):
            raise UserError(_(
                "Only Pending or Failed migration records "
                "can be migrated."
            ))

        success = self._migrate_one()

        if success:
            message = _(
                "Attachment migrated and verified successfully."
            )
            notification_type = "success"
        else:
            message = self.error_message or _(
                "Migration failed. Check the migration record for details."
            )
            notification_type = "warning"

        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Secure Storage Migration"),
                "message": message,
                "type": notification_type,
                "sticky": True,
            },
        }

    # ---------------------------------------------------------
    # MIGRATE ONE ATTACHMENT
    # ---------------------------------------------------------

    def _migrate_one(self):
        self.ensure_one()

        migration = self
        secure_fname = False

        # Lock the migration tracking record.
        # This protects both manual and automatic migration.
        self.env.cr.execute(
            """
            SELECT status
              FROM secure_storage_migration
             WHERE id = %s
             FOR UPDATE
            """,
            (migration.id,),
        )

        migration_row = self.env.cr.fetchone()

        if not migration_row:
            return False

        migration.invalidate_recordset([
            "status",
            "retry_count",
        ])

        if migration.status not in ("pending", "failed"):
            return False

        try:
            self._check_secure_storage_configuration()

            # Use a savepoint so a failed migration does not
            # leave the surrounding Odoo transaction aborted.
            with self.env.cr.savepoint():

                # 1. Lock the source attachment against concurrent updates.
                self.env.cr.execute(
                    """
                    SELECT store_fname,
                           checksum,
                           file_size,
                           write_date
                      FROM ir_attachment
                     WHERE id = %s
                     FOR UPDATE
                    """,
                    (migration.attachment_id.id,),
                )

                source_row = self.env.cr.fetchone()

                if not source_row:
                    raise ValidationError(_(
                        "The original attachment does not exist "
                        "in the database."
                    ))

                (
                    current_fname,
                    current_checksum,
                    current_size,
                    current_write_date,
                ) = source_row

                # 2. Verify that the source has not changed since discovery.
                snapshot_write_date = fields.Datetime.to_datetime(
                    migration.source_write_date
                )

                if (
                    current_fname != migration.source_store_fname
                    or current_checksum != migration.source_checksum
                    or current_size != migration.source_file_size
                    or current_write_date != snapshot_write_date
                ):
                    migration.write({
                        "status": "skipped",
                        "error_message": _(
                            "Source attachment changed after discovery. "
                            "Run discovery again to capture its current state."
                        ),
                        "completed_at": fields.Datetime.now(),
                    })
                    return False

                if not current_fname:
                    raise ValidationError(_(
                        "The source attachment has no filestore reference."
                    ))

                if current_fname.startswith("secure-minio://"):
                    migration.write({
                        "status": "skipped",
                        "error_message": _(
                            "Attachment is already in secure object storage."
                        ),
                        "completed_at": fields.Datetime.now(),
                    })
                    return False

                # 3. Enforce the initial migration size limit.
                if (
                    current_size is not None
                    and current_size > self.MAX_MIGRATION_SIZE
                ):
                    migration.write({
                        "status": "skipped",
                        "error_message": _(
                            "File exceeds the initial 100 MiB migration limit. "
                            "Use the dedicated streaming migration process."
                        ),
                        "completed_at": fields.Datetime.now(),
                    })
                    return False

                migration.write({
                    "status": "processing",
                    "started_at": fields.Datetime.now(),
                    "completed_at": False,
                    "error_message": False,
                    "retry_count": migration.retry_count + 1,
                })

                # 4. Read the original Odoo filestore object.
                attachment = migration.attachment_id.sudo()

                content = attachment._file_read(current_fname)

                if not isinstance(content, bytes):
                    raise ValidationError(_(
                        "Odoo filestore did not return binary content."
                    ))

                if (
                    current_size is not None
                    and len(content) != current_size
                ):
                    raise ValidationError(_(
                        "Source file size mismatch. Expected %s bytes, "
                        "received %s bytes."
                    ) % (current_size, len(content)))

                # 5. Verify original Odoo SHA-1 checksum.
                source_sha1 = hashlib.sha1(content).hexdigest()

                if (
                    current_checksum
                    and source_sha1 != current_checksum
                ):
                    raise ValidationError(_(
                        "Original filestore checksum verification failed."
                    ))

                # 6. Encrypt and upload using the existing secure _file_write.
                secure_fname = attachment._file_write(
                    content,
                    source_sha1,
                )

                if (
                    not secure_fname
                    or not secure_fname.startswith("secure-minio://")
                ):
                    raise ValidationError(_(
                        "Secure storage did not return a valid "
                        "MinIO object reference."
                    ))

                # 7. Verify the encrypted object through the normal
                # secure attachment read implementation.
                verified_content = attachment._file_read(secure_fname)

                if not isinstance(verified_content, bytes):
                    raise ValidationError(_(
                        "Secure storage did not return binary content."
                    ))

                if len(verified_content) != len(content):
                    raise ValidationError(_(
                        "Encrypted object verification failed: "
                        "file size mismatch."
                    ))

                verified_sha1 = hashlib.sha1(
                    verified_content
                ).hexdigest()

                if verified_sha1 != source_sha1:
                    raise ValidationError(_(
                        "Encrypted object verification failed: "
                        "SHA-1 checksum mismatch."
                    ))

                # 8. Update and verify the PostgreSQL attachment reference.
                self._update_attachment_reference(
                    attachment=attachment,
                    old_fname=current_fname,
                    secure_fname=secure_fname,
                )

                # 9. Only mark migration successful after the database
                # reference has been verified.
                migration.write({
                    "status": "done",
                    "target_object_key": secure_fname.rsplit("/", 1)[-1],
                    "completed_at": fields.Datetime.now(),
                    "error_message": False,
                })

                _logger.info(
                    "SECURE_STORAGE_MIGRATION_SUCCESS "
                    "migration_id=%s attachment_id=%s size=%s "
                    "target=%s",
                    migration.id,
                    attachment.id,
                    len(content),
                    secure_fname.rsplit("/", 1)[-1],
                )

            return True

        except Exception as exc:
            _logger.exception(
                "Secure attachment migration failed: "
                "migration_id=%s attachment_id=%s",
                migration.id,
                migration.attachment_id.id,
            )

            # The savepoint rolls back the attachment reference and
            # migration processing writes. Record the failure outside it.
            migration.invalidate_recordset()

            error = str(exc)[:2000]

            if secure_fname:
                orphan_key = secure_fname.rsplit("/", 1)[-1]

                error += (
                    "\n\nA MinIO object may have been uploaded but "
                    "was not committed to the attachment. "
                    "Target object key: %s. "
                    "Do not delete it until it is confirmed unused."
                ) % orphan_key
            else:
                orphan_key = False

            migration.write({
                "status": "failed",
                "retry_count": migration.retry_count + 1,
                "completed_at": fields.Datetime.now(),
                "target_object_key": orphan_key or False,
                "error_message": error,
            })

            return False

    # ---------------------------------------------------------
    # SELECTED RECORDS
    # ---------------------------------------------------------

    def action_migrate_selected(self):
        self._check_secure_storage_configuration()

        if not self:
            raise UserError(_(
                "Select at least one migration record."
            ))

        succeeded = 0
        failed = 0

        for migration in self:
            if migration.status not in ("pending", "failed"):
                continue

            if migration._migrate_one():
                succeeded += 1
            else:
                failed += 1

        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Migration Results"),
                "message": _(
                    "Successfully migrated: %s\n"
                    "Failed or skipped: %s"
                ) % (succeeded, failed),
                "type": "success" if failed == 0 else "warning",
                "sticky": True,
            },
        }

    # ---------------------------------------------------------
    # CONTROLLED BATCH MIGRATION
    # ---------------------------------------------------------

    @api.model
    def action_migrate_batch(self, limit=5):
        self._check_secure_storage_configuration()

        limit = int(limit)

        if limit < 1 or limit > 100:
            raise UserError(_(
                "Migration batch size must be between 1 and 100."
            ))

        records = self.search(
            [("status", "=", "pending")],
            order="id asc",
            limit=limit,
        )

        succeeded = 0
        failed = 0

        for migration in records:
            if migration._migrate_one():
                succeeded += 1
            else:
                failed += 1

        return {
            "processed": len(records),
            "succeeded": succeeded,
            "failed_or_skipped": failed,
        }

    # ---------------------------------------------------------
    # REUSABLE LEGACY ATTACHMENT DISCOVERY
    # ---------------------------------------------------------

    @api.model
    def _discover_legacy_attachments(
        self,
        batch_size=500,
        last_attachment_id=0,
    ):
        """
        Discover legacy filestore attachments.

        This method is shared by:

        1. Manual discovery wizard:
           Uses the wizard's last_attachment_id.

        2. Automatic discovery cron:
           Uses the persistent configuration cursor.

        This method does not check auto_migrate because manual
        discovery must remain available when automation is disabled.
        """

        batch_size = int(batch_size)
        last_attachment_id = int(last_attachment_id or 0)

        if batch_size < 1 or batch_size > 5000:
            raise UserError(_(
                "Discovery batch size must be between 1 and 5,000."
            ))

        if last_attachment_id < 0:
            raise UserError(_(
                "Last attachment ID cannot be negative."
            ))

        Config = self.env["secure.storage.config"].sudo()
        config = Config.get_config()

        # Serialize manual and automatic discovery operations.
        self.env.cr.execute(
            """
            SELECT id
              FROM secure_storage_config
             WHERE id = %s
             FOR UPDATE
            """,
            (config.id,),
        )

        if not self.env.cr.fetchone():
            raise UserError(_(
                "Secure storage configuration could not be found."
            ))

        Attachment = self.env["ir.attachment"].sudo()
        Migration = self.sudo()

        # Find legacy filestore attachments only.
        attachments = Attachment.search(
            [
                ("id", ">", last_attachment_id),
                ("type", "=", "binary"),
                ("store_fname", "!=", False),
                ("store_fname", "not like", "secure-minio://%"),
            ],
            order="id asc",
            limit=batch_size,
        )

        # No more attachments were found.
        if not attachments:
            return {
                "scanned": 0,
                "discovered": 0,
                "last_attachment_id": last_attachment_id,
                "completed": True,
            }

        # Identify attachments that already have migration records.
        existing_records = Migration.search(
            [("attachment_id", "in", attachments.ids)]
        )

        existing_ids = set(
            existing_records.mapped("attachment_id").ids
        )

        new_records = []

        # Prepare tracking records for undiscovered attachments.
        for attachment in attachments:
            if attachment.id in existing_ids:
                continue

            new_records.append({
                "attachment_id": attachment.id,
                "attachment_name": (
                    attachment.name or "Unnamed attachment"
                ),
                "source_store_fname": attachment.store_fname,
                "source_checksum": attachment.checksum,
                "source_file_size": attachment.file_size or 0,
                "source_write_date": attachment.write_date,
                "mimetype": attachment.mimetype,
                "status": "pending",
            })

        # Create migration tracking records.
        if new_records:
            Migration.create(new_records)

        last_id = attachments[-1].id

        result = {
            "scanned": len(attachments),
            "discovered": len(new_records),
            "last_attachment_id": last_id,
            "completed": False,
        }

        _logger.info(
            "SECURE_STORAGE_DISCOVERY "
            "scanned=%s discovered=%s last_id=%s",
            result["scanned"],
            result["discovered"],
            result["last_attachment_id"],
        )

        return result

    # ---------------------------------------------------------
    # AUTOMATIC BATCH MIGRATION
    # ---------------------------------------------------------

    @api.model
    def _process_pending_batch(
        self,
        batch_size=5,
        retry_limit=5,
    ):
        """
        Automatically process pending and retryable failed records.

        FOR UPDATE SKIP LOCKED prevents multiple cron workers
        from processing the same migration records concurrently.
        """

        Config = self.env["secure.storage.config"].sudo()
        config = Config.get_config()

        if not config.auto_migrate:
            return {
                "enabled": False,
                "processed": 0,
                "succeeded": 0,
                "failed": 0,
            }

        self._check_secure_storage_configuration()

        batch_size = int(batch_size)
        retry_limit = int(retry_limit)

        if batch_size < 1 or batch_size > 100:
            raise UserError(_(
                "Migration batch size must be between 1 and 100."
            ))

        if retry_limit < 1 or retry_limit > 20:
            raise UserError(_(
                "Retry limit must be between 1 and 20."
            ))

        # Flush fields before executing direct SQL.
        self.flush_model([
            "status",
            "retry_count",
        ])

        # Select and lock migration records atomically.
        self.env.cr.execute(
            """
            SELECT id
              FROM secure_storage_migration
             WHERE (
                    status = 'pending'
                )
                OR (
                    status = 'failed'
                    AND retry_count < %s
                )
             ORDER BY id ASC
             LIMIT %s
             FOR UPDATE SKIP LOCKED
            """,
            (retry_limit, batch_size),
        )

        migration_ids = [
            row[0] for row in self.env.cr.fetchall()
        ]

        if not migration_ids:
            return {
                "enabled": True,
                "processed": 0,
                "succeeded": 0,
                "failed": 0,
            }

        migrations = self.sudo().browse(migration_ids)

        succeeded = 0
        failed = 0

        for migration in migrations:
            if migration._migrate_one():
                succeeded += 1
            else:
                failed += 1

        result = {
            "enabled": True,
            "processed": len(migrations),
            "succeeded": succeeded,
            "failed": failed,
        }

        _logger.info(
            "SECURE_STORAGE_AUTO_MIGRATION "
            "processed=%s succeeded=%s failed=%s",
            result["processed"],
            result["succeeded"],
            result["failed"],
        )

        return result

    # ---------------------------------------------------------
    # AUTOMATIC DISCOVERY CRON
    # ---------------------------------------------------------

    @api.model
    def cron_auto_discover(self):
        """
        Scheduled automatic discovery.

        Reads the persistent cursor, discovers the next batch,
        and updates the cursor after successful discovery.
        """

        Config = self.env["secure.storage.config"].sudo()
        config = Config.get_config()

        # Lock the configuration row before reading the cursor.
        # This prevents concurrent discovery cron workers from
        # reading and processing the same cursor.
        self.env.cr.execute(
            """
            SELECT auto_migrate,
                   discovery_batch_size,
                   last_discovered_attachment_id
              FROM secure_storage_config
             WHERE id = %s
             FOR UPDATE
            """,
            (config.id,),
        )

        config_row = self.env.cr.fetchone()

        if not config_row:
            _logger.warning(
                "Automatic discovery skipped: "
                "secure storage configuration not found."
            )
            return

        auto_migrate, batch_size, last_id = config_row

        if not auto_migrate:
            _logger.info(
                "Automatic discovery skipped: auto_migrate is disabled."
            )
            return

        try:
            self._check_secure_storage_configuration()

            # Use the persistent configuration cursor.
            result = self.sudo()._discover_legacy_attachments(
                batch_size=batch_size,
                last_attachment_id=last_id or 0,
            )

            # Update the cursor only when attachments were scanned.
            # If discovery fails, the transaction rolls back and
            # the previous cursor remains unchanged.
            if result["scanned"] > 0:
                config.write({
                    "last_discovered_attachment_id": (
                        result["last_attachment_id"]
                    ),
                })

            _logger.info(
                "SECURE_STORAGE_AUTO_DISCOVERY_CRON "
                "enabled=True scanned=%s discovered=%s "
                "last_attachment_id=%s completed=%s",
                result["scanned"],
                result["discovered"],
                result["last_attachment_id"],
                result["completed"],
            )

            return result

        except Exception:
            _logger.exception(
                "Automatic attachment discovery failed."
            )
            raise

    # ---------------------------------------------------------
    # AUTOMATIC MIGRATION CRON
    # ---------------------------------------------------------

    @api.model
    def cron_auto_migrate(self):
        """
        Scheduled automatic migration.

        Processes pending records and retries failed records
        until their configured retry limit is reached.
        """

        Config = self.env["secure.storage.config"].sudo()
        config = Config.get_config()

        if not config.auto_migrate:
            _logger.info(
                "Automatic migration skipped: auto_migrate is disabled."
            )
            return

        try:
            self._check_secure_storage_configuration()

            result = self.sudo()._process_pending_batch(
                batch_size=config.migration_batch_size,
                retry_limit=config.retry_limit,
            )

            _logger.info(
                "SECURE_STORAGE_AUTO_MIGRATION_CRON "
                "processed=%s succeeded=%s failed=%s",
                result["processed"],
                result["succeeded"],
                result["failed"],
            )

            return result

        except Exception:
            _logger.exception(
                "Automatic attachment migration failed."
            )
            raise
