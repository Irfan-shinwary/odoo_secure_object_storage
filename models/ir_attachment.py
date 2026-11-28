import hashlib
import io
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
import time
import tempfile

from minio import Minio
from odoo import api, models
from odoo.exceptions import UserError
from odoo.tools import human_size
from odoo.tools.mimetypes import guess_mimetype
from odoo.addons.base.models.ir_attachment import IrAttachment as BaseIrAttachment

from ..services import key_provider, object_storage, streaming_encryption

_logger = logging.getLogger(__name__)

_PREFIX = "secure-minio://"
_OBJECT_KEY_RE = re.compile(r"^[0-9a-f]{32}$")


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _storage_enabled():
    return _env_bool("ODOO_SECURE_STORAGE_ENABLED", False)


def _get_minio_config():
    endpoint = os.getenv("ODOO_SECURE_MINIO_ENDPOINT", "").strip()
    access_key = os.getenv("ODOO_SECURE_MINIO_ACCESS_KEY", "")
    secret_key = os.getenv("ODOO_SECURE_MINIO_SECRET_KEY", "")
    bucket = os.getenv("ODOO_SECURE_MINIO_BUCKET", "").strip()
    secure = _env_bool("ODOO_SECURE_MINIO_TLS", True)

    if not all((endpoint, access_key, secret_key, bucket)):
        raise UserError(
            "Secure attachment storage is enabled but one or more required "
            "MinIO environment variables are missing."
        )
    return endpoint, access_key, secret_key, bucket, secure



def _client():
    endpoint, access_key, secret_key, bucket, secure = _get_minio_config()
    client = Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )
    if not client.bucket_exists(bucket):
        raise UserError(
            "The configured secure attachment bucket does not exist. "
            "Create it privately before enabling secure storage."
        )
    return client, bucket



def _object_key_from_fname(fname, bucket):
    """Validate and extract the MinIO object key from an Odoo storage reference."""
    if not fname or not fname.startswith(_PREFIX):
        return None

    reference = fname[len(_PREFIX):]
    expected_prefix = bucket + "/"
    if not reference.startswith(expected_prefix):
        raise UserError(
            "Attachment object reference does not match configured bucket."
        )

    object_key = reference[len(expected_prefix):]
    if not _OBJECT_KEY_RE.fullmatch(object_key):
        raise UserError("Invalid secure attachment object reference.")

    return object_key


def _read_exact(stream, size):
    """Read exactly size bytes, tolerating short reads from the stream."""
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            break
        result.extend(part)
    return bytes(result)




class IrAttachment(models.Model):
    _inherit = "ir.attachment"




    @api.model
    def _stream_index_content(self, source, mimetype):
        """Build Odoo-compatible index content without loading the file at once."""
        if not mimetype:
            return False

        index_type = mimetype.split("/", 1)[0]
        if index_type != "text":
            return index_type

        # Odoo stores index_content as a PostgreSQL text value. Keep this
        # secondary metadata bounded independently from the document size.
        try:
            max_index_bytes = max(
                0,
                int(os.getenv("ODOO_SECURE_STORAGE_MAX_INDEX_BYTES", "1048576")),
            )
        except ValueError:
            max_index_bytes = 1048576

        source.seek(0)
        pending = b""
        indexed_runs = []
        indexed_bytes = 0

        while indexed_bytes < max_index_bytes:
            chunk = source.read(min(
                streaming_encryption.CHUNK_SIZE,
                max_index_bytes - indexed_bytes,
            ))
            if not chunk:
                break
            indexed_bytes += len(chunk)

            data = pending + chunk
            trailing = re.search(rb"[\x20-\x7E]+$", data)

            if trailing:
                stable_data = data[:trailing.start()]
                pending = trailing.group(0)
            else:
                stable_data = data
                pending = b""

            indexed_runs.extend(
                re.findall(rb"[\x20-\x7E]{4,}", stable_data)
            )

        if len(pending) >= 4:
            indexed_runs.append(pending)

        source.seek(0)
        return b"\n".join(indexed_runs).decode("ascii")

    @api.model
    def _create_secure_attachment_from_stream(
        self,
        filename,
        source,
        res_model=False,
        res_id=0,
        mimetype=None,
    ):
        """Create an Odoo attachment from a seekable stream using bounded memory.

        Odoo's standard create(raw=...) API requires the entire file as bytes.
        This method creates the normal attachment record first, then stores
        authenticated encrypted content in MinIO and writes Odoo's internal
        storage metadata using the base ORM write implementation.
        """
        if not _storage_enabled():
            raise UserError(
                "Secure attachment streaming is not enabled."
            )

        if not filename or not hasattr(source, "read"):
            raise UserError("A valid filename and binary stream are required.")

        temporary_source = None
        attachment = self.browse()
        object_key = None
        uploaded = False

        try:
            # Werkzeug normally provides a seekable SpooledTemporaryFile.
            # Copy non-seekable sources to a disk-backed temporary file.
            try:
                source.seek(0)
                source.tell()
            except (AttributeError, OSError, ValueError):
                temporary_source = tempfile.TemporaryFile(mode="w+b")
                while True:
                    chunk = source.read(streaming_encryption.CHUNK_SIZE)
                    if not chunk:
                        break
                    temporary_source.write(chunk)
                temporary_source.seek(0)
                source = temporary_source

            # First bounded pass: calculate both Odoo's SHA-1 checksum and
            # the SHA-256 digest authenticated by the ODSDOC01 format.
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            plaintext_size = 0
            head = b""

            source.seek(0)
            while True:
                chunk = source.read(streaming_encryption.CHUNK_SIZE)
                if not chunk:
                    break

                if len(head) < 2048:
                    head += chunk[:2048 - len(head)]

                sha1.update(chunk)
                sha256.update(chunk)
                plaintext_size += len(chunk)

            source.seek(0)

            supplied_mimetype = (mimetype or "").strip().lower()
            if not supplied_mimetype or supplied_mimetype == "application/octet-stream":
                supplied_mimetype = guess_mimetype(
                    head,
                    default="application/octet-stream",
                )

            # Keep Odoo's XML/plain-text MIME policy. No binary payload is
            # passed through _check_contents, so it cannot materialize data.
            checked_values = self._check_contents({
                "name": filename,
                "mimetype": supplied_mimetype,
            })
            final_mimetype = checked_values["mimetype"]

            # Odoo's configured image autoresizer uses PIL on a complete
            # byte string. Retain that exact native behavior for configured
            # resizable image formats; all other files remain disk-streamed.
            if not self.env.context.get("image_no_postprocess"):
                ICP = self.env["ir.config_parameter"].sudo().get_param
                resize_types = {
                    item.strip().lower()
                    for item in ICP(
                        "base.image_autoresize_extensions",
                        "png,jpeg,bmp,tiff",
                    ).split(",")
                    if item.strip()
                }
                image_type = final_mimetype.partition("/")[2]
                max_resolution = ICP(
                    "base.image_autoresize_max_px",
                    "1920x1920",
                )
                if (
                    final_mimetype.startswith("image/")
                    and image_type in resize_types
                    and str(max_resolution).lower() not in {
                        "0", "false", "no", "off", ""
                    }
                ):
                    source.seek(0)
                    image_data = source.read()
                    return self.create({
                        "name": filename,
                        "type": "binary",
                        "mimetype": final_mimetype,
                        "res_model": res_model or False,
                        "res_id": int(res_id or 0),
                        "raw": image_data,
                    })

            index_content = self._stream_index_content(
                source,
                final_mimetype,
            )

            # Match Odoo's empty-file behavior: no external object is created.
            attachment = self.create({
                "name": filename,
                "type": "binary",
                "mimetype": final_mimetype,
                "res_model": res_model or False,
                "res_id": int(res_id or 0),
            })

            if plaintext_size == 0:
                return attachment

            bucket = os.getenv(
                "ODOO_SECURE_MINIO_BUCKET", ""
            ).strip()
            if not bucket:
                raise UserError("Secure storage bucket is not configured.")

            object_key = uuid.uuid4().hex

            # A new random DEK is generated and wrapped for every attachment.
            data_key = key_provider.generate_data_key()[0]
            wrapped_key = key_provider.wrap_data_key(data_key)
            plaintext_sha256 = sha256.hexdigest()

            encrypted_stream = streaming_encryption.encrypt_stream(
                source=source,
                key=data_key,
                document_id=object_key,
                plaintext_size=plaintext_size,
                plaintext_sha256=plaintext_sha256,
            )

            object_storage.put_encrypted_stream(
                stream=object_storage.IteratorReader(encrypted_stream),
                plaintext_size=plaintext_size,
                chunk_size=streaming_encryption.CHUNK_SIZE,
                object_name=object_key,
                metadata={
                    "storage-format": "odoo-vault-aesgcm-stream-v1",
                    "wrapped-key": wrapped_key,
                    "plaintext-size": str(plaintext_size),
                    "plaintext-sha256": plaintext_sha256,
                },
            )
            uploaded = True

            # If the PostgreSQL transaction rolls back after the MinIO
            # upload, remove the unreferenced ciphertext object.
            def cleanup_after_rollback(name=object_key):
                try:
                    object_storage.remove_object(name)
                except Exception:
                    _logger.exception(
                        "Failed to clean up rolled-back streamed attachment %s",
                        name,
                    )

            self.env.cr.postrollback.add(cleanup_after_rollback)

            store_fname = f"{_PREFIX}{bucket}/{object_key}"
            internal_values = {
                "file_size": plaintext_size,
                "checksum": sha1.hexdigest(),
                "index_content": index_content,
                "store_fname": store_fname,
                "db_datas": False,
            }

            # Bypass ir.attachment.write's deliberate removal of computed
            # storage fields. This is the same internal pattern Odoo uses
            # in _set_attachment_data() when calling super(Base, record).
            super(BaseIrAttachment, attachment.sudo()).write(
                internal_values
            )
            attachment.invalidate_recordset([
                "file_size", "checksum", "index_content",
                "store_fname", "db_datas", "raw", "datas",
            ])

            _logger.info(
                "SECURE_STREAM_UPLOAD_PERFORMANCE "
                "status=SUCCESS object=%s size_bytes=%s chunks=%s",
                object_key,
                plaintext_size,
                max(
                    1,
                    (plaintext_size + streaming_encryption.CHUNK_SIZE - 1)
                    // streaming_encryption.CHUNK_SIZE,
                ),
            )
            return attachment

        except Exception:
            if uploaded and object_key:
                try:
                    object_storage.remove_object(object_key)
                except Exception:
                    _logger.exception(
                        "Failed to clean up streamed attachment object %s",
                        object_key,
                    )

            if attachment and attachment.exists():
                try:
                    attachment.sudo().unlink()
                except Exception:
                    _logger.exception(
                        "Failed to remove incomplete streamed attachment record."
                    )
            raise

        finally:
            if temporary_source is not None:
                temporary_source.close()

    @api.model
    def _file_write(self, value, checksum):
        if not _storage_enabled():
            return super()._file_write(value, checksum)

        total_start = time.perf_counter()
        timings = {}

        try:
            # Normalize Odoo attachment data.
            stage = time.perf_counter()

            if isinstance(value, memoryview):
                value = value.tobytes()
            elif isinstance(value, bytearray):
                value = bytes(value)
            elif isinstance(value, str):
                value = value.encode("utf-8")

            if not isinstance(value, bytes):
                raise UserError(
                    "Odoo supplied attachment content in an unsupported format."
                )

            timings["normalize"] = time.perf_counter() - stage

            object_key = uuid.uuid4().hex
            plaintext_size = len(value)

            # Calculate document checksum.
            stage = time.perf_counter()
            plaintext_sha256 = hashlib.sha256(value).hexdigest()
            timings["sha256"] = time.perf_counter() - stage

            # Generate and wrap the data-encryption key.
            stage = time.perf_counter()
            data_key = key_provider.generate_data_key()[0]
            timings["dek_generation"] = time.perf_counter() - stage

            stage = time.perf_counter()
            wrapped_key = key_provider.wrap_data_key(data_key)
            timings["vault_wrap"] = time.perf_counter() - stage

            # Encrypt and upload.
            source = io.BytesIO(value)

            encrypted_stream = streaming_encryption.encrypt_stream(
                source=source,
                key=data_key,
                document_id=object_key,
                plaintext_size=plaintext_size,
                plaintext_sha256=plaintext_sha256,
            )

            uploaded = False

            try:
                stage = time.perf_counter()

                object_storage.put_encrypted_stream(
                    stream=object_storage.IteratorReader(encrypted_stream),
                    plaintext_size=plaintext_size,
                    chunk_size=streaming_encryption.CHUNK_SIZE,
                    object_name=object_key,
                    metadata={
                        "storage-format": "odoo-vault-aesgcm-stream-v1",
                        "wrapped-key": wrapped_key,
                        "plaintext-size": str(plaintext_size),
                        "plaintext-sha256": plaintext_sha256,
                    },
                )

                timings["encryption_and_minio"] = time.perf_counter() - stage
                uploaded = True

                def cleanup_after_rollback(name=object_key):
                    try:
                        object_storage.remove_object(name)
                    except Exception:
                        _logger.exception(
                            "Failed to clean up rolled-back Vault attachment object %s",
                            name,
                        )

                self.env.cr.postrollback.add(cleanup_after_rollback)

                total_elapsed = time.perf_counter() - total_start

                _logger.info(
                    "SECURE_UPLOAD_PERFORMANCE object=%s size_bytes=%s "
                    "normalize=%.3fs sha256=%.3fs dek_generation=%.3fs "
                    "vault_wrap=%.3fs encryption_and_minio=%.3fs "
                    "total=%.3fs",
                    object_key,
                    plaintext_size,
                    timings["normalize"],
                    timings["sha256"],
                    timings["dek_generation"],
                    timings["vault_wrap"],
                    timings["encryption_and_minio"],
                    total_elapsed,
                )

                return (
                    f"{_PREFIX}"
                    f"{os.getenv('ODOO_SECURE_MINIO_BUCKET', '').strip()}"
                    f"/{object_key}"
                )

            except Exception:
                if uploaded:
                    try:
                        object_storage.remove_object(object_key)
                    except Exception:
                        _logger.exception(
                            "Failed to clean up failed Vault attachment object %s",
                            object_key,
                        )

                raise

        except Exception:
            _logger.exception("Failed to write Vault-encrypted Odoo attachment")
            raise

    @api.model
    def _file_read(self, fname, bin_size=False):
        if not fname or not fname.startswith(_PREFIX):
            return super()._file_read(fname)

        total_started = time.perf_counter()
        timings = {}
        response = None
        object_key = "unknown"

        try:
            # 1. Resolve object reference.
            stage = time.perf_counter()

            bucket = os.getenv(
                "ODOO_SECURE_MINIO_BUCKET", ""
            ).strip()

            object_key = _object_key_from_fname(fname, bucket)

            timings["reference_resolution"] = (
                    time.perf_counter() - stage
            )

            if not object_key:
                raise UserError("Invalid secure attachment reference.")

            # 2. Initialize MinIO download.
            stage = time.perf_counter()

            response = object_storage.get_object(object_key)

            timings["minio_get_object"] = (
                    time.perf_counter() - stage
            )

            # 3. Read the encrypted format identifier.
            stage = time.perf_counter()

            first_eight = _read_exact(response, 8)

            if len(first_eight) != 8:
                raise ValueError(
                    "Encrypted attachment header is truncated."
                )

            timings["header_read"] = (
                    time.perf_counter() - stage
            )

            class HeaderPrefixedStream:
                def __init__(self, prefix, stream):
                    self.prefix = prefix
                    self.stream = stream

                def read(self, size=-1):
                    if size is None or size < 0:
                        result = self.prefix + self.stream.read()
                        self.prefix = b""
                        return result

                    if size == 0:
                        return b""

                    result = self.prefix[:size]
                    self.prefix = self.prefix[size:]

                    if len(result) == size:
                        return result

                    return result + self.stream.read(
                        size - len(result)
                    )

            # 4. Vault-backed ODSDOC01 format.
            if first_eight == streaming_encryption.MAGIC:

                stage = time.perf_counter()

                header = (
                        first_eight
                        + _read_exact(
                    response,
                    streaming_encryption.HEADER_SIZE - 8,
                )
                )

                if len(header) != streaming_encryption.HEADER_SIZE:
                    raise ValueError(
                        "Encrypted attachment header is truncated."
                    )

                plaintext_size = int.from_bytes(
                    header[12:20], "big"
                )

                plaintext_sha256 = header[20:52].hex()

                timings["full_header_read"] = (
                        time.perf_counter() - stage
                )

                if bin_size:
                    return human_size(plaintext_size)

                # 5. Read metadata from the existing GET response.
                # This eliminates the additional MinIO STAT request.
                stage = time.perf_counter()

                metadata = object_storage.get_object_metadata(
                    response
                )

                timings["metadata_read"] = (
                        time.perf_counter() - stage
                )

                wrapped_key = metadata.get("wrapped-key")

                if not wrapped_key:
                    raise ValueError(
                        "Vault-wrapped attachment key is missing."
                    )

                stored_size = metadata.get("plaintext-size")

                if stored_size is not None:
                    try:
                        stored_size = int(stored_size)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(
                            "Attachment size metadata is invalid."
                        ) from exc

                    if stored_size != plaintext_size:
                        raise ValueError(
                            "Attachment size metadata does not match its header."
                        )

                # 6. Unwrap the DEK through Vault.
                stage = time.perf_counter()

                data_key = key_provider.unwrap_data_key(
                    wrapped_key
                )

                timings["vault_unwrap"] = (
                        time.perf_counter() - stage
                )

                # 7. Decrypt and authenticate the complete stream.
                stage = time.perf_counter()

                plaintext_stream = streaming_encryption.decrypt_stream(
                    source=HeaderPrefixedStream(header, response),
                    key=data_key,
                    document_id=object_key,
                    expected_size=plaintext_size,
                    expected_sha256=plaintext_sha256,
                )

                plaintext = b"".join(plaintext_stream)

                timings["decrypt_and_assemble"] = (
                        time.perf_counter() - stage
                )

                if len(plaintext) != plaintext_size:
                    raise ValueError(
                        "Decrypted attachment size does not match its header."
                    )

                total_elapsed = time.perf_counter() - total_started

                _logger.info(
                    "SECURE_STORAGE_PERFORMANCE "
                    "operation=DOWNLOAD status=SUCCESS "
                    "format=ODSDOC01 object=%s size_bytes=%s "
                    "reference_resolution=%.4fs "
                    "minio_get_object=%.4fs "
                    "header_read=%.4fs "
                    "metadata_read=%.4fs "
                    "vault_unwrap=%.4fs "
                    "decrypt_and_assemble=%.4fs "
                    "total=%.4fs",
                    object_key,
                    plaintext_size,
                    timings["reference_resolution"],
                    timings["minio_get_object"],
                    timings["header_read"],
                    timings["metadata_read"],
                    timings["vault_unwrap"],
                    timings["decrypt_and_assemble"],
                    total_elapsed,
                )

                return plaintext

            raise ValueError(
                "Unsupported encrypted attachment format. "
                "Only the current Vault-backed ODSDOC01 format is supported."
            )

        except Exception as exc:
            total_elapsed = time.perf_counter() - total_started

            _logger.exception(
                "SECURE_STORAGE_PERFORMANCE "
                "operation=DOWNLOAD status=FAILED "
                "object=%s stages=%s total=%.4fs error_type=%s",
                object_key,
                timings,
                total_elapsed,
                type(exc).__name__,
            )

            raise UserError(
                "The attachment could not be retrieved or authenticated. "
                "Contact the system administrator."
            ) from exc

        finally:
            if response is not None:
                try:
                    response.close()
                    response.release_conn()
                except Exception:
                    _logger.debug(
                        "Could not clean up object-storage response",
                        exc_info=True,
                    )




    @api.model
    def _file_delete(self, fname):
        if not fname or not fname.startswith(_PREFIX):
            return super()._file_delete(fname)

        client, bucket = _client()
        object_key = _object_key_from_fname(fname, bucket)

        def delete_after_commit():
            try:
                client.remove_object(bucket, object_key)
            except Exception:
                _logger.exception(
                    "Could not delete secure attachment object %s", object_key
                )

        self.env.cr.postcommit.add(delete_after_commit)

    @api.model
    def _cron_cleanup_orphaned_secure_objects(self):
        """Delete old encrypted attachment objects not referenced by Odoo."""
        if not _storage_enabled():
            return

        try:
            client, bucket = _client()
            grace_hours = max(
                24,
                int(os.getenv("ODOO_SECURE_STORAGE_ORPHAN_GRACE_HOURS", "24")),
            )
            cutoff = datetime.now(timezone.utc) - timedelta(hours=grace_hours)
            allowed_formats = {
                "odoo-vault-aesgcm-stream-v1",
            }
            inspected = 0
            deleted = 0

            for listed in client.list_objects(bucket, recursive=True):
                if not listed.object_name:
                    continue
                if listed.last_modified and listed.last_modified > cutoff:
                    continue
                if not _OBJECT_KEY_RE.fullmatch(listed.object_name):
                    continue

                inspected += 1
                try:
                    info = client.stat_object(bucket, listed.object_name)
                    metadata = {
                        str(key).lower(): str(value)
                        for key, value in (info.metadata or {}).items()
                    }
                    storage_format = (
                        metadata.get("x-amz-meta-storage-format")
                        or metadata.get("storage-format")
                    )
                    if storage_format not in allowed_formats:
                        continue

                    object_reference = f"{_PREFIX}{bucket}/{listed.object_name}"
                    exists = self.sudo().search_count(
                        [("store_fname", "=", object_reference)], limit=1
                    )
                    if exists:
                        continue
                    if info.last_modified and info.last_modified > cutoff:
                        continue

                    client.remove_object(bucket, listed.object_name)
                    deleted += 1
                except Exception:
                    _logger.exception(
                        "Orphan cleanup failed for attachment object %s",
                        listed.object_name,
                    )

            _logger.info(
                "Secure attachment cleanup completed: inspected=%s deleted=%s",
                inspected,
                deleted,
            )
        except Exception:
            _logger.exception("Secure attachment orphan cleanup could not run")
