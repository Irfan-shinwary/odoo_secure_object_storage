
import base64
import binascii
import logging
import os
import re
import tempfile
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from minio import Minio
from odoo import api, models
from odoo.exceptions import UserError
from odoo.tools import human_size
from datetime import datetime, timedelta, timezone

_logger = logging.getLogger(__name__)

# V2 authenticates the complete header as part of every chunk's AAD.
# V1 remains readable for compatibility with objects already stored.
_MAGIC_V1 = b"ODOOENC1"
_MAGIC_V2 = b"ODOOENC2"
_HEADER_SIZE = 28
_CHUNK_SIZE = 4 * 1024 * 1024
_B64_INPUT_CHUNK = 4 * 1024 * 1024
_PREFIX = "secure-minio://"
_OBJECT_KEY_RE = re.compile(r"^[0-9a-f]{32}$")
_BASE64_SEGMENT_RE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _storage_enabled():
    return _env_bool("ODOO_SECURE_STORAGE_ENABLED", False)


def _get_config():
    endpoint = os.getenv("ODOO_SECURE_MINIO_ENDPOINT", "").strip()
    access_key = os.getenv("ODOO_SECURE_MINIO_ACCESS_KEY", "")
    secret_key = os.getenv("ODOO_SECURE_MINIO_SECRET_KEY", "")
    bucket = os.getenv("ODOO_SECURE_MINIO_BUCKET", "").strip()
    secure = _env_bool("ODOO_SECURE_MINIO_TLS", True)
    master_key_b64 = os.getenv("ODOO_SECURE_STORAGE_MASTER_KEY", "").strip()

    if not all((endpoint, access_key, secret_key, bucket, master_key_b64)):
        raise UserError(
            "Secure attachment storage is enabled but one or more required "
            "ODOO_SECURE_* environment variables are missing."
        )

    try:
        master_key = base64.b64decode(master_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UserError(
            "ODOO_SECURE_STORAGE_MASTER_KEY must be valid Base64."
        ) from exc

    if len(master_key) != 32:
        raise UserError(
            "ODOO_SECURE_STORAGE_MASTER_KEY must decode to exactly 32 bytes."
        )

    return endpoint, access_key, secret_key, bucket, secure, master_key


def _client():
    endpoint, access_key, secret_key, bucket, secure, _master_key = (
        _get_config()
    )
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


def _derive_key(master_key, object_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=object_key.encode("ascii"),
        info=b"odoo-secure-attachment-aesgcm-v2",
    ).derive(master_key)


def _derive_v1_key(master_key, object_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=object_key.encode("ascii"),
        info=b"odoo-secure-attachment-aesgcm-v1",
    ).derive(master_key)


def _nonce(prefix, counter):
    if not 0 <= counter < 2**32:
        raise ValueError("Attachment exceeds the supported encrypted chunk count.")
    return prefix + counter.to_bytes(4, "big")


def _make_header(nonce_prefix, plain_size):
    if not 0 <= plain_size < 2**64:
        raise ValueError("Attachment size is outside the supported range.")
    return (
        _MAGIC_V2
        + nonce_prefix
        + _CHUNK_SIZE.to_bytes(4, "big")
        + plain_size.to_bytes(8, "big")
    )


def _parse_header(header):
    if len(header) != _HEADER_SIZE:
        raise ValueError("Invalid encrypted attachment header.")

    magic = header[:8]
    if magic not in (_MAGIC_V1, _MAGIC_V2):
        raise ValueError("Unknown encrypted attachment format.")

    nonce_prefix = header[8:16]
    chunk_size = int.from_bytes(header[16:20], "big")
    plain_size = int.from_bytes(header[20:28], "big")

    if not 1 <= chunk_size <= 16 * 1024 * 1024:
        raise ValueError("Invalid encrypted attachment chunk size.")

    if magic == _MAGIC_V2 and chunk_size != _CHUNK_SIZE:
        raise ValueError("Unsupported version-2 chunk size.")

    return magic, nonce_prefix, chunk_size, plain_size


def _object_key_from_fname(fname, bucket):
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


def _encrypt_base64_to_file(value, object_key, master_key, target_path):

    if isinstance(value, str):
        value = value.encode("ascii")
    if not isinstance(value, bytes):
        raise ValueError("Attachment content must be Base64 bytes.")

    if len(value) % 4:
        raise ValueError("Invalid Base64 attachment length.")

    padding = 2 if value.endswith(b"==") else 1 if value.endswith(b"=") else 0
    plain_size = (len(value) // 4) * 3 - padding

    if plain_size < 0:
        raise ValueError("Invalid Base64 attachment content.")

    nonce_prefix = os.urandom(8)
    header = _make_header(nonce_prefix, plain_size)
    aes = AESGCM(_derive_key(master_key, object_key))
    object_key_bytes = object_key.encode("ascii")
    counter = 0
    pending = bytearray()

    def encrypt_chunk(output, plaintext):
        nonlocal counter
        aad = object_key_bytes + header + counter.to_bytes(4, "big")
        output.write(
            aes.encrypt(_nonce(nonce_prefix, counter), plaintext, aad)
        )
        counter += 1

    with open(target_path, "wb") as output:
        output.write(header)

        for offset in range(0, len(value), _B64_INPUT_CHUNK):
            segment = value[offset:offset + _B64_INPUT_CHUNK]
            is_last = offset + len(segment) == len(value)

            if not _BASE64_SEGMENT_RE.fullmatch(segment):
                raise ValueError("Invalid Base64 attachment content.")

            if not is_last and b"=" in segment:
                raise ValueError("Base64 padding is only permitted at the end.")

            try:
                decoded = base64.b64decode(segment, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("Invalid Base64 attachment content.") from exc

            pending.extend(decoded)

            while len(pending) >= _CHUNK_SIZE:
                chunk = bytes(pending[:_CHUNK_SIZE])
                del pending[:_CHUNK_SIZE]
                encrypt_chunk(output, chunk)

        # V2 always authenticates at least one chunk, even for an empty file.
        if pending:
            encrypt_chunk(output, bytes(pending))
        elif plain_size == 0:
            encrypt_chunk(output, b"")

    return plain_size


def _decrypt_stream_to_base64(response, object_key, master_key):
    header = _read_exact(response, _HEADER_SIZE)
    magic, nonce_prefix, chunk_size, remaining = _parse_header(header)

    if magic == _MAGIC_V1:
        aes = AESGCM(_derive_v1_key(master_key, object_key))
    else:
        aes = AESGCM(_derive_key(master_key, object_key))

    object_key_bytes = object_key.encode("ascii")
    counter = 0

    # Odoo requires _file_read() to return all Base64 bytes. Keep plaintext
    # and encoded data on disk during processing to avoid a full plaintext
    # bytearray plus a second full-size Base64 allocation.
    with tempfile.TemporaryFile(mode="w+b") as plaintext_file:
        chunks_to_read = (
            (remaining + chunk_size - 1) // chunk_size
            if remaining
            else (1 if magic == _MAGIC_V2 else 0)
        )

        for _ in range(chunks_to_read):
            plain_length = min(chunk_size, remaining)
            encrypted_length = plain_length + 16
            encrypted_chunk = _read_exact(response, encrypted_length)

            if len(encrypted_chunk) != encrypted_length:
                raise ValueError("Encrypted attachment is truncated.")

            if magic == _MAGIC_V1:
                aad = object_key_bytes + counter.to_bytes(4, "big")
            else:
                aad = (
                    object_key_bytes
                    + header
                    + counter.to_bytes(4, "big")
                )

            plaintext_chunk = aes.decrypt(
                _nonce(nonce_prefix, counter),
                encrypted_chunk,
                aad,
            )

            if len(plaintext_chunk) != plain_length:
                raise ValueError("Decrypted attachment chunk has an invalid size.")

            plaintext_file.write(plaintext_chunk)
            remaining -= plain_length
            counter += 1

        if remaining != 0:
            raise ValueError("Encrypted attachment size is inconsistent.")

        if response.read(1):
            raise ValueError("Encrypted attachment contains trailing data.")

        plaintext_file.seek(0)

        with tempfile.TemporaryFile(mode="w+b") as encoded_file:
            # Three-byte boundaries preserve valid Base64 between iterations.
            while True:
                chunk = plaintext_file.read(3 * 1024 * 1024)
                if not chunk:
                    break
                encoded_file.write(base64.b64encode(chunk))

            encoded_file.seek(0)
            return encoded_file.read()

def _decrypt_stream_to_bytes(response, object_key, master_key):
    """Decrypt a V1 or V2 object and return raw attachment bytes."""
    header = _read_exact(response, _HEADER_SIZE)
    if len(header) != _HEADER_SIZE:
        raise ValueError("Encrypted attachment header is truncated.")

    magic, nonce_prefix, chunk_size, remaining = _parse_header(header)

    if magic == _MAGIC_V1:
        aes = AESGCM(_derive_v1_key(master_key, object_key))
    else:
        aes = AESGCM(_derive_key(master_key, object_key))

        object_key_bytes = object_key.encode("ascii")
        counter = 0
        chunks_to_read = (
            (remaining + chunk_size - 1) // chunk_size
            if remaining
            else (1 if magic == _MAGIC_V2 else 0)
        )

        with tempfile.TemporaryFile(mode="w+b") as plaintext_file:
            for _ in range(chunks_to_read):
                plain_length = min(chunk_size, remaining)
                encrypted_length = plain_length + 16
                encrypted_chunk = _read_exact(response, encrypted_length)

                if len(encrypted_chunk) != encrypted_length:
                    raise ValueError("Encrypted attachment is truncated.")

                if magic == _MAGIC_V1:
                    aad = object_key_bytes + counter.to_bytes(4, "big")
                else:
                    aad = (
                            object_key_bytes
                            + header
                            + counter.to_bytes(4, "big")
                    )

                plaintext_chunk = aes.decrypt(
                    _nonce(nonce_prefix, counter),
                    encrypted_chunk,
                    aad,
                )

                if len(plaintext_chunk) != plain_length:
                    raise ValueError(
                        "Decrypted attachment chunk has an invalid size."
                    )

                plaintext_file.write(plaintext_chunk)
                remaining -= plain_length
                counter += 1

            if remaining != 0:
                raise ValueError("Encrypted attachment size is inconsistent.")

            if response.read(1):
                raise ValueError("Encrypted attachment contains trailing data.")

            plaintext_file.seek(0)
            return plaintext_file.read()


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    @api.model
    def _file_write(self, value, checksum):
        if not _storage_enabled():
            return super()._file_write(value, checksum)

        client, bucket = _client()
        _endpoint, _access, _secret, _bucket, _tls, master_key = _get_config()
        object_key = uuid.uuid4().hex
        temp_path = None
        uploaded = False

        try:
            with tempfile.NamedTemporaryFile(
                prefix="odoo-encrypted-",
                suffix=".bin",
                delete=False,
            ) as temp_file:
                temp_path = temp_file.name

            # plain_size = _encrypt_base64_to_file(
            #     value, object_key, master_key, temp_path
            # )
            plain_size = _encrypt_bytes_to_file(
                value, object_key, master_key, temp_path
            )

            client.fput_object(
                bucket,
                object_key,
                temp_path,
                content_type="application/octet-stream",
                metadata={
                    "storage-format": "odoo-aesgcm-chunked-v2",
                    "plaintext-size": str(plain_size),
                },
            )
            uploaded = True

            # If the surrounding Odoo transaction rolls back, remove the
            # object written by this operation.
            def cleanup_after_rollback():
                try:
                    client.remove_object(bucket, object_key)
                except Exception:
                    _logger.exception(
                        "Failed to clean up rolled-back attachment object %s",
                        object_key,
                    )

            self.env.cr.postrollback.add(cleanup_after_rollback)

            return f"{_PREFIX}{bucket}/{object_key}"

        except Exception:
            if uploaded:
                try:
                    client.remove_object(bucket, object_key)
                except Exception:
                    _logger.exception(
                        "Failed to clean up failed attachment object %s",
                        object_key,
                    )
            _logger.exception(
                "Failed to write encrypted Odoo attachment to object storage"
            )
            raise

        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    _logger.exception(
                        "Could not remove temporary encrypted attachment file"
                    )

    @api.model
    def _file_read(self, fname, bin_size=False):
        if not fname or not fname.startswith(_PREFIX):
            return super()._file_read(fname)

        client, bucket = _client()
        _endpoint, _access, _secret, _bucket, _tls, master_key = _get_config()
        object_key = _object_key_from_fname(fname, bucket)

        response = None
        try:
            response = client.get_object(bucket, object_key)
            header = _read_exact(response, _HEADER_SIZE)
            magic, _nonce_prefix, _chunk_size, plain_size = _parse_header(header)

            if bin_size:
                # This reports header metadata only; it does not authenticate
                # the complete object contents.
                return human_size(plain_size)

            # The header has already been consumed; reconstruct the stream
            # expected by the decryptor without buffering the entire object.
            class HeaderPrefixedStream:
                def __init__(self, prefix, stream):
                    self.prefix = prefix
                    self.stream = stream

                def read(self, size=-1):
                    if self.prefix:
                        if size < 0:
                            result = self.prefix
                            self.prefix = b""
                            return result + self.stream.read()
                        result = self.prefix[:size]
                        self.prefix = self.prefix[size:]
                        if len(result) == size:
                            return result
                        return result + self.stream.read(size - len(result))
                    return self.stream.read(size)

            reconstructed = HeaderPrefixedStream(header, response)
            # return _decrypt_stream_to_base64(
            #     reconstructed, object_key, master_key
            # )
            return _decrypt_stream_to_bytes(
                reconstructed, object_key, master_key
            )

        except Exception as exc:
            _logger.exception("Failed to read/decrypt secure Odoo attachment")
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
                    "Could not delete secure attachment object %s",
                    object_key,
                )

        self.env.cr.postcommit.add(delete_after_commit)


    @api.model
    def _cron_cleanup_orphaned_secure_objects(self):
        """Retry cleanup of old encrypted attachment objects not in Odoo."""
        if not _storage_enabled():
            return

        try:
            client, bucket = _client()
            grace_hours = max(
                24,
                int(os.getenv("ODOO_SECURE_STORAGE_ORPHAN_GRACE_HOURS", "24")),
            )
            cutoff = datetime.now(timezone.utc) - timedelta(hours=grace_hours)

            # Never clean arbitrary objects: this bucket may also contain
            # secure-document API objects.
            allowed_formats = {
                "odoo-aesgcm-chunked-v1",
                "odoo-aesgcm-chunked-v2",
            }

            inspected = 0
            deleted = 0

            for listed in client.list_objects(bucket, recursive=True):
                if not listed.object_name:
                    continue

                # Avoid repeated work on newly uploaded objects and allow
                # transactions enough time to commit.
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

                    object_reference = (
                        f"{_PREFIX}{bucket}/{listed.object_name}"
                    )

                    # sudo is needed for the system cleanup job to inspect
                    # attachments across users and companies.
                    exists = self.sudo().search_count(
                        [("store_fname", "=", object_reference)],
                        limit=1,
                    )

                    if exists:
                        continue

                    # Recheck age from the object's current metadata.
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

def _encrypt_bytes_to_file(value, object_key, master_key, target_path):
        """Encrypt raw attachment bytes using the V2 chunked AES-GCM format."""
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            raise ValueError("Attachment content must be bytes.")

        plain_size = len(value)
        nonce_prefix = os.urandom(8)
        header = _make_header(nonce_prefix, plain_size)
        aes = AESGCM(_derive_key(master_key, object_key))
        object_key_bytes = object_key.encode("ascii")
        counter = 0

        with open(target_path, "wb") as output:
            output.write(header)

            # V2 authenticates an empty file with one empty encrypted chunk.
            if not value:
                aad = object_key_bytes + header + counter.to_bytes(4, "big")
                output.write(
                    aes.encrypt(_nonce(nonce_prefix, counter), b"", aad)
                )
                return plain_size

            for offset in range(0, plain_size, _CHUNK_SIZE):
                chunk = value[offset:offset + _CHUNK_SIZE]
                aad = object_key_bytes + header + counter.to_bytes(4, "big")

                output.write(
                    aes.encrypt(_nonce(nonce_prefix, counter), chunk, aad)
                )
                counter += 1

        return plain_size

