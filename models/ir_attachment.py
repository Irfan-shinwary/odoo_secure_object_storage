import base64
import binascii
import hashlib
import io
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from minio import Minio
from odoo import api, models
from odoo.exceptions import UserError
from odoo.tools import human_size

from ..services import key_provider, object_storage, streaming_encryption

_logger = logging.getLogger(__name__)

# V2 authenticates the complete header as part of every chunk's AAD.
# V1 remains readable for compatibility with objects already stored.
_MAGIC_V1 = b"ODOOENC1"
_MAGIC_V2 = b"ODOOENC2"
_HEADER_SIZE = 28
_CHUNK_SIZE = 4 * 1024 * 1024
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


def _get_config():
    endpoint, access_key, secret_key, bucket, secure = _get_minio_config()
    master_key_b64 = os.getenv("ODOO_SECURE_STORAGE_MASTER_KEY", "").strip()
    if not master_key_b64:
        raise UserError(
            "The legacy attachment master key is not configured. "
            "Set ODOO_SECURE_STORAGE_MASTER_KEY to read legacy encrypted attachments."
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


def _encrypt_bytes_to_file(value, object_key, master_key, target_path):
    """Encrypt raw bytes, matching Odoo 17's _file_write contract."""
    if isinstance(value, bytearray):
        value = bytes(value)
    elif isinstance(value, str):
        # Odoo normally supplies bytes. Accept text only if it can be encoded
        # losslessly as UTF-8; never treat the value as Base64 here.
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError("Odoo attachment content must be bytes or text.")

    plain_size = len(value)
    nonce_prefix = os.urandom(8)
    header = _make_header(nonce_prefix, plain_size)
    aes = AESGCM(_derive_key(master_key, object_key))
    object_key_bytes = object_key.encode("ascii")
    counter = 0

    def encrypt_chunk(output, plaintext):
        nonlocal counter
        aad = object_key_bytes + header + counter.to_bytes(4, "big")
        output.write(aes.encrypt(_nonce(nonce_prefix, counter), plaintext, aad))
        counter += 1

    with open(target_path, "wb") as output:
        output.write(header)
        for offset in range(0, plain_size, _CHUNK_SIZE):
            encrypt_chunk(output, value[offset:offset + _CHUNK_SIZE])
        # Authenticate an empty object with one GCM tag.
        if plain_size == 0:
            encrypt_chunk(output, b"")

    return plain_size


def _decrypt_stream_to_bytes(response, object_key, master_key):
    """Decrypt an object and return raw bytes as required by Odoo _file_read."""
    header = _read_exact(response, _HEADER_SIZE)
    magic, nonce_prefix, chunk_size, remaining = _parse_header(header)

    if magic == _MAGIC_V1:
        aes = AESGCM(_derive_v1_key(master_key, object_key))
    else:
        aes = AESGCM(_derive_key(master_key, object_key))

    object_key_bytes = object_key.encode("ascii")
    counter = 0

    # Use a temporary file while decrypting so we do not maintain a second
    # growing plaintext buffer. Odoo's API still requires returning all bytes.
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
                aad = object_key_bytes + header + counter.to_bytes(4, "big")

            plaintext_chunk = aes.decrypt(
                _nonce(nonce_prefix, counter), encrypted_chunk, aad
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
        return plaintext_file.read()


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
    """Compatibility helper for older unit tests; production uses raw bytes."""
    if isinstance(value, str):
        value = value.encode("ascii")
    if not isinstance(value, bytes):
        raise ValueError("Attachment content must be Base64 bytes.")
    try:
        raw_value = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 attachment content.") from exc
    return _encrypt_bytes_to_file(raw_value, object_key, master_key, target_path)


def _decrypt_stream_to_base64(response, object_key, master_key):
    """Compatibility helper for older tests; Odoo itself needs raw bytes."""
    return base64.b64encode(
        _decrypt_stream_to_bytes(response, object_key, master_key)
    )


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    @api.model
    def _file_write(self, value, checksum):
        if not _storage_enabled():
            return super()._file_write(value, checksum)

        # New attachments use a random DEK wrapped by Vault Transit. Existing
        # ODOOENC1/ODOOENC2 objects remain readable through the legacy branch.
        _client()  # Validate MinIO configuration and bucket before contacting Vault.
        if isinstance(value, memoryview):
            value = value.tobytes()
        elif isinstance(value, bytearray):
            value = bytes(value)
        elif isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, bytes):
            raise UserError("Odoo supplied attachment content in an unsupported format.")

        object_key = uuid.uuid4().hex
        plaintext_size = len(value)
        plaintext_sha256 = hashlib.sha256(value).hexdigest()
        data_key = key_provider.generate_data_key()[0]
        wrapped_key = key_provider.wrap_data_key(data_key)
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

            def cleanup_after_rollback(name=object_key):
                try:
                    object_storage.remove_object(name)
                except Exception:
                    _logger.exception(
                        "Failed to clean up rolled-back Vault attachment object %s",
                        name,
                    )

            self.env.cr.postrollback.add(cleanup_after_rollback)
            return f"{_PREFIX}{os.getenv('ODOO_SECURE_MINIO_BUCKET', '').strip()}/{object_key}"
        except Exception:
            if uploaded:
                try:
                    object_storage.remove_object(object_key)
                except Exception:
                    _logger.exception(
                        "Failed to clean up failed Vault attachment object %s",
                        object_key,
                    )
            _logger.exception("Failed to write Vault-encrypted Odoo attachment")
            raise

    @api.model
    def _file_read(self, fname, bin_size=False):
        if not fname or not fname.startswith(_PREFIX):
            return super()._file_read(fname)

        client, bucket = _client()
        object_key = _object_key_from_fname(fname, bucket)
        response = None
        try:
            response = client.get_object(bucket, object_key)
            first_eight = _read_exact(response, 8)
            if len(first_eight) != 8:
                raise ValueError("Encrypted attachment header is truncated.")

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
                    return result + self.stream.read(size - len(result))

            if first_eight == streaming_encryption.MAGIC:
                # Vault-backed ODSDOC01 format: 52-byte authenticated header.
                header = first_eight + _read_exact(response, streaming_encryption.HEADER_SIZE - 8)
                if len(header) != streaming_encryption.HEADER_SIZE:
                    raise ValueError("Encrypted attachment header is truncated.")
                plaintext_size = int.from_bytes(header[12:20], "big")
                plaintext_sha256 = header[20:52].hex()
                if bin_size:
                    return human_size(plaintext_size)

                info = client.stat_object(bucket, object_key)
                metadata = {
                    str(key).lower(): str(value)
                    for key, value in (info.metadata or {}).items()
                }
                wrapped_key = (
                    metadata.get("x-amz-meta-wrapped-key")
                    or metadata.get("wrapped-key")
                )
                if not wrapped_key:
                    raise ValueError("Vault-wrapped attachment key is missing.")
                stored_size = metadata.get("x-amz-meta-plaintext-size") or metadata.get("plaintext-size")
                if stored_size is not None and int(stored_size) != plaintext_size:
                    raise ValueError("Attachment size metadata does not match its header.")

                _logger.error(
                    "Secure storage diagnostic: object_key=%s, "
                    "wrapped_key_present=%s, wrapped_key_length=%s, "
                    "wrapped_key_prefix=%s, vault_addr=%s, "
                    "transit_mount=%s, transit_key=%s",
                    object_key,
                    bool(wrapped_key),
                    len(wrapped_key) if wrapped_key else 0,
                    wrapped_key.split(":")[0] if wrapped_key else None,
                    os.getenv("ODOO_VAULT_ADDR"),
                    os.getenv("ODOO_VAULT_TRANSIT_MOUNT", "transit"),
                    os.getenv("ODOO_VAULT_TRANSIT_KEY", "odoo-documents"),
                )
                data_key = key_provider.unwrap_data_key(wrapped_key)
                plaintext_stream = streaming_encryption.decrypt_stream(
                    source=HeaderPrefixedStream(header, response),
                    key=data_key,
                    document_id=object_key,
                    expected_size=plaintext_size,
                    expected_sha256=plaintext_sha256,
                )
                # Odoo's _file_read contract returns the complete content bytes.
                return b"".join(plaintext_stream)

            # Legacy ODOOENC1/ODOOENC2 format; retain master-key compatibility.
            header = first_eight + _read_exact(response, _HEADER_SIZE - 8)
            magic, _nonce_prefix, _chunk_size, plaintext_size = _parse_header(header)
            if bin_size:
                return human_size(plaintext_size)
            _endpoint, _access, _secret, _bucket, _tls, master_key = _get_config()
            return _decrypt_stream_to_bytes(
                HeaderPrefixedStream(header, response), object_key, master_key
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
                        "Could not clean up object-storage response", exc_info=True
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
                "odoo-aesgcm-chunked-v1",
                "odoo-aesgcm-chunked-v2",
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
