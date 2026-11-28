
"""Private temporary-file streaming for secure Odoo attachments.

Encrypted objects are read from MinIO and authenticated/decrypted one
chunk at a time. Plaintext is written to a private temporary file so Odoo's
native HTTP response can stream it without loading the whole file in RAM.
"""

import logging
import os
import re
import stat
import tempfile

from pathlib import Path

from ..services import key_provider, object_storage, streaming_encryption


_logger = logging.getLogger(__name__)

_REFERENCE_PREFIX = "secure-minio://"
_OBJECT_KEY_RE = re.compile(r"^[0-9a-f]{32}$")
_TEMP_PREFIX = "odoo-secure-attachment-"


class SecureAttachmentStreamError(Exception):
    """Raised when a secure attachment cannot be safely streamed."""


class HeaderPrefixedStream:
    """Replay bytes already read from the beginning of a stream."""

    def __init__(self, prefix, stream):
        self._prefix = bytearray(prefix)
        self._stream = stream

    def read(self, size=-1):
        if size is None or size < 0:
            prefix = bytes(self._prefix)
            self._prefix.clear()
            return prefix + self._stream.read()

        if size == 0:
            return b""

        result = bytes(self._prefix[:size])
        del self._prefix[:size]

        if len(result) == size:
            return result

        return result + self._stream.read(size - len(result))


def _read_exact(stream, size):
    """Read exactly size bytes, tolerating short reads."""
    result = bytearray()

    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            break
        result.extend(part)

    return bytes(result)


def _resolve_object_reference(store_fname):
    """Validate the secure MinIO reference and return bucket/object key."""
    if not isinstance(store_fname, str):
        raise SecureAttachmentStreamError(
            "Invalid secure attachment reference."
        )

    if not store_fname.startswith(_REFERENCE_PREFIX):
        raise SecureAttachmentStreamError(
            "Unsupported attachment storage reference."
        )

    bucket = os.getenv("ODOO_SECURE_MINIO_BUCKET", "").strip()

    if not bucket:
        raise SecureAttachmentStreamError(
            "Secure storage bucket is not configured."
        )

    reference = store_fname[len(_REFERENCE_PREFIX):]
    expected_prefix = bucket + "/"

    if not reference.startswith(expected_prefix):
        raise SecureAttachmentStreamError(
            "Attachment reference does not match the configured bucket."
        )

    object_key = reference[len(expected_prefix):]

    if not _OBJECT_KEY_RE.fullmatch(object_key):
        raise SecureAttachmentStreamError(
            "Invalid secure attachment object key."
        )

    return object_key


def _get_temporary_directory():
    """Return a validated directory for temporary plaintext files."""
    configured = os.getenv(
        "ODOO_SECURE_STORAGE_TEMP_DIR", ""
    ).strip()

    if not configured:
        # Development fallback only. Production must configure a private
        # memory-backed directory explicitly.
        directory = tempfile.gettempdir()

        _logger.warning(
            "ODOO_SECURE_STORAGE_TEMP_DIR is not configured. "
            "Using the operating-system temporary directory. "
            "Configure a private tmpfs directory for production."
        )

        return directory

    path = Path(configured)

    if not path.is_absolute():
        raise SecureAttachmentStreamError(
            "The secure temporary directory must be an absolute path."
        )

    if path.is_symlink() or not path.is_dir():
        raise SecureAttachmentStreamError(
            "The configured secure temporary directory is invalid."
        )

    if not os.access(str(path), os.W_OK | os.X_OK):
        raise SecureAttachmentStreamError(
            "The Odoo service cannot write to the secure temporary directory."
        )

    if os.name != "nt":
        directory_stat = path.stat()
        directory_mode = stat.S_IMODE(directory_stat.st_mode)

        if directory_stat.st_uid != os.geteuid():
            raise SecureAttachmentStreamError(
                "The secure temporary directory must belong to the Odoo service user."
            )

        if directory_mode & 0o077:
            raise SecureAttachmentStreamError(
                "The secure temporary directory must not grant group "
                "or other users access. Required permissions: 0700."
            )

    return str(path)


def decrypt_attachment_to_tempfile(
    store_fname,
    expected_file_size=None,
):
    """Decrypt an ODSDOC01 object to a private temporary file.

    The function does not return the file until every AES-GCM chunk and
    the final SHA-256 digest have been verified.

    Returns:
        tuple[str, int]: Temporary file path and verified plaintext size.

    Raises:
        SecureAttachmentStreamError: On invalid references, unavailable
        services, invalid metadata, authentication failure or I/O errors.
    """
    response = None
    temporary_path = None
    object_key = "unknown"

    try:
        object_key = _resolve_object_reference(store_fname)

        # Open the encrypted MinIO object.
        response = object_storage.get_object(object_key)

        # Read and validate the ODSDOC01 header.
        first_eight = _read_exact(response, 8)

        if first_eight != streaming_encryption.MAGIC:
            raise SecureAttachmentStreamError(
                "Unsupported encrypted attachment format."
            )

        remaining_header = _read_exact(
            response,
            streaming_encryption.HEADER_SIZE - 8,
        )

        if len(remaining_header) != streaming_encryption.HEADER_SIZE - 8:
            raise SecureAttachmentStreamError(
                "Encrypted attachment header is truncated."
            )

        header = first_eight + remaining_header

        plaintext_size = int.from_bytes(header[12:20], "big")
        plaintext_sha256 = header[20:52].hex()

        if expected_file_size is not None:
            if int(expected_file_size) != plaintext_size:
                raise SecureAttachmentStreamError(
                    "Attachment size does not match its Odoo metadata."
                )

        # Validate MinIO metadata against the authenticated header.
        metadata = object_storage.get_object_metadata(response)

        if metadata.get("storage-format") != "odoo-vault-aesgcm-stream-v1":
            raise SecureAttachmentStreamError(
                "Unsupported secure attachment storage format."
            )

        wrapped_key = metadata.get("wrapped-key")

        if not wrapped_key:
            raise SecureAttachmentStreamError(
                "The wrapped attachment key is missing."
            )

        metadata_size = metadata.get("plaintext-size")

        if metadata_size is None:
            raise SecureAttachmentStreamError(
                "The attachment size metadata is missing."
            )

        try:
            if int(metadata_size) != plaintext_size:
                raise SecureAttachmentStreamError(
                    "Attachment size metadata does not match its header."
                )
        except (TypeError, ValueError) as exc:
            raise SecureAttachmentStreamError(
                "Invalid attachment size metadata."
            ) from exc

        metadata_sha256 = metadata.get("plaintext-sha256", "").lower()

        if metadata_sha256 != plaintext_sha256:
            raise SecureAttachmentStreamError(
                "Attachment digest metadata does not match its header."
            )

        # Unwrap the per-attachment DEK through Vault Transit.
        data_key = key_provider.unwrap_data_key(wrapped_key)

        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise SecureAttachmentStreamError(
                "Vault returned an invalid attachment encryption key."
            )

        # Create a private temporary file only after validating the
        # reference, header, metadata and wrapped key.
        temporary_directory = _get_temporary_directory()

        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=_TEMP_PREFIX,
            suffix=".plain",
            dir=temporary_directory,
        )

        if os.name != "nt":
            os.chmod(temporary_path, 0o600)

        source = HeaderPrefixedStream(header, response)

        plaintext_stream = streaming_encryption.decrypt_stream(
            source=source,
            key=data_key,
            document_id=object_key,
            expected_size=plaintext_size,
            expected_sha256=plaintext_sha256,
        )

        written = 0

        # The iterator authenticates each AES-GCM chunk before yielding it.
        # Exhausting the iterator also verifies the final SHA-256 digest.
        with os.fdopen(file_descriptor, "wb") as output:
            for plaintext_chunk in plaintext_stream:
                output.write(plaintext_chunk)
                written += len(plaintext_chunk)

            output.flush()
            os.fsync(output.fileno())

        if written != plaintext_size:
            raise SecureAttachmentStreamError(
                "Decrypted attachment size is inconsistent."
            )

        _logger.info(
            "SECURE_ATTACHMENT_STREAM_DOWNLOAD "
            "status=SUCCESS object=%s size_bytes=%s",
            object_key,
            plaintext_size,
        )

        return temporary_path, plaintext_size

    except Exception as exc:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            except OSError:
                _logger.exception(
                    "Could not remove failed temporary attachment file."
                )

        _logger.exception(
            "Secure attachment streaming failed. object=%s error_type=%s",
            object_key,
            type(exc).__name__,
        )

        if isinstance(exc, SecureAttachmentStreamError):
            raise

        raise SecureAttachmentStreamError(
            "The secure attachment could not be decrypted and verified."
        ) from exc

    finally:
        if response is not None:
            try:
                response.close()
            finally:
                response.release_conn()
