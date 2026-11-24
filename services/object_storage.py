
import os
import uuid
import logging
import time

from minio import Minio


_logger = logging.getLogger(__name__)


class ObjectStorageError(Exception):
    pass


def _client():
    """Create a MinIO client using the configured credentials."""

    endpoint = os.getenv("ODOO_SECURE_MINIO_ENDPOINT", "")
    access_key = os.getenv("ODOO_SECURE_MINIO_ACCESS_KEY", "")
    secret_key = os.getenv("ODOO_SECURE_MINIO_SECRET_KEY", "")

    secure = os.getenv(
        "ODOO_SECURE_MINIO_TLS", "true"
    ).lower() in {"true", "1", "yes"}

    if not all((endpoint, access_key, secret_key)):
        raise ObjectStorageError(
            "MinIO configuration is incomplete."
        )

    return Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )


def _bucket():
    """Return the configured bucket name."""

    bucket = os.getenv("ODOO_SECURE_MINIO_BUCKET", "")

    if not bucket:
        raise ObjectStorageError(
            "MinIO bucket is not configured."
        )

    return bucket


def _log_performance(operation, object_name, started, stages,
                     status="SUCCESS", error=None):
    """Write a consistent performance log for a MinIO operation."""

    total = time.perf_counter() - started

    stage_details = " ".join(
        f"{name}={elapsed:.4f}s"
        for name, elapsed in stages.items()
    )

    message = (
        "MINIO_OPERATION_PERFORMANCE "
        f"operation={operation} "
        f"status={status} "
        f"object={object_name or 'unknown'} "
        f"{stage_details} "
        f"total={total:.4f}s"
    )

    if error:
        message += f" error_type={type(error).__name__}"

    if status == "SUCCESS":
        _logger.info(message)
    else:
        _logger.exception(message, exc_info=error)


def encrypted_size(plaintext_size, chunk_size):
    """
    Calculate the expected encrypted object size.

    Header: 52 bytes.
    Each chunk: 4-byte length + 12-byte nonce
                + plaintext bytes + 16-byte GCM tag.
    """

    chunks = max(
        1,
        (plaintext_size + chunk_size - 1) // chunk_size
    )

    return 52 + plaintext_size + chunks * (4 + 12 + 16)


def put_encrypted_stream(
    stream,
    plaintext_size,
    chunk_size,
    object_name=None,
    metadata=None,
):
    client = _client()
    bucket = _bucket()

    if not client.bucket_exists(bucket):
        raise ObjectStorageError(
            "Secure storage bucket does not exist."
        )

    object_name = object_name or uuid.uuid4().hex

    length = encrypted_size(
        plaintext_size,
        chunk_size,
    )

    started = time.perf_counter()
    uploaded = False
    put_elapsed = 0.0
    finalize_elapsed = 0.0

    try:
        # Upload exactly the calculated encrypted content length.
        put_started = time.perf_counter()

        client.put_object(
            bucket,
            object_name,
            stream,
            length=length,
            part_size=10 * 1024 * 1024,
            content_type="application/octet-stream",
            metadata=metadata or {
                "storage-format": "odoo-secure-document-v1"
            },
        )

        put_elapsed = time.perf_counter() - put_started
        uploaded = True

        # IMPORTANT:
        # Force the underlying encryption generator to finish.
        #
        # MinIO may stop reading immediately after consuming
        # the declared content length. The generator can therefore
        # remain suspended at its final yield.
        finalize_started = time.perf_counter()

        extra_data = stream.read(1)

        finalize_elapsed = (
            time.perf_counter() - finalize_started
        )

        if extra_data:
            raise ObjectStorageError(
                "Encrypted stream contains unexpected trailing data."
            )

        elapsed = time.perf_counter() - started

        _logger.info(
            "MINIO_UPLOAD_PERFORMANCE "
            "status=SUCCESS object=%s "
            "plaintext_bytes=%s encrypted_bytes=%s "
            "put_object=%.4fs stream_finalize=%.4fs "
            "total=%.4fs",
            object_name,
            plaintext_size,
            length,
            put_elapsed,
            finalize_elapsed,
            elapsed,
        )

    except Exception as exc:

        # If the upload completed but stream validation failed,
        # remove the object to avoid leaving an invalid object.
        if uploaded:
            try:
                client.remove_object(bucket, object_name)
                _logger.warning(
                    "MINIO_UPLOAD_CLEANUP object=%s status=SUCCESS",
                    object_name,
                )
            except Exception:
                _logger.exception(
                    "MINIO_UPLOAD_CLEANUP object=%s status=FAILED",
                    object_name,
                )

        _logger.exception(
            "MINIO_UPLOAD_PERFORMANCE "
            "status=FAILED object=%s",
            object_name,
        )

        raise ObjectStorageError(
            "Encrypted object upload failed."
        ) from exc

    return object_name


def stat_object(object_name):
    """
    Retrieve object metadata.

    Measures the MinIO stat request independently.
    """

    total_started = time.perf_counter()
    stages = {}

    try:
        started = time.perf_counter()
        client = _client()
        stages["client_init"] = time.perf_counter() - started

        started = time.perf_counter()
        bucket = _bucket()
        stages["bucket_config"] = time.perf_counter() - started

        started = time.perf_counter()
        result = client.stat_object(bucket, object_name)
        stages["stat_object"] = time.perf_counter() - started

        _log_performance(
            operation="STAT",
            object_name=object_name,
            started=total_started,
            stages=stages,
        )

        return result

    except Exception as exc:
        _log_performance(
            operation="STAT",
            object_name=object_name,
            started=total_started,
            stages=stages,
            status="FAILED",
            error=exc,
        )

        if isinstance(exc, ObjectStorageError):
            raise

        raise ObjectStorageError(
            "MinIO object metadata retrieval failed."
        ) from exc


def get_object(object_name):
    """
    Initialize a MinIO object download.

    Note: get_object() returns a response stream.
    The actual download is measured when that stream is read
    by the attachment download pipeline.
    """

    total_started = time.perf_counter()
    stages = {}

    try:
        started = time.perf_counter()
        client = _client()
        stages["client_init"] = time.perf_counter() - started

        started = time.perf_counter()
        bucket = _bucket()
        stages["bucket_config"] = time.perf_counter() - started

        started = time.perf_counter()
        response = client.get_object(bucket, object_name)
        stages["get_object_request"] = (
            time.perf_counter() - started
        )

        _log_performance(
            operation="DOWNLOAD_INIT",
            object_name=object_name,
            started=total_started,
            stages=stages,
        )

        return response

    except Exception as exc:
        _log_performance(
            operation="DOWNLOAD_INIT",
            object_name=object_name,
            started=total_started,
            stages=stages,
            status="FAILED",
            error=exc,
        )

        if isinstance(exc, ObjectStorageError):
            raise

        raise ObjectStorageError(
            "Encrypted object download initialization failed."
        ) from exc


def get_object_metadata(response):
    """
    Extract custom S3 metadata from an existing MinIO GET response.

    Example:
        x-amz-meta-wrapped-key: ...
        x-amz-meta-plaintext-size: 838917

    Returns:
        {
            "wrapped-key": "...",
            "plaintext-size": "838917"
        }
    """
    try:
        metadata = {}
        prefix = "x-amz-meta-"

        for name, value in response.headers.items():
            normalized_name = str(name).lower().strip()

            if normalized_name.startswith(prefix):
                metadata_key = normalized_name[len(prefix):]
                metadata[metadata_key] = str(value).strip()

        return metadata

    except Exception as exc:
        raise ObjectStorageError(
            "Unable to extract encrypted object metadata."
        ) from exc
def remove_object(object_name):
    """Delete an object from MinIO and measure the operation."""

    total_started = time.perf_counter()
    stages = {}

    try:
        started = time.perf_counter()
        client = _client()
        stages["client_init"] = time.perf_counter() - started

        started = time.perf_counter()
        bucket = _bucket()
        stages["bucket_config"] = time.perf_counter() - started

        started = time.perf_counter()
        client.remove_object(bucket, object_name)
        stages["remove_object"] = time.perf_counter() - started

        _log_performance(
            operation="DELETE",
            object_name=object_name,
            started=total_started,
            stages=stages,
        )

    except Exception as exc:
        _log_performance(
            operation="DELETE",
            object_name=object_name,
            started=total_started,
            stages=stages,
            status="FAILED",
            error=exc,
        )

        if isinstance(exc, ObjectStorageError):
            raise

        raise ObjectStorageError(
            "MinIO object deletion failed."
        ) from exc


class IteratorReader:
    """Expose an iterable of bytes through a bounded-memory read() interface."""

    def __init__(self, iterable):
        self._iterator = iter(iterable)
        self._buffer = bytearray()
        self._finished = False

    def read(self, size=-1):
        if size is None or size < 0:
            # Avoid unbounded reads.
            size = 10 * 1024 * 1024

        while len(self._buffer) < size and not self._finished:
            try:
                part = next(self._iterator)
            except StopIteration:
                self._finished = True
                break

            if part:
                self._buffer.extend(part)

        result = bytes(self._buffer[:size])
        del self._buffer[:size]

        return result

