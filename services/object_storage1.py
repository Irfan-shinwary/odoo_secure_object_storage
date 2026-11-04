
import os
import uuid

from minio import Minio


class ObjectStorageError(Exception):
    pass


def _client():
    endpoint = os.getenv("ODOO_SECURE_MINIO_ENDPOINT", "")
    access_key = os.getenv("ODOO_SECURE_MINIO_ACCESS_KEY", "")
    secret_key = os.getenv("ODOO_SECURE_MINIO_SECRET_KEY", "")
    secure = os.getenv("ODOO_SECURE_MINIO_TLS", "true").lower() in {
        "true", "1", "yes"
    }

    if not all((endpoint, access_key, secret_key)):
        raise ObjectStorageError("MinIO configuration is incomplete.")

    return Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )


def _bucket():
    bucket = os.getenv("ODOO_SECURE_MINIO_BUCKET", "")
    if not bucket:
        raise ObjectStorageError("MinIO bucket is not configured.")
    return bucket


def encrypted_size(plaintext_size, chunk_size):
    chunks = max(1, (plaintext_size + chunk_size - 1) // chunk_size)
    # Header: 52 bytes. Each chunk: 4-byte length + 12-byte nonce
    # + plaintext bytes + 16-byte GCM tag.
    return 52 + plaintext_size + chunks * (4 + 12 + 16)



def put_encrypted_stream(stream, plaintext_size, chunk_size):
    client = _client()
    bucket = _bucket()

    if not client.bucket_exists(bucket):
        raise ObjectStorageError("Configured MinIO bucket does not exist.")

    object_name = uuid.uuid4().hex
    length = encrypted_size(plaintext_size, chunk_size)

    try:
        client.put_object(
            bucket,
            object_name,
            stream,
            length=length,
            part_size=10 * 1024 * 1024,
            content_type="application/octet-stream",
            metadata={"storage-format": "odoo-secure-document-v1"},
        )
    except Exception as exc:
        raise ObjectStorageError("Encrypted object upload failed.") from exc

    return object_name

def get_object(object_name):
    return _client().get_object(_bucket(), object_name)


def remove_object(object_name):
    _client().remove_object(_bucket(), object_name)



class IteratorReader:
    """Expose an iterable of bytes through a bounded-memory read() interface."""

    def __init__(self, iterable):
        self._iterator = iter(iterable)
        self._buffer = bytearray()
        self._finished = False

    def read(self, size=-1):
        if size is None or size < 0:
            # Avoid unbounded reads. MinIO should request a finite part size.
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
