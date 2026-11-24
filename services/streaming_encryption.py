
import hashlib
import logging
import os
import struct
import time

from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_logger = logging.getLogger(__name__)


MAGIC = b"ODSDOC01"
CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
HEADER_SIZE = 8 + 4 + 8 + 32
LENGTH_SIZE = 4
NONCE_SIZE = 12
TAG_SIZE = 16


class SecureStreamError(Exception):
    pass


def _aad(document_id, index, size, digest):
    return (
        MAGIC
        + document_id.encode("utf-8")
        + struct.pack(">Q", index)
        + struct.pack(">Q", size)
        + digest
    )


def _read_exact(source, size):
    result = bytearray()

    while len(result) < size:
        part = source.read(size - len(result))

        if not part:
            break

        result.extend(part)

    return bytes(result)


def encrypt_stream(
    source: BinaryIO,
    key: bytes,
    document_id: str,
    plaintext_size: int,
    plaintext_sha256: str,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    """Yield framed AES-GCM encrypted chunks with performance metrics."""

    total_started = time.perf_counter()

    source_read_time = 0.0
    aes_encrypt_time = 0.0
    chunks = 0
    processed_bytes = 0
    status = "SUCCESS"

    try:
        if len(key) != 32:
            raise ValueError(
                "The data-encryption key must be 32 bytes."
            )

        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError("Invalid encryption chunk size.")

        if plaintext_size < 0:
            raise ValueError("Invalid plaintext size.")

        digest = bytes.fromhex(plaintext_sha256)

        if len(digest) != 32:
            raise ValueError(
                "SHA-256 digest must be 32 bytes."
            )

        yield MAGIC + struct.pack(">I", chunk_size)
        yield struct.pack(">Q", plaintext_size) + digest

        aes = AESGCM(key)
        index = 0
        remaining = plaintext_size

        # Empty documents still receive one authenticated chunk.
        while remaining > 0 or index == 0:

            expected = min(chunk_size, remaining)

            stage = time.perf_counter()
            plaintext = _read_exact(source, expected)
            source_read_time += time.perf_counter() - stage

            if len(plaintext) != expected:
                raise SecureStreamError(
                    "Source file changed or ended unexpectedly."
                )

            nonce = os.urandom(NONCE_SIZE)
            aad = _aad(
                document_id,
                index,
                plaintext_size,
                digest,
            )

            stage = time.perf_counter()

            ciphertext = aes.encrypt(
                nonce,
                plaintext,
                aad,
            )

            aes_encrypt_time += time.perf_counter() - stage

            yield struct.pack(">I", len(ciphertext))
            yield nonce
            yield ciphertext

            processed_bytes += len(plaintext)
            remaining -= len(plaintext)
            index += 1
            chunks += 1

        # Detect source changes after the expected content.
        stage = time.perf_counter()
        extra_data = source.read(1)
        source_read_time += time.perf_counter() - stage

        if extra_data:
            raise SecureStreamError(
                "Source file grew during encryption."
            )

    except GeneratorExit:
        status = "CANCELLED"
        raise

    except Exception:
        status = "FAILED"
        raise

    finally:
        total_elapsed = time.perf_counter() - total_started

        _logger.info(
            "AES_GCM_ENCRYPTION_PERFORMANCE "
            "status=%s object=%s plaintext_bytes=%s chunks=%s "
            "source_read=%.4fs aes_encrypt=%.4fs total=%.4fs",
            status,
            document_id,
            processed_bytes,
            chunks,
            source_read_time,
            aes_encrypt_time,
            total_elapsed,
        )


def decrypt_stream(
    source: BinaryIO,
    key: bytes,
    document_id: str,
    expected_size: int,
    expected_sha256: str,
) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks with performance metrics."""

    total_started = time.perf_counter()

    source_read_time = 0.0
    aes_decrypt_time = 0.0
    hash_time = 0.0

    chunks = 0
    processed_bytes = 0
    integrity_time = 0.0
    status = "SUCCESS"

    try:
        if len(key) != 32:
            raise ValueError(
                "The data-encryption key must be 32 bytes."
            )

        stage = time.perf_counter()
        header = _read_exact(source, HEADER_SIZE)
        source_read_time += time.perf_counter() - stage

        if len(header) != HEADER_SIZE or header[:8] != MAGIC:
            raise SecureStreamError(
                "Invalid encrypted document header."
            )

        chunk_size = struct.unpack(">I", header[8:12])[0]
        plaintext_size = struct.unpack(">Q", header[12:20])[0]
        digest = header[20:52]

        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise SecureStreamError(
                "Invalid encrypted chunk size."
            )

        if plaintext_size != expected_size:
            raise SecureStreamError(
                "Document size does not match metadata."
            )

        if digest.hex() != expected_sha256:
            raise SecureStreamError(
                "Document digest does not match metadata."
            )

        aes = AESGCM(key)
        remaining = plaintext_size
        index = 0
        calculated_hash = hashlib.sha256()

        while remaining > 0 or index == 0:

            # Read encrypted chunk length.
            stage = time.perf_counter()
            length_data = _read_exact(source, LENGTH_SIZE)
            source_read_time += time.perf_counter() - stage

            if len(length_data) != LENGTH_SIZE:
                raise SecureStreamError(
                    "Missing encrypted chunk."
                )

            (ciphertext_size,) = struct.unpack(
                ">I", length_data
            )

            expected_plain = min(chunk_size, remaining)

            if ciphertext_size != expected_plain + TAG_SIZE:
                raise SecureStreamError(
                    "Invalid encrypted chunk length."
                )

            # Read nonce and ciphertext.
            stage = time.perf_counter()

            nonce = _read_exact(source, NONCE_SIZE)
            ciphertext = _read_exact(
                source, ciphertext_size
            )

            source_read_time += time.perf_counter() - stage

            if (
                len(nonce) != NONCE_SIZE
                or len(ciphertext) != ciphertext_size
            ):
                raise SecureStreamError(
                    "Truncated encrypted chunk."
                )

            aad = _aad(
                document_id,
                index,
                plaintext_size,
                digest,
            )

            # Authenticate and decrypt.
            stage = time.perf_counter()

            try:
                plaintext = aes.decrypt(
                    nonce,
                    ciphertext,
                    aad,
                )
            except InvalidTag as exc:
                raise SecureStreamError(
                    f"Authentication failed for chunk {index}."
                ) from exc

            aes_decrypt_time += time.perf_counter() - stage

            if len(plaintext) != expected_plain:
                raise SecureStreamError(
                    "Invalid plaintext chunk size."
                )

            # Update the final plaintext digest.
            stage = time.perf_counter()

            calculated_hash.update(plaintext)

            hash_time += time.perf_counter() - stage

            processed_bytes += len(plaintext)
            remaining -= len(plaintext)
            index += 1
            chunks += 1

            # The chunk is yielded only after AES-GCM authentication.
            yield plaintext

        if remaining != 0:
            raise SecureStreamError(
                "Document size is inconsistent."
            )

        # Ensure there are no unexpected trailing bytes.
        stage = time.perf_counter()
        extra_data = source.read(1)
        source_read_time += time.perf_counter() - stage

        if extra_data:
            raise SecureStreamError(
                "Unexpected trailing encrypted data."
            )

        # Verify the complete plaintext SHA-256 digest.
        stage = time.perf_counter()

        if calculated_hash.hexdigest() != expected_sha256:
            raise SecureStreamError(
                "Final plaintext checksum mismatch."
            )

        integrity_time = time.perf_counter() - stage

    except GeneratorExit:
        status = "CANCELLED"
        raise

    except Exception:
        status = "FAILED"
        raise

    finally:
        total_elapsed = time.perf_counter() - total_started

        _logger.info(
            "AES_GCM_DECRYPTION_PERFORMANCE "
            "status=%s object=%s plaintext_bytes=%s chunks=%s "
            "source_read=%.4fs aes_decrypt=%.4fs "
            "hash_update=%.4fs integrity_check=%.4fs "
            "total=%.4fs",
            status,
            document_id,
            processed_bytes,
            chunks,
            source_read_time,
            aes_decrypt_time,
            hash_time,
            integrity_time,
            total_elapsed,
        )
