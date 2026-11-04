
import hashlib
import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    """Yield a framed encrypted stream without loading the full file."""
    if len(key) != 32:
        raise ValueError("The data-encryption key must be 32 bytes.")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("Invalid encryption chunk size.")
    if plaintext_size < 0:
        raise ValueError("Invalid plaintext size.")

    digest = bytes.fromhex(plaintext_sha256)
    if len(digest) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes.")

    yield MAGIC + struct.pack(">I", chunk_size)
    yield struct.pack(">Q", plaintext_size) + digest

    aes = AESGCM(key)
    index = 0
    remaining = plaintext_size

    # An empty document still gets an authenticated empty chunk.
    while remaining > 0 or index == 0:
        expected = min(chunk_size, remaining)
        plaintext = _read_exact(source, expected)

        if len(plaintext) != expected:
            raise SecureStreamError("Source file changed or ended unexpectedly.")

        nonce = os.urandom(NONCE_SIZE)
        aad = _aad(document_id, index, plaintext_size, digest)
        ciphertext = aes.encrypt(nonce, plaintext, aad)

        yield struct.pack(">I", len(ciphertext))
        yield nonce
        yield ciphertext

        remaining -= len(plaintext)
        index += 1

    if source.read(1):
        raise SecureStreamError("Source file grew during encryption.")


def decrypt_stream(
    source: BinaryIO,
    key: bytes,
    document_id: str,
    expected_size: int,
    expected_sha256: str,
) -> Iterator[bytes]:
    """Yield plaintext chunks only after each chunk authenticates."""
    if len(key) != 32:
        raise ValueError("The data-encryption key must be 32 bytes.")

    header = _read_exact(source, HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[:8] != MAGIC:
        raise SecureStreamError("Invalid encrypted document header.")

    chunk_size = struct.unpack(">I", header[8:12])[0]
    plaintext_size = struct.unpack(">Q", header[12:20])[0]
    digest = header[20:52]

    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise SecureStreamError("Invalid encrypted chunk size.")
    if plaintext_size != expected_size:
        raise SecureStreamError("Document size does not match metadata.")
    if digest.hex() != expected_sha256:
        raise SecureStreamError("Document digest does not match metadata.")

    aes = AESGCM(key)
    remaining = plaintext_size
    index = 0
    calculated_hash = hashlib.sha256()

    while remaining > 0 or index == 0:
        length_data = _read_exact(source, LENGTH_SIZE)
        if len(length_data) != LENGTH_SIZE:
            raise SecureStreamError("Missing encrypted chunk.")

        (ciphertext_size,) = struct.unpack(">I", length_data)
        expected_plain = min(chunk_size, remaining)

        if ciphertext_size != expected_plain + TAG_SIZE:
            raise SecureStreamError("Invalid encrypted chunk length.")

        nonce = _read_exact(source, NONCE_SIZE)
        ciphertext = _read_exact(source, ciphertext_size)

        if len(nonce) != NONCE_SIZE or len(ciphertext) != ciphertext_size:
            raise SecureStreamError("Truncated encrypted chunk.")

        aad = _aad(document_id, index, plaintext_size, digest)
        try:
            plaintext = aes.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise SecureStreamError(
                f"Authentication failed for chunk {index}."
            ) from exc

        if len(plaintext) != expected_plain:
            raise SecureStreamError("Invalid plaintext chunk size.")

        calculated_hash.update(plaintext)
        remaining -= len(plaintext)
        index += 1
        yield plaintext

    if source.read(1):
        raise SecureStreamError("Unexpected trailing encrypted data.")

    if calculated_hash.hexdigest() != expected_sha256:
        raise SecureStreamError("Final plaintext checksum mismatch.")
