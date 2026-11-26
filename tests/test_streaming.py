
import hashlib
import io
import os
from odoo.tests.common import TransactionCase

from ..services.streaming_encryption import (
    SecureStreamError,
    decrypt_stream,
    encrypt_stream,
)


def encrypted_bytes(data, key, document_id):
    digest = hashlib.sha256(data).hexdigest()
    stream = encrypt_stream(
        io.BytesIO(data),
        key,
        document_id,
        len(data),
        digest,
    )
    return b"".join(stream), digest


class TestStreamingEncryption(TransactionCase):

    def test_round_trip(self):
        data = os.urandom(9 * 1024 * 1024 + 137)
        key = os.urandom(32)
        document_id = "document-123"
        encrypted, digest = encrypted_bytes(data, key, document_id)

        result = b"".join(decrypt_stream(
            io.BytesIO(encrypted),
            key,
            document_id,
            len(data),
            digest,
        ))
        self.assertEqual(result, data)

    def test_empty_document(self):
        data = b""
        key = os.urandom(32)
        document_id = "empty-document"
        encrypted, digest = encrypted_bytes(data, key, document_id)

        result = b"".join(decrypt_stream(
            io.BytesIO(encrypted), key, document_id, 0, digest
        ))
        self.assertEqual(result, b"")

    def test_tampering_is_rejected(self):
        data = b"confidential patient document" * 100
        key = os.urandom(32)
        encrypted, digest = encrypted_bytes(data, key, "doc-1")

        damaged = bytearray(encrypted)
        damaged[-1] ^= 1

        with self.assertRaises(SecureStreamError):
            b"".join(decrypt_stream(
                io.BytesIO(damaged), key, "doc-1", len(data), digest
            ))

    def test_wrong_document_id_is_rejected(self):
        data = b"patient data"
        key = os.urandom(32)
        encrypted, digest = encrypted_bytes(data, key, "doc-A")

        with self.assertRaises(SecureStreamError):
            b"".join(decrypt_stream(
                io.BytesIO(encrypted), key, "doc-B", len(data), digest
            ))

    def test_truncated_stream_is_rejected(self):
        data = os.urandom(1024)
        key = os.urandom(32)
        encrypted, digest = encrypted_bytes(data, key, "doc-truncated")

        with self.assertRaises(SecureStreamError):
            b"".join(decrypt_stream(
                io.BytesIO(encrypted[:-5]),
                key,
                "doc-truncated",
                len(data),
                digest,
            ))


if __name__ == "__main__":
    unittest.main()
