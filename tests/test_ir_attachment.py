
import base64
import io
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models.ir_attachment import (
    _CHUNK_SIZE,
    _MAGIC_V1,
    _MAGIC_V2,
    _derive_v1_key,
    _decrypt_stream_to_base64,
    _encrypt_base64_to_file,
    _make_header,
    _nonce,
)


class TestSecureAttachmentEncryption(unittest.TestCase):

    def setUp(self):
        self.master_key = os.urandom(32)
        self.object_key = "0123456789abcdef0123456789abcdef"

    def encrypt_and_decrypt(self, plaintext):
        encoded = base64.b64encode(plaintext)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "encrypted.bin")

            size = _encrypt_base64_to_file(
                encoded,
                self.object_key,
                self.master_key,
                path,
            )

            with open(path, "rb") as encrypted_file:
                encrypted = encrypted_file.read()

        self.assertEqual(size, len(plaintext))

        decrypted_base64 = _decrypt_stream_to_base64(
            io.BytesIO(encrypted),
            self.object_key,
            self.master_key,
        )

        return base64.b64decode(decrypted_base64, validate=True), encrypted

    def test_empty_attachment_round_trip(self):
        decrypted, encrypted = self.encrypt_and_decrypt(b"")

        self.assertEqual(decrypted, b"")
        self.assertEqual(encrypted[:8], _MAGIC_V2)
        # Even an empty attachment must contain an authenticated GCM tag.
        self.assertGreater(len(encrypted), 28)

    def test_small_attachment_round_trip(self):
        original = b"Confidential attachment content."
        decrypted, encrypted = self.encrypt_and_decrypt(original)

        self.assertEqual(decrypted, original)
        self.assertEqual(encrypted[:8], _MAGIC_V2)

    def test_multichunk_attachment_round_trip(self):
        original = os.urandom(_CHUNK_SIZE * 2 + 317)
        decrypted, _encrypted = self.encrypt_and_decrypt(original)

        self.assertEqual(decrypted, original)

    def test_tampered_v2_header_is_rejected(self):
        original = b"Confidential attachment."
        _decrypted, encrypted = self.encrypt_and_decrypt(original)

        tampered = bytearray(encrypted)
        tampered[8] ^= 1  # Modify the nonce prefix in the header.

        with self.assertRaises(Exception):
            _decrypt_stream_to_base64(
                io.BytesIO(tampered),
                self.object_key,
                self.master_key,
            )

    def test_tampered_ciphertext_is_rejected(self):
        original = b"Confidential attachment."
        _decrypted, encrypted = self.encrypt_and_decrypt(original)

        tampered = bytearray(encrypted)
        tampered[-1] ^= 1

        with self.assertRaises(Exception):
            _decrypt_stream_to_base64(
                io.BytesIO(tampered),
                self.object_key,
                self.master_key,
            )

    def test_wrong_object_key_is_rejected(self):
        original = b"Attachment bound to its object key."
        _decrypted, encrypted = self.encrypt_and_decrypt(original)

        wrong_key = "abcdef0123456789abcdef0123456789"

        with self.assertRaises(Exception):
            _decrypt_stream_to_base64(
                io.BytesIO(encrypted),
                wrong_key,
                self.master_key,
            )

    def test_invalid_base64_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "encrypted.bin")

            with self.assertRaises(ValueError):
                _encrypt_base64_to_file(
                    b"AAAA!!!!",
                    self.object_key,
                    self.master_key,
                    path,
                )

    def test_v1_attachment_remains_readable(self):
        # Construct a legacy version-1 object using the original format.
        original = b"Existing encrypted attachment from version one."
        nonce_prefix = os.urandom(8)

        header = (
            _MAGIC_V1
            + nonce_prefix
            + _CHUNK_SIZE.to_bytes(4, "big")
            + len(original).to_bytes(8, "big")
        )

        aes = AESGCM(_derive_v1_key(self.master_key, self.object_key))
        aad = self.object_key.encode("ascii") + (0).to_bytes(4, "big")
        encrypted_chunk = aes.encrypt(
            _nonce(nonce_prefix, 0),
            original,
            aad,
        )

        encrypted_object = header + encrypted_chunk

        decrypted_base64 = _decrypt_stream_to_base64(
            io.BytesIO(encrypted_object),
            self.object_key,
            self.master_key,
        )

        self.assertEqual(
            base64.b64decode(decrypted_base64, validate=True),
            original,
        )


if __name__ == "__main__":
    unittest.main()
