import base64
import io
import os
import unittest
from unittest.mock import patch

from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase


class FakeObject:
    """MinIO GET response substitute, including S3 user metadata headers."""

    def __init__(self, data, metadata):
        self.stream = io.BytesIO(data)
        self.headers = {
            "x-amz-meta-" + key.lower(): value
            for key, value in metadata.items()
        }

    def read(self, size=-1):
        return self.stream.read(size)

    def close(self):
        self.stream.close()

    def release_conn(self):
        pass


class FakeAttachmentObjectStorage:
    """In-memory object store used to isolate workflow tests from MinIO."""

    def __init__(self):
        self.objects = {}
        self.metadata = {}

    def put_encrypted_stream(
        self,
        stream,
        plaintext_size,
        chunk_size,
        object_name=None,
        metadata=None,
    ):
        chunks = []
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)

        object_name = object_name or os.urandom(16).hex()
        self.objects[object_name] = b"".join(chunks)
        self.metadata[object_name] = dict(metadata or {})
        return object_name

    def get_object(self, object_name):
        return FakeObject(
            self.objects[object_name],
            self.metadata[object_name],
        )

    def remove_object(self, object_name):
        self.objects.pop(object_name, None)
        self.metadata.pop(object_name, None)


class TestSecureAttachmentWorkflows(TransactionCase):

    def setUp(self):
        super().setUp()

        self.bucket = "test-secure-attachments"
        self.fake_storage = FakeAttachmentObjectStorage()
        self.module_path = (
            "odoo.addons.odoo_secure_object_storage.models.ir_attachment"
        )
        self.storage_path = (
            "odoo.addons.odoo_secure_object_storage.services.object_storage"
        )
        self.key_provider_path = (
            "odoo.addons.odoo_secure_object_storage.services.key_provider"
        )

        self.generated_keys = {}

        def generate_data_key():
            key = os.urandom(32)
            return key, None

        def wrap_data_key(key):
            wrapped = base64.b64encode(key).decode("ascii")
            self.generated_keys[wrapped] = key
            return wrapped

        def unwrap_data_key(wrapped):
            if wrapped not in self.generated_keys:
                raise ValueError("Unknown test wrapped key")
            return self.generated_keys[wrapped]

        patches = [
            patch(f"{self.module_path}._storage_enabled", return_value=True),
            patch(
                f"{self.storage_path}.put_encrypted_stream",
                side_effect=self.fake_storage.put_encrypted_stream,
            ),
            patch(
                f"{self.storage_path}.get_object",
                side_effect=self.fake_storage.get_object,
            ),
            patch(
                f"{self.storage_path}.remove_object",
                side_effect=self.fake_storage.remove_object,
            ),
            patch(
                f"{self.key_provider_path}.generate_data_key",
                side_effect=generate_data_key,
            ),
            patch(
                f"{self.key_provider_path}.wrap_data_key",
                side_effect=wrap_data_key,
            ),
            patch(
                f"{self.key_provider_path}.unwrap_data_key",
                side_effect=unwrap_data_key,
            ),
        ]

        for mocked in patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def _create_attachment(self, content, name="integration-test.txt"):
        return self.env["ir.attachment"].create({
            "name": name,
            "type": "binary",
            "mimetype": "text/plain",
            "datas": base64.b64encode(content),
        })

    def _stored_object(self, attachment):
        self.assertTrue(attachment.store_fname.startswith("secure-minio://"))
        return attachment.store_fname.rsplit("/", 1)[-1]

    def test_create_and_read_vault_wrapped_attachment(self):
        original = b"Secure attachment integration test."
        attachment = self._create_attachment(original)

        object_name = self._stored_object(attachment)
        encrypted = self.fake_storage.objects[object_name]
        metadata = self.fake_storage.metadata[object_name]

        self.assertTrue(encrypted.startswith(b"ODSDOC01"))
        self.assertNotIn(original, encrypted)
        self.assertEqual(
            metadata["storage-format"],
            "odoo-vault-aesgcm-stream-v1",
        )
        self.assertTrue(metadata.get("wrapped-key"))
        self.assertEqual(
            metadata["plaintext-size"],
            str(len(original)),
        )
        self.assertEqual(
            base64.b64decode(attachment.datas),
            original,
        )

    def test_update_attachment_content(self):
        original = b"Original content"
        replacement = b"Updated attachment content"

        attachment = self._create_attachment(original)
        attachment.datas = base64.b64encode(replacement)

        self.assertEqual(
            base64.b64decode(attachment.datas),
            replacement,
        )

        current_object = self._stored_object(attachment)
        self.assertIn(current_object, self.fake_storage.objects)

    def test_empty_attachment(self):
        attachment = self._create_attachment(b"", "empty.txt")

        self.assertEqual(base64.b64decode(attachment.datas), b"")
        self.assertFalse(
            attachment.store_fname,
            "Odoo normally stores empty attachment content in the database.",
        )

    def test_large_attachment_crosses_encryption_chunk_boundary(self):
        original = os.urandom(4 * 1024 * 1024 + 123)
        attachment = self._create_attachment(original, "large.bin")

        object_name = self._stored_object(attachment)
        self.assertTrue(
            self.fake_storage.objects[object_name].startswith(b"ODSDOC01")
        )
        self.assertEqual(base64.b64decode(attachment.datas), original)

    def test_tampered_ciphertext_is_rejected(self):
        attachment = self._create_attachment(b"tamper detection test")
        object_name = self._stored_object(attachment)

        damaged = bytearray(self.fake_storage.objects[object_name])
        damaged[-1] ^= 1
        self.fake_storage.objects[object_name] = bytes(damaged)

        with self.assertRaises(UserError):
            _ = attachment.datas

    def test_missing_wrapped_key_is_rejected(self):
        attachment = self._create_attachment(b"wrapped key metadata test")
        object_name = self._stored_object(attachment)
        self.fake_storage.metadata[object_name].pop("wrapped-key")

        with self.assertRaises(UserError):
            _ = attachment.datas
