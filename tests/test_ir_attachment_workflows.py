
import base64
import io
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from odoo.tests.common import TransactionCase


class FakeObject:
    def __init__(self, data):
        self.stream = io.BytesIO(data)

    def read(self, size=-1):
        return self.stream.read(size)

    def close(self):
        self.stream.close()

    def release_conn(self):
        pass


class FakeObjectInfo:
    def __init__(self, name, metadata, data):
        self.object_name = name
        self.metadata = metadata
        self.size = len(data)
        self.last_modified = datetime.now(timezone.utc)


class FakeMinio:
    def __init__(self):
        self.objects = {}
        self.metadata = {}

    def bucket_exists(self, bucket):
        return True

    def fput_object(
        self, bucket, object_name, file_path,
        content_type=None, metadata=None,
    ):
        with open(file_path, "rb") as source:
            self.objects[object_name] = source.read()
        self.metadata[object_name] = {
            "x-amz-meta-" + key.lower(): value
            for key, value in (metadata or {}).items()
        }

    def get_object(self, bucket, object_name):
        return FakeObject(self.objects[object_name])

    def remove_object(self, bucket, object_name):
        self.objects.pop(object_name, None)
        self.metadata.pop(object_name, None)

    def stat_object(self, bucket, object_name):
        return FakeObjectInfo(
            object_name,
            self.metadata[object_name],
            self.objects[object_name],
        )

    def list_objects(self, bucket, recursive=True):
        class Listed:
            def __init__(self, name):
                self.object_name = name
                self.last_modified = datetime.now(timezone.utc)

        return [Listed(name) for name in self.objects]


class TestSecureAttachmentWorkflows(TransactionCase):

    def setUp(self):
        super().setUp()

        self.master_key = os.urandom(32)
        self.fake_minio = FakeMinio()
        self.bucket = "test-secure-attachments"

        module_path = (
            "odoo.addons.odoo_secure_object_storage.models.ir_attachment"
        )

        self.config_patch = patch(
            f"{module_path}._get_config",
            return_value=(
                "127.0.0.1:9000",
                "test-access",
                "test-secret",
                self.bucket,
                False,
                self.master_key,
            ),
        )
        self.client_patch = patch(
            f"{module_path}._client",
            return_value=(self.fake_minio, self.bucket),
        )
        self.enabled_patch = patch(
            f"{module_path}._storage_enabled",
            return_value=True,
        )

        self.config_patch.start()
        self.client_patch.start()
        self.enabled_patch.start()

        self.addCleanup(self.config_patch.stop)
        self.addCleanup(self.client_patch.stop)
        self.addCleanup(self.enabled_patch.stop)

#     def setUp(self):
#         super().setUp()
#         self.master_key = os.urandom(32)
#         self.fake_minio = FakeMinio()
#         self.bucket = "test-secure-attachments"
#
#         self.config_patch = patch(
#             "odoo_secure_object_storage.models.ir_attachment._get_config""odoo.addons.odoo_secure_object_storage.models.ir_attachment._get_config"
# ,
#             return_value=(
#                 "127.0.0.1:9000",
#                 "test-access",
#                 "test-secret",
#                 self.bucket,
#                 False,
#                 self.master_key,
#             ),
#         )
#         self.client_patch = patch(
#             "odoo.addons.odoo_secure_object_storage.models.ir_attachment._client"
# ,
#             return_value=(self.fake_minio, self.bucket),
#         )
#         self.enabled_patch = patch(
#             "odoo.addons.odoo_secure_object_storage.models.ir_attachment._storage_enabled",
#             return_value=True,
#         )
#
#         self.config_patch.start()
#         self.client_patch.start()
#         self.enabled_patch.start()
#
#         self.addCleanup(self.config_patch.stop)
#         self.addCleanup(self.client_patch.stop)
#         self.addCleanup(self.enabled_patch.stop)

    def _create_attachment(self, content, name="integration-test.txt"):
        return self.env["ir.attachment"].create({
            "name": name,
            "type": "binary",
            "mimetype": "text/plain",
            "datas": base64.b64encode(content),
        })

    def test_create_and_read_attachment(self):
        original = b"Secure attachment integration test."
        attachment = self._create_attachment(original)

        self.assertTrue(attachment.store_fname.startswith("secure-minio://"))

        object_name = attachment.store_fname.rsplit("/", 1)[-1]
        encrypted = self.fake_minio.objects[object_name]

        self.assertTrue(encrypted.startswith(b"ODOOENC2"))
        self.assertNotIn(original, encrypted)
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

    def test_empty_attachment(self):
        attachment = self._create_attachment(b"", "empty.txt")

        self.assertEqual(base64.b64decode(attachment.datas), b"")
        self.assertFalse(
            attachment.store_fname,
            "Odoo normally does not create a storage object for empty content.",
        )
    # def test_empty_attachment(self):
    #     attachment = self._create_attachment(b"", "empty.txt")
    #
    #     self.assertEqual(base64.b64decode(attachment.datas), b"")
    #
    #     object_name = attachment.store_fname.rsplit("/", 1)[-1]
    #     self.assertGreater(len(self.fake_minio.objects[object_name]), 28)

    def test_large_attachment(self):
        original = os.urandom(5 * 1024 * 1024 + 123)
        attachment = self._create_attachment(original, "large.bin")

        self.assertEqual(
            base64.b64decode(attachment.datas),
            original,
        )
