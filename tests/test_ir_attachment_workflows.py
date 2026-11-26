
import base64
import io
import os
from unittest.mock import patch

from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase

from odoo.addons.odoo_secure_object_storage.services import (
    key_provider,
    object_storage,
    streaming_encryption,
)


class FakeObject:
    """In-memory response object compatible with MinIO get_object()."""

    def __init__(self, data, metadata=None):
        self.stream = io.BytesIO(data)
        self.headers = {
            "x-amz-meta-" + key.lower(): str(value)
            for key, value in (metadata or {}).items()
        }

    def read(self, size=-1):
        return self.stream.read(size)

    def close(self):
        self.stream.close()

    def release_conn(self):
        pass


class FakeObjectInfo:
    """Minimal MinIO stat_object() response."""

    def __init__(self, name, metadata, data):
        self.object_name = name
        self.metadata = metadata
        self.size = len(data)


class FakeMinio:
    """In-memory MinIO implementation for attachment workflow tests."""

    def __init__(self):
        self.objects = {}
        self.metadata = {}

    def bucket_exists(self, bucket):
        return True

    def put_object(
        self,
        bucket,
        object_name,
        data,
        length,
        part_size=None,
        content_type=None,
        metadata=None,
    ):
        """Consume the encrypted stream exactly as a MinIO upload would."""

        if length < 0:
            raise ValueError("Invalid object length.")

        content = bytearray()
        remaining = length

        while remaining > 0:
            chunk = data.read(min(1024 * 1024, remaining))

            if not chunk:
                raise ValueError(
                    "Encrypted stream ended before the expected length."
                )

            content.extend(chunk)
            remaining -= len(chunk)

        if len(content) != length:
            raise ValueError("Uploaded object length does not match.")

        self.objects[object_name] = bytes(content)
        self.metadata[object_name] = dict(metadata or {})

    def get_object(self, bucket, object_name):
        if object_name not in self.objects:
            raise FileNotFoundError(object_name)

        return FakeObject(
            self.objects[object_name],
            self.metadata.get(object_name),
        )

    def remove_object(self, bucket, object_name):
        self.objects.pop(object_name, None)
        self.metadata.pop(object_name, None)

    def stat_object(self, bucket, object_name):
        data = self.objects[object_name]

        metadata = {
            "x-amz-meta-" + key.lower(): str(value)
            for key, value in self.metadata.get(object_name, {}).items()
        }

        return FakeObjectInfo(object_name, metadata, data)

    def list_objects(self, bucket, recursive=True):
        class Listed:
            def __init__(self, name):
                self.object_name = name
                self.last_modified = None

        return [
            Listed(name)
            for name in self.objects
        ]


class TestSecureAttachmentWorkflows(TransactionCase):

    def setUp(self):
        super().setUp()

        self.fake_minio = FakeMinio()
        self.bucket = "test-secure-attachments"

        # Keep the generated DEKs real, but simulate Vault Transit.
        self.wrapped_keys = {}

        # Odoo attachment model module.
        self.attachment_module = (
            "odoo.addons.odoo_secure_object_storage.models.ir_attachment"
        )

        # Mock the Vault key-wrapping operations.
        self.wrap_patch = patch.object(
            key_provider,
            "wrap_data_key",
            side_effect=self._fake_wrap_data_key,
        )

        self.unwrap_patch = patch.object(
            key_provider,
            "unwrap_data_key",
            side_effect=self._fake_unwrap_data_key,
        )

        # Mock the MinIO client used by the object-storage service.
        self.storage_client_patch = patch.object(
            object_storage,
            "_client",
            return_value=self.fake_minio,
        )

        self.storage_bucket_patch = patch.object(
            object_storage,
            "_bucket",
            return_value=self.bucket,
        )

        # The legacy deletion method in ir_attachment.py still uses
        # its own direct MinIO client.
        self.attachment_client_patch = patch(
            f"{self.attachment_module}._client",
            return_value=(self.fake_minio, self.bucket),
        )

        # Enable secure storage for these tests.
        self.enabled_patch = patch(
            f"{self.attachment_module}._storage_enabled",
            return_value=True,
        )

        # _file_write() and _file_read() use this environment variable
        # to construct and resolve secure-minio:// references.
        self.environment_patch = patch.dict(
            os.environ,
            {
                "ODOO_SECURE_MINIO_BUCKET": self.bucket,
            },
        )

        patches = [
            self.wrap_patch,
            self.unwrap_patch,
            self.storage_client_patch,
            self.storage_bucket_patch,
            self.attachment_client_patch,
            self.enabled_patch,
            self.environment_patch,
        ]

        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)

    def _fake_wrap_data_key(self, key):
        """Simulate Vault wrapping while retaining the real AES key."""

        wrapped_key = (
            "test-vault:"
            + base64.b64encode(key).decode("ascii")
        )

        self.wrapped_keys[wrapped_key] = bytes(key)

        return wrapped_key

    def _fake_unwrap_data_key(self, wrapped_key):
        """Simulate Vault unwrapping."""

        if wrapped_key not in self.wrapped_keys:
            raise ValueError("Unknown test-wrapped data key.")

        return self.wrapped_keys[wrapped_key]

    def _create_attachment(
        self,
        content,
        name="integration-test.txt",
    ):
        return self.env["ir.attachment"].create({
            "name": name,
            "type": "binary",
            "mimetype": "text/plain",
            "datas": base64.b64encode(content),
        })

    def _read_attachment_content(self, attachment):
        """Invalidate ORM cache so assertions exercise MinIO decryption."""
        attachment.invalidate_recordset(["datas"])
        return base64.b64decode(attachment.datas)

    def test_create_and_read_attachment(self):
        original = b"Secure attachment integration test."

        attachment = self._create_attachment(original)

        # Verify the secure object reference.
        self.assertTrue(
            attachment.store_fname.startswith("secure-minio://")
        )

        object_name = attachment.store_fname.rsplit("/", 1)[-1]

        # Verify that the encrypted object was uploaded.
        self.assertIn(object_name, self.fake_minio.objects)

        encrypted = self.fake_minio.objects[object_name]

        # Verify the current streaming encryption format.
        self.assertTrue(
            encrypted.startswith(streaming_encryption.MAGIC)
        )

        # Plaintext must not appear in the encrypted object.
        self.assertNotIn(original, encrypted)

        # Verify Vault-wrapped key metadata was stored.
        metadata = self.fake_minio.metadata[object_name]

        self.assertIn("wrapped-key", metadata)
        self.assertIn("plaintext-size", metadata)
        self.assertIn("plaintext-sha256", metadata)

        # Verify that the actual decryption pipeline returns
        # the original attachment content.
        self.assertEqual(
            self._read_attachment_content(attachment),
            original,
        )

    def test_each_attachment_gets_a_distinct_wrapped_dek(self):
        first = self._create_attachment(
            b"first confidential payload",
            "first-dek-test.txt",
        )
        second = self._create_attachment(
            b"second confidential payload",
            "second-dek-test.txt",
        )

        first_object = first.store_fname.rsplit("/", 1)[-1]
        second_object = second.store_fname.rsplit("/", 1)[-1]

        self.assertNotEqual(first_object, second_object)

        first_metadata = self.fake_minio.metadata[first_object]
        second_metadata = self.fake_minio.metadata[second_object]

        self.assertIn("wrapped-key", first_metadata)
        self.assertIn("wrapped-key", second_metadata)
        self.assertNotEqual(
            first_metadata["wrapped-key"],
            second_metadata["wrapped-key"],
            "Each attachment must receive an independently wrapped DEK.",
        )

    def test_update_attachment_content(self):
        original = b"Original content"
        replacement = b"Updated attachment content"

        attachment = self._create_attachment(original)

        old_reference = attachment.store_fname

        attachment.write({
            "datas": base64.b64encode(replacement),
        })

        self.assertEqual(
            self._read_attachment_content(attachment),
            replacement,
        )

        self.assertNotEqual(
            attachment.store_fname,
            old_reference,
        )

        self.assertTrue(
            attachment.store_fname.startswith("secure-minio://")
        )

    def test_empty_attachment(self):
        attachment = self._create_attachment(
            b"",
            "empty.txt",
        )

        self.assertEqual(
            self._read_attachment_content(attachment),
            b"",
        )

        self.assertFalse(
            attachment.store_fname,
            "Odoo normally does not create a storage object for empty content.",
        )

        self.assertEqual(
            len(self.fake_minio.objects),
            0,
        )

    def test_large_attachment(self):
        original = os.urandom(5 * 1024 * 1024 + 123)

        attachment = self._create_attachment(
            original,
            "large.bin",
        )

        self.assertTrue(
            attachment.store_fname.startswith("secure-minio://")
        )

        object_name = attachment.store_fname.rsplit("/", 1)[-1]

        encrypted = self.fake_minio.objects[object_name]

        self.assertTrue(
            encrypted.startswith(streaming_encryption.MAGIC)
        )

        # The content is larger than one 4 MiB encryption chunk.
        self.assertGreater(
            len(original),
            streaming_encryption.CHUNK_SIZE,
        )

        # Confirm complete multi-chunk decryption.
        self.assertEqual(
            self._read_attachment_content(attachment),
            original,
        )

    def test_ciphertext_tampering_is_rejected(self):
        """Verify AES-GCM rejects modified encrypted attachment data."""

        original = b"Confidential document that must remain protected."

        # 1. Create a normal encrypted attachment.
        attachment = self._create_attachment(
            original,
            "tampered-document.txt",
        )

        self.assertTrue(
            attachment.store_fname.startswith("secure-minio://")
        )

        object_name = attachment.store_fname.rsplit("/", 1)[-1]

        # 2. Retrieve the encrypted object from fake MinIO.
        encrypted = bytearray(
            self.fake_minio.objects[object_name]
        )

        self.assertTrue(
            encrypted.startswith(streaming_encryption.MAGIC)
        )

        # 3. Calculate the beginning of the first ciphertext.
        #
        # ODSDOC01 layout:
        #   Header:              52 bytes
        #   Encrypted length:     4 bytes
        #   Nonce:               12 bytes
        #   Ciphertext:          plaintext + 16-byte GCM tag
        #
        ciphertext_offset = (
                streaming_encryption.HEADER_SIZE
                + streaming_encryption.LENGTH_SIZE
                + streaming_encryption.NONCE_SIZE
        )

        self.assertLess(
            ciphertext_offset,
            len(encrypted),
        )

        # 4. Modify one byte inside the ciphertext.
        encrypted[ciphertext_offset] ^= 0x01

        # 5. Save the modified object without changing its metadata.
        self.fake_minio.objects[object_name] = bytes(encrypted)

        # 6. Invalidate the cached attachment data.
        # This forces Odoo to retrieve and decrypt the object again.
        attachment.invalidate_recordset(["datas"])

        # 7. Reading the attachment must fail authentication.
        with self.assertRaises(UserError):
            _ = attachment.datas

    def test_invalid_wrapped_dek_is_rejected(self):
        original = b"Testing invalid wrapped DEK rejection."
        attachment = self._create_attachment(
            original,
            "invalid-wrapped-key.txt",
        )

        object_name = attachment.store_fname.rsplit("/", 1)[-1]

        # Confirm the wrapped DEK exists in the stored object metadata.
        metadata = self.fake_minio.metadata[object_name]

        self.assertIn(
            "wrapped-key",
            metadata,
            "The encrypted object does not contain a wrapped DEK.",
        )

        # Replace the valid wrapped DEK with an invalid value.
        metadata["wrapped-key"] = "INVALID_WRAPPED_DATA_ENCRYPTION_KEY"

        # Force Odoo to retrieve the attachment again from MinIO.
        attachment.invalidate_recordset(["datas"])

        # Reading must fail because the DEK cannot be unwrapped.
        with self.assertRaises(UserError):
            _ = attachment.datas

    def test_vault_unavailable_is_rejected(self):
        original = b"Testing attachment retrieval when Vault is unavailable."

        # Upload while the fake Vault is working normally.
        attachment = self._create_attachment(
            original,
            "vault-unavailable.txt",
        )

        # Confirm that the attachment was uploaded.
        object_name = attachment.store_fname.rsplit("/", 1)[-1]
        self.assertIn(object_name, self.fake_minio.objects)

        # Simulate Vault becoming unavailable during retrieval.
        with patch.object(
                key_provider,
                "unwrap_data_key",
                side_effect=ConnectionError("Vault service is unavailable."),
        ):
            # Force Odoo to retrieve the attachment from MinIO.
            attachment.invalidate_recordset(["datas"])

            # The attachment must not be returned without its DEK.
            with self.assertRaises(UserError):
                _ = attachment.datas

    def test_minio_unavailable_is_rejected(self):
        original = b"Testing attachment retrieval when MinIO is unavailable."

        attachment = self._create_attachment(
            original,
            "minio-unavailable.txt",
        )

        object_name = attachment.store_fname.rsplit("/", 1)[-1]

        self.assertIn(
            object_name,
            self.fake_minio.objects,
            "The encrypted object was not uploaded to fake MinIO.",
        )

        with patch.object(
                object_storage,
                "get_object",
                side_effect=ConnectionError("MinIO service is unavailable."),
        ):
            attachment.invalidate_recordset(["datas"])

            with self.assertRaises(UserError):
                _ = attachment.datas


    def test_secure_object_is_cleaned_up_on_transaction_rollback(self):
        original = b"Testing secure object rollback cleanup."

        postrollback = self.env.cr.postrollback
        callbacks_class = type(postrollback)

        with patch.object(
                callbacks_class,
                "add",
                autospec=True,
        ) as mock_add:
            attachment = self._create_attachment(
                original,
                "rollback-cleanup-test.txt",
            )

        mock_add.assert_called_once()
        registered_callback = mock_add.call_args[0][1]

        self.assertTrue(callable(registered_callback))

        object_key = attachment.store_fname.rsplit("/", 1)[-1]
        self.assertIn(
            object_key,
            self.fake_minio.objects,
            "The uploaded object should exist before rollback cleanup.",
        )

        registered_callback()

        self.assertNotIn(
            object_key,
            self.fake_minio.objects,
            "The uploaded object was not removed by rollback cleanup.",
        )
        self.assertNotIn(
            object_key,
            self.fake_minio.metadata,
            "Object metadata was not removed by rollback cleanup.",
        )

    def test_secure_object_is_deleted_after_commit(self):
        original = b"Testing secure object deletion after database commit."

        attachment = self._create_attachment(
            original,
            "deletion-test.txt",
        )

        object_key = attachment.store_fname.rsplit("/", 1)[-1]

        # Confirm the encrypted object exists before deletion.
        self.assertIn(
            object_key,
            self.fake_minio.objects,
            "The encrypted object was not uploaded to fake MinIO.",
        )

        postcommit = self.env.cr.postcommit
        callbacks_class = type(postcommit)

        # Patch the class method because the instance method is read-only.
        with patch.object(
                callbacks_class,
                "add",
                autospec=True,
        ) as mock_add:
            self.env["ir.attachment"]._file_delete(
                attachment.store_fname
            )

        # Verify that exactly one callback was registered.
        mock_add.assert_called_once()

        # Retrieve the callback passed to postcommit.add().
        registered_callback = mock_add.call_args[0][1]

        self.assertTrue(
            callable(registered_callback),
            "The registered post-commit callback is not callable.",
        )

        # Object must still exist before the callback executes.
        self.assertIn(
            object_key,
            self.fake_minio.objects,
            "The object was deleted before transaction commit.",
        )

        # Simulate execution of the post-commit callback.
        registered_callback()

        # Verify that the object was removed.
        self.assertNotIn(
            object_key,
            self.fake_minio.objects,
            "The secure object was not deleted after commit.",
        )

        # Verify that its associated metadata was also removed.
        self.assertNotIn(
            object_key,
            self.fake_minio.metadata,
            "The secure object metadata was not deleted.",
        )