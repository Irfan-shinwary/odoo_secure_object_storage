"""HTTP-level tests for secure native Odoo attachment upload/download."""

import io
import os
from unittest.mock import patch

from odoo import http
from odoo.tests import HttpCase, tagged

from odoo.addons.odoo_secure_object_storage.services import (
    key_provider,
    object_storage,
    streaming_file,
)


class FakeMinioResponse:
    def __init__(self, payload, metadata):
        self._stream = io.BytesIO(payload)
        self.headers = {
            "x-amz-meta-" + str(key).lower(): str(value)
            for key, value in (metadata or {}).items()
        }
        self.closed = False
        self.released = False

    def read(self, size=-1):
        return self._stream.read(size)

    def close(self):
        self.closed = True
        self._stream.close()

    def release_conn(self):
        self.released = True


class FakeMinio:
    """Small in-memory MinIO double that consumes the supplied stream."""

    def __init__(self):
        self.objects = {}
        self.metadata = {}
        self.download_responses = []

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
        payload = bytearray()
        remaining = length
        while remaining:
            chunk = data.read(min(10 * 1024 * 1024, remaining))
            if not chunk:
                raise AssertionError("Encrypted upload ended before its declared length.")
            payload.extend(chunk)
            remaining -= len(chunk)
        self.objects[object_name] = bytes(payload)
        self.metadata[object_name] = dict(metadata or {})

    def get_object(self, bucket, object_name):
        response = FakeMinioResponse(
            self.objects[object_name],
            self.metadata.get(object_name),
        )
        self.download_responses.append(response)
        return response

    def remove_object(self, bucket, object_name):
        self.objects.pop(object_name, None)
        self.metadata.pop(object_name, None)


@tagged("-at_install", "post_install")
class TestSecureAttachmentHTTP(HttpCase):
    """Exercise the real Odoo HTTP routes with secure storage enabled."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bucket = "test-secure-attachment-http"
        cls.fake_minio = FakeMinio()
        cls.wrapped_keys = {}

        cls._patchers = [
            patch.object(
                key_provider,
                "wrap_data_key",
                side_effect=lambda key: cls._wrap_key(key),
            ),
            patch.object(
                key_provider,
                "unwrap_data_key",
                side_effect=lambda wrapped: cls.wrapped_keys[wrapped],
            ),
            patch.object(
                object_storage,
                "_client",
                return_value=cls.fake_minio,
            ),
            patch.object(
                object_storage,
                "_bucket",
                return_value=cls.bucket,
            ),
            patch(
                "odoo.addons.odoo_secure_object_storage.models.ir_attachment._client",
                return_value=(cls.fake_minio, cls.bucket),
            ),
            patch(
                "odoo.addons.odoo_secure_object_storage.models.ir_attachment._storage_enabled",
                return_value=True,
            ),
            patch(
                "odoo.addons.odoo_secure_object_storage.controllers.binary._secure_storage_enabled",
                return_value=True,
            ),
            patch.dict(
                os.environ,
                {"ODOO_SECURE_MINIO_BUCKET": cls.bucket},
            ),
        ]
        for patcher in cls._patchers:
            patcher.start()
            cls.addClassCleanup(patcher.stop)

    @classmethod
    def _wrap_key(cls, key):
        import base64

        wrapped = "http-test-vault:" + base64.b64encode(key).decode("ascii")
        cls.wrapped_keys[wrapped] = bytes(key)
        return wrapped

    def setUp(self):
        super().setUp()
        self.authenticate("admin", "admin")

    def test_native_http_upload_uses_secure_streaming_storage(self):
        payload = (b"secure-http-upload-" * 8192) + b"end"
        partner = self.env.user.partner_id

        response = self.url_open(
            "/web/binary/upload_attachment",
            data={
                "csrf_token": http.Request.csrf_token(self),
                "model": "res.partner",
                "id": str(partner.id),
            },
            files={
                "ufile": (
                    "http-streamed-upload.txt",
                    payload,
                    "text/plain",
                ),
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(len(result), 1)
        self.assertNotIn("error", result[0], result[0])

        attachment = self.env["ir.attachment"].sudo().browse(result[0]["id"])
        self.assertTrue(attachment.exists())
        self.assertEqual(attachment.file_size, len(payload))
        self.assertTrue(attachment.store_fname.startswith("secure-minio://"))

        object_key = attachment.store_fname.rsplit("/", 1)[-1]
        self.assertIn(object_key, self.fake_minio.objects)
        self.assertNotIn(
            payload,
            self.fake_minio.objects[object_key],
            "Plaintext must not be stored in the MinIO object.",
        )

    def test_native_http_download_returns_verified_content_and_closes_minio(self):
        payload = (b"secure-http-download-" * 4096) + b"end"
        attachment = self.env["ir.attachment"]._create_secure_attachment_from_stream(
            filename="http-streamed-download.bin",
            source=io.BytesIO(payload),
            mimetype="application/octet-stream",
        )
        self.assertTrue(attachment.store_fname.startswith("secure-minio://"))

        created_paths = []
        real_decrypt = streaming_file.decrypt_attachment_to_tempfile

        def capture_tempfile(*args, **kwargs):
            result = real_decrypt(*args, **kwargs)
            created_paths.append(result[0])
            return result

        with patch.object(
            streaming_file,
            "decrypt_attachment_to_tempfile",
            side_effect=capture_tempfile,
        ):
            response = self.url_open(
                "/web/content/%s?download=true" % attachment.id,
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, payload)
        self.assertTrue(created_paths, "The secure download path was not invoked.")
        self.assertFalse(
            os.path.exists(created_paths[0]),
            "The temporary plaintext file must be removed when the HTTP response closes.",
        )
        self.assertTrue(self.fake_minio.download_responses)
        minio_response = self.fake_minio.download_responses[-1]
        self.assertTrue(minio_response.closed)
        self.assertTrue(minio_response.released)
