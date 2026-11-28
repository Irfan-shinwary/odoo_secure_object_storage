
from odoo.exceptions import AccessError
from odoo.tests.common import TransactionCase

import io
from unittest.mock import patch

from odoo.addons.odoo_secure_object_storage.services import (
    key_provider,
    object_storage,
)


class TestSecureDocument(TransactionCase):

    def test_owner_is_set(self):
        document = self.env["secure.document"].create({
            "name": "test.txt",
            "owner_id": self.env.user.id,
            "company_id": self.env.company.id,
        })

        self.assertEqual(document.owner_id, self.env.user)
        self.assertEqual(document.state, "draft")

    def test_foreign_owner_is_denied(self):
        other_user = self.env["res.users"].create({
            "name": "Other Test User",
            "login": "other_test_user",
            "email": "other_test_user@example.com",
            "notification_type": "email",
            "groups_id": [
                (6, 0, [self.env.ref("base.group_user").id])
            ],
        })

        document = self.env["secure.document"].with_user(
            self.env.user
        ).create({
            "name": "private.txt",
            "owner_id": self.env.user.id,
            "company_id": self.env.company.id,
        })

        with self.assertRaises(AccessError):
            document.with_user(
                other_user
            )._check_document_access("read")


    def test_uploaded_object_is_removed_after_database_rollback(self):
        document = self.env["secure.document"].create({
            "name": "rollback.txt",
            "owner_id": self.env.user.id,
            "company_id": self.env.company.id,
        })

        def consume_encrypted_stream(stream, **kwargs):
            while stream.read(1024 * 1024):
                pass
            return "rollback-object"

        postrollback_class = type(self.env.cr.postrollback)

        with patch.object(
            key_provider,
            "generate_data_key",
            return_value=(b"k" * 32, None),
        ), patch.object(
            key_provider,
            "wrap_data_key",
            return_value="test-wrapped-key",
        ), patch.object(
            object_storage,
            "put_encrypted_stream",
            side_effect=consume_encrypted_stream,
        ), patch.object(
            object_storage,
            "remove_object",
        ) as remove_object, patch.object(
            postrollback_class,
            "add",
            autospec=True,
        ) as register_rollback:
            document._stream_upload(
                io.BytesIO(b"rollback secure document"),
                "rollback.txt",
                "text/plain",
            )

        register_rollback.assert_called_once()
        callback = register_rollback.call_args[0][1]
        self.assertTrue(callable(callback))
        callback()
        remove_object.assert_called_once_with("rollback-object")
