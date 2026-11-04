from odoo.exceptions import AccessError
from odoo.tests.common import TransactionCase


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
                "name": "Other Secure User",
                "login": "other-secure-user-test",
                "email": "other-secure-user-test@example.invalid",
                "company_id": self.env.company.id,
                "company_ids": [(6, 0, [self.env.company.id])],
            })
        # other_user = self.env["res.users"].create({
        #     "name": "Other Secure User",
        #     "login": "other-secure-user-test",
        #     "email": "other-secure-user-test@example.invalid",
        #     "company_id": self.env.company.id,
        #     "company_ids": [(6, 0, [self.env.company.id])],
        #     "partner_id": False,
        #     "notification_type": "inbox",
        # })

        document = self.env["secure.document"].with_user(
            self.env.user
        ).create({
            "name": "private.txt",
            "owner_id": self.env.user.id,
            "company_id": self.env.company.id,
        })

        with self.assertRaises(AccessError):
            document.with_user(other_user)._check_document_access("read")
