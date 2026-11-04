{
    "name": "Secure Encrypted Object Storage",
    "summary": "Encrypted private MinIO storage for Odoo documents",
    "version": "17.0.2.0.0",
    "category": "Technical",
    "license": "LGPL-3",
    "author": "Custom implementation",
    "depends": ["base", "web"],
    "external_dependencies": {
        "python": ["minio", "cryptography", "requests"],
    },
    "data": [
        "security/security.xml",
        "data/secure_attachment_cron.xml",
    ],
    "installable": True,
    "application": False,
}