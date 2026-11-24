{
    "name": "Secure Encrypted Object Storage",
    "summary": "Encrypted private MinIO storage for Odoo documents",
    "version": "17.0.2.0.0",
    "category": "Technical",
    "license": "LGPL-3",
    "author": "Custom implementation",
    "depends": ["base", "web","mail"],
    "external_dependencies": {
        "python": ["minio", "cryptography", "requests"],
    },
    "data": [
        "security/security.xml",
        'security/ir.model.access.csv',

        "data/secure_storage_config_data.xml",
        'wizard/discovery_wizard.xml',
        'views/menu.xml',
        'views/migration_views.xml',
        "views/secure_storage_config_views.xml",

        "data/migration_cron.xml",
        "data/secure_attachment_cron.xml",
    ],
    "installable": True,
    "application": True,
}
