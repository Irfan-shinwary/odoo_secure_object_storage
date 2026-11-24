# HashiCorp Vault Transit setup

Vault Transit wraps and unwraps per-object DEKs for new `ir.attachment` objects and for the separate `secure.document` model. Legacy `ODOOENC1`/`ODOOENC2` attachment objects still require `ODOO_SECURE_STORAGE_MASTER_KEY` for decryption.

## 1. Start local development Vault

Create the local `.env` file, then:

```bash
docker compose up -d vault
docker compose logs -f vault
```

The provided local configuration listens without TLS but Docker publishes the API only on `127.0.0.1:8200`. Do not expose this configuration to a network.

## 2. Initialize Vault once

For a brand-new Vault data volume only:

```bash
docker exec -it odoo-secure-vault vault operator init
```

Vault prints unseal key shares and an initial root token. Record them immediately in an approved password manager or offline secrets vault with restricted access. Never put them in Git, a shared document, a ticket, an Odoo configuration file, or the application environment.

Initialization is a one-time operation for the storage backend. Do not initialize an already initialized Vault.

## 3. Unseal after startup

After a restart, Vault may be sealed. Submit the required unseal key shares interactively:

```bash
docker exec -it odoo-secure-vault vault operator unseal
```

Repeat with distinct key shares until Vault reports that it is unsealed. Do not pass unseal keys as command-line arguments or save them in scripts.

## 4. Authenticate administratively and enable Transit

Use the initial root token only for initial administration, entered interactively:

```bash
docker exec -it odoo-secure-vault sh
vault login
vault secrets enable transit
vault write -f transit/keys/odoo-documents
```

The Transit engine and key must be created once. If the engine is already enabled or the key already exists, inspect current state rather than repeating creation blindly.

## 5. Create a limited application policy

Create a policy file on the administrator's secure workstation named `odoo-transit.hcl`:

```hcl
path "transit/encrypt/odoo-documents" {
  capabilities = ["update"]
}

path "transit/decrypt/odoo-documents" {
  capabilities = ["update"]
}
```

Load the policy and create an application token using the Vault CLI as an administrator:

```bash
vault policy write odoo-transit odoo-transit.hcl
vault token create -policy=odoo-transit -ttl=24h
```

For production, integrate token issuance/renewal with your organization's authentication method and secret manager. Choose an appropriate TTL and renewal strategy. Do not give the Odoo process the root token.

## 6. Configure Odoo

```dotenv
ODOO_VAULT_ADDR=http://127.0.0.1:8200
ODOO_VAULT_TOKEN=<limited-application-token>
ODOO_VAULT_TRANSIT_MOUNT=transit
ODOO_VAULT_TRANSIT_KEY=odoo-documents
```

For production use HTTPS, a trusted CA and `ODOO_VAULT_CA_BUNDLE` if a private CA is used. The code verifies TLS by default and uses the optional CA bundle path when configured.

## 7. Where to keep keys and tokens

- **Unseal key shares:** store separately in an enterprise secrets vault or physically secured offline locations, following the organization's threshold/key-custody policy. Do not store all shares together.
- **Initial root token:** secure administrator-only storage; revoke or tightly control after bootstrap according to Vault operational policy.
- **Odoo application token:** secret manager or protected service environment file readable only by the Odoo service account. Use a limited policy and rotation procedure.
- **Transit key material:** remains in Vault's persistent storage; protect and back up that storage.
- **Legacy attachment master key:** separate secret, not a Vault unseal key or Transit token. Keep it in a secrets manager and secure backup only while legacy `ODOOENC1`/`ODOOENC2` objects remain; losing it makes those remaining objects unreadable.

## 8. Production requirements

Use TLS, a supported Vault storage backend, restricted firewall rules, audited administrative access, appropriate auto-unseal where organizationally approved, and tested backup/restore. The included file-storage backend and TLS-disabled listener are for local development only. Follow HashiCorp's current production hardening and recovery documentation before production rollout.
