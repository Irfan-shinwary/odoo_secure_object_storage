
import base64
import os
import secrets

import requests


class KeyProviderError(Exception):
    pass



def _config():
    address = os.getenv("ODOO_VAULT_ADDR", "").rstrip("/")
    token = os.getenv("ODOO_VAULT_TOKEN", "")
    key_name = os.getenv("ODOO_VAULT_TRANSIT_KEY", "odoo-documents")
    mount = os.getenv("ODOO_VAULT_TRANSIT_MOUNT", "transit").strip("/")

    if not address or not token or not key_name:
        raise KeyProviderError("Vault configuration is incomplete.")

    return address, token, mount, key_name


def _post(path, payload):
    address, token, _mount, _key_name = _config()
    response = requests.post(
        f"{address}/v1/{path}",
        json=payload,
        headers={"X-Vault-Token": token},
        timeout=(5, 30),
        verify=os.getenv("ODOO_VAULT_CA_BUNDLE") or True,
    )
    if not response.ok:
        raise RuntimeError(
            f"Vault API error: HTTP {response.status_code}: {response.text}"
        )
    # response.raise_for_status()
    return response.json()["data"]


def generate_data_key():
    """Return (raw_32_byte_key, Vault_wrapped_ciphertext)."""
    return secrets.token_bytes(32), None


def wrap_data_key(key):
    if len(key) != 32:
        raise ValueError("DEK must be 32 bytes.")

    _address, _token, mount, key_name = _config()
    data = _post(
        f"{mount}/encrypt/{key_name}",
        {"plaintext": base64.b64encode(key).decode("ascii")},
    )
    return data["ciphertext"]


def unwrap_data_key(wrapped_key):
    _address, _token, mount, key_name = _config()
    data = _post(
        f"{mount}/decrypt/{key_name}",
        {"ciphertext": wrapped_key},
    )
    try:
        key = base64.b64decode(data["plaintext"], validate=True)
    except Exception as exc:
        raise KeyProviderError("Vault returned an invalid data key.") from exc

    if len(key) != 32:
        raise KeyProviderError("Vault returned a key of an invalid length.")

    return key
