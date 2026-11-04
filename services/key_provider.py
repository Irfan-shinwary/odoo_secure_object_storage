
import base64
import logging
import os
import secrets
import time

import requests


_logger = logging.getLogger(__name__)


class KeyProviderError(Exception):
    pass


def _config():
    started = time.perf_counter()

    address = os.getenv("ODOO_VAULT_ADDR", "").rstrip("/")
    token = os.getenv("ODOO_VAULT_TOKEN", "")
    key_name = os.getenv(
        "ODOO_VAULT_TRANSIT_KEY", "odoo-documents"
    )
    mount = os.getenv(
        "ODOO_VAULT_TRANSIT_MOUNT", "transit"
    ).strip("/")

    if not address or not token or not key_name or not mount:
        raise KeyProviderError(
            "Vault configuration is incomplete."
        )

    elapsed = time.perf_counter() - started

    _logger.debug(
        "VAULT_CONFIG_PERFORMANCE elapsed=%.4fs",
        elapsed,
    )

    return address, token, mount, key_name


def _post(path, payload):
    """Send a Vault Transit request and measure every stage."""

    total_started = time.perf_counter()
    stages = {}

    try:
        stage = time.perf_counter()
        address, token, _mount, _key_name = _config()
        stages["config"] = time.perf_counter() - stage

        stage = time.perf_counter()

        response = requests.post(
            f"{address}/v1/{path}",
            json=payload,
            headers={"X-Vault-Token": token},
            timeout=(5, 30),
            verify=os.getenv("ODOO_VAULT_CA_BUNDLE") or True,
        )

        stages["http_request"] = time.perf_counter() - stage

        stage = time.perf_counter()

        if not response.ok:
            raise KeyProviderError(
                f"Vault API returned HTTP {response.status_code}."
            )

        result = response.json()["data"]

        stages["response_parse"] = time.perf_counter() - stage

        total = time.perf_counter() - total_started

        _logger.info(
            "VAULT_TRANSIT_PERFORMANCE "
            "status=SUCCESS endpoint=%s http_status=%s "
            "config=%.4fs http_request=%.4fs "
            "response_parse=%.4fs total=%.4fs",
            path,
            response.status_code,
            stages["config"],
            stages["http_request"],
            stages["response_parse"],
            total,
        )

        return result

    except Exception as exc:
        total = time.perf_counter() - total_started

        _logger.error(
            "VAULT_TRANSIT_PERFORMANCE "
            "status=FAILED endpoint=%s error_type=%s "
            "stages=%s total=%.4fs",
            path,
            type(exc).__name__,
            stages,
            total,
            exc_info=True,
        )

        if isinstance(exc, KeyProviderError):
            raise

        raise KeyProviderError(
            "Vault Transit operation failed."
        ) from exc


def generate_data_key():
    """Generate a random 32-byte data-encryption key."""

    started = time.perf_counter()

    try:
        key = secrets.token_bytes(32)

        elapsed = time.perf_counter() - started

        _logger.info(
            "DEK_GENERATION_PERFORMANCE "
            "status=SUCCESS elapsed=%.4fs",
            elapsed,
        )

        return key, None

    except Exception:
        _logger.exception(
            "DEK_GENERATION_PERFORMANCE status=FAILED"
        )
        raise


def wrap_data_key(key):
    """Wrap a 32-byte DEK using Vault Transit."""

    started = time.perf_counter()

    try:
        if len(key) != 32:
            raise ValueError("DEK must be 32 bytes.")

        _address, _token, mount, key_name = _config()

        data = _post(
            f"{mount}/encrypt/{key_name}",
            {
                "plaintext": base64.b64encode(
                    key
                ).decode("ascii")
            },
        )

        wrapped_key = data["ciphertext"]

        elapsed = time.perf_counter() - started

        _logger.info(
            "DEK_WRAP_PERFORMANCE "
            "status=SUCCESS elapsed=%.4fs",
            elapsed,
        )

        return wrapped_key

    except Exception:
        _logger.exception(
            "DEK_WRAP_PERFORMANCE status=FAILED"
        )
        raise


def unwrap_data_key(wrapped_key):
    """Unwrap a DEK using Vault Transit."""

    started = time.perf_counter()

    try:
        if not wrapped_key:
            raise KeyProviderError(
                "Vault-wrapped data key is missing."
            )

        _address, _token, mount, key_name = _config()

        data = _post(
            f"{mount}/decrypt/{key_name}",
            {"ciphertext": wrapped_key},
        )

        try:
            key = base64.b64decode(
                data["plaintext"],
                validate=True,
            )
        except Exception as exc:
            raise KeyProviderError(
                "Vault returned an invalid data key."
            ) from exc

        if len(key) != 32:
            raise KeyProviderError(
                "Vault returned a key of an invalid length."
            )

        elapsed = time.perf_counter() - started

        _logger.info(
            "DEK_UNWRAP_PERFORMANCE "
            "status=SUCCESS elapsed=%.4fs",
            elapsed,
        )

        return key

    except Exception:
        _logger.exception(
            "DEK_UNWRAP_PERFORMANCE status=FAILED"
        )
        raise



#
# import base64
# import os
# import secrets
#
# import requests
# import logging
# import time
#
# _logger = logging.getLogger(__name__)
#
# class KeyProviderError(Exception):
#     pass
#
#
#
# def _config():
#     address = os.getenv("ODOO_VAULT_ADDR", "").rstrip("/")
#     token = os.getenv("ODOO_VAULT_TOKEN", "")
#     key_name = os.getenv("ODOO_VAULT_TRANSIT_KEY", "odoo-documents")
#     mount = os.getenv("ODOO_VAULT_TRANSIT_MOUNT", "transit").strip("/")
#
#     if not address or not token or not key_name:
#         raise KeyProviderError("Vault configuration is incomplete.")
#
#     return address, token, mount, key_name
#
# def _post(path, payload):
#     address, token, _mount, _key_name = _config()
#
#     started = time.perf_counter()
#
#     response = requests.post(
#         f"{address}/v1/{path}",
#         json=payload,
#         headers={"X-Vault-Token": token},
#         timeout=(5, 30),
#         verify=os.getenv("ODOO_VAULT_CA_BUNDLE") or True,
#     )
#
#     elapsed = time.perf_counter() - started
#
#     _logger.info(
#         "VAULT_TRANSIT_PERFORMANCE endpoint=%s "
#         "status=%s elapsed=%.3fs",
#         path,
#         response.status_code,
#         elapsed,
#     )
#
#     if not response.ok:
#         raise RuntimeError(
#             f"Vault API error: HTTP {response.status_code}: {response.text}"
#         )
#
#     return response.json()["data"]
#
# # def _post(path, payload):
# #     address, token, _mount, _key_name = _config()
# #     response = requests.post(
# #         f"{address}/v1/{path}",
# #         json=payload,
# #         headers={"X-Vault-Token": token},
# #         timeout=(5, 30),
# #         verify=os.getenv("ODOO_VAULT_CA_BUNDLE") or True,
# #     )
# #     if not response.ok:
# #         raise RuntimeError(
# #             f"Vault API error: HTTP {response.status_code}: {response.text}"
# #         )
# #     # response.raise_for_status()
# #     return response.json()["data"]
# #
#
# def generate_data_key():
#     """Return (raw_32_byte_key, Vault_wrapped_ciphertext)."""
#     return secrets.token_bytes(32), None
#
#
# def wrap_data_key(key):
#     if len(key) != 32:
#         raise ValueError("DEK must be 32 bytes.")
#
#     _address, _token, mount, key_name = _config()
#     data = _post(
#         f"{mount}/encrypt/{key_name}",
#         {"plaintext": base64.b64encode(key).decode("ascii")},
#     )
#     return data["ciphertext"]
#
#
# def unwrap_data_key(wrapped_key):
#     _address, _token, mount, key_name = _config()
#     data = _post(
#         f"{mount}/decrypt/{key_name}",
#         {"ciphertext": wrapped_key},
#     )
#     try:
#         key = base64.b64decode(data["plaintext"], validate=True)
#     except Exception as exc:
#         raise KeyProviderError("Vault returned an invalid data key.") from exc
#
#     if len(key) != 32:
#         raise KeyProviderError("Vault returned a key of an invalid length.")
#
#     return key
