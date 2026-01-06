"""Encryption/decryption middleware for API layer.

This module provides helpers to encrypt data before storing and decrypt
after retrieving, keeping encryption logic at the API layer.
"""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING, Any, cast

import orjson
import structlog
from starlette.authentication import BaseUser
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request  # noqa: TC002

from langgraph_api.config import LANGGRAPH_ENCRYPTION
from langgraph_api.encryption.context import (
    get_encryption_context,
    set_encryption_context,
)
from langgraph_api.encryption.custom import (
    ModelType,
    get_encryption_instance,
)
from langgraph_api.schema import NESTED_ENCRYPTED_SUBFIELDS
from langgraph_api.serde import Fragment, json_loads

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from langgraph_sdk import Encryption

# Only import EncryptionContext at module load if encryption is configured
# This avoids requiring langgraph-sdk>=0.2.14 for users who don't use encryption
if LANGGRAPH_ENCRYPTION:
    from langgraph_sdk import EncryptionContext

logger = structlog.stdlib.get_logger(__name__)

ENCRYPTION_CONTEXT_KEY = "__encryption_context__"


def _serialize_user_for_encryption(user: BaseUser) -> dict[str, Any]:
    """Serialize a BaseUser to a JSON-serializable dict for encryption.

    Called by _prepare_data_for_encryption when langgraph_auth_user contains a
    BaseUser that needs to be serialized before JSON encryption.

    Args:
        user: The BaseUser to serialize (ProxyUser, SimpleUser, or custom subclass)

    Returns:
        A JSON-serializable dict with user data
    """
    # ProxyUser has model_dump() which preserves extra fields from the wrapped user
    if hasattr(user, "model_dump") and callable(user.model_dump):
        return cast("dict[str, Any]", user.model_dump())

    # Plain BaseUser subclasses - extract the required properties
    return {
        "identity": user.identity,
        "is_authenticated": user.is_authenticated,
        "display_name": user.display_name,
    }


def _prepare_data_for_encryption(data: dict[str, Any]) -> dict[str, Any]:
    """Prepare data dict for encryption by serializing non-JSON-serializable objects.

    Specifically handles langgraph_auth_user which may contain BaseUser objects
    that can't be JSON-serialized. Dicts pass through unchanged (already serializable).

    Args:
        data: The data dict to prepare

    Returns:
        A new dict with serialized values where needed
    """
    if "langgraph_auth_user" not in data:
        return data

    user = data["langgraph_auth_user"]
    if isinstance(user, BaseUser):
        data = dict(data)  # shallow copy
        data["langgraph_auth_user"] = _serialize_user_for_encryption(user)

    return data


def extract_encryption_context(request: Request) -> dict[str, Any]:
    """Extract encryption context from X-Encryption-Context header.

    Args:
        request: The Starlette request object

    Returns:
        Encryption context dict, or empty dict if header not present

    Raises:
        HTTPException: 422 if header is present but malformed
    """
    header_value = request.headers.get("X-Encryption-Context")
    if not header_value:
        return {}

    try:
        decoded = base64.b64decode(header_value.encode())
        context = orjson.loads(decoded)
        if not isinstance(context, dict):
            raise HTTPException(
                status_code=422,
                detail="Invalid X-Encryption-Context header: expected base64-encoded JSON object",
            )
        return context
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid X-Encryption-Context header: {e}",
        ) from e


class EncryptionContextMiddleware(BaseHTTPMiddleware):
    """Middleware to extract and set encryption context from request headers.

    If a @encryption.context handler is registered, it is called after extracting
    the initial context from the X-Encryption-Context header. The handler receives
    the authenticated user and can derive encryption context from auth (e.g., JWT claims).
    """

    async def dispatch(self, request: Request, call_next):
        context_dict = extract_encryption_context(request)

        # Call context handler if registered (to derive context from auth)
        encryption_instance = get_encryption_instance()
        if encryption_instance and encryption_instance._context_handler:
            user = request.scope.get("user")
            if user:
                initial_ctx = EncryptionContext(
                    model=None, field=None, metadata=context_dict
                )
                try:
                    context_dict = await encryption_instance._context_handler(
                        user, initial_ctx
                    )
                except Exception as e:
                    await logger.aexception(
                        "Error in encryption context handler", exc_info=e
                    )

        set_encryption_context(context_dict)
        request.state.encryption_context = context_dict
        response = await call_next(request)
        return response


class EncryptionKeyError(Exception):
    """Raised when JSON encryptor violates key preservation constraint."""


class DoubleEncryptionError(Exception):
    """Raised when attempting to encrypt data that is already encrypted.

    This typically indicates a bug where encrypted data is being passed through
    the encryption pipeline again, which would corrupt the data.
    """


async def encrypt_json_if_needed(
    data: dict[str, Any] | None,
    encryption_instance: Encryption | None,
    model_type: ModelType,
    field: str | None = None,
) -> dict[str, Any] | None:
    """Encrypt JSON data dict if encryption is configured.

    Args:
        data: The plaintext data dict
        encryption_instance: The encryption instance (or None if no encryption)
        model_type: The type of model (e.g., "thread", "assistant", "run")
        field: The specific field being encrypted (e.g., "metadata", "context")

    Returns:
        Encrypted data dict with stored context, or original if no encryption configured

    Raises:
        EncryptionKeyError: If the encryptor adds or removes keys (violates key preservation)
        DoubleEncryptionError: If data already has encryption context marker (already encrypted)
    """
    if data is None or encryption_instance is None:
        return data

    # Safety check: detect if data is already encrypted to prevent double encryption.
    # The encryption marker (__encryption_context__) is added by this function after encryption.
    if ENCRYPTION_CONTEXT_KEY in data:
        raise DoubleEncryptionError(
            f"Attempted to encrypt data that is already encrypted (has {ENCRYPTION_CONTEXT_KEY}). "
            f"model_type={model_type}, field={field}. "
            f"This indicates a bug where encrypted data is being re-encrypted. "
            f"Ensure data is decrypted before re-encrypting."
        )

    encryptor = encryption_instance.get_json_encryptor(model_type)
    if encryptor is None:
        return data

    # Prepare data for encryption by serializing non-JSON-serializable objects
    # (e.g., BaseUser in langgraph_auth_user)
    data = _prepare_data_for_encryption(data)

    context_dict = get_encryption_context()

    ctx = EncryptionContext(model=model_type, field=field, metadata=context_dict)
    encrypted = await encryptor(ctx, data)

    # Validate key preservation: encryptor must not add or remove keys
    # This constraint exists because SQL-level JSONB merge (||) operates on keys:
    # if encryptor consolidates keys (e.g., multiple fields → __encrypted__),
    # merge will overwrite, causing data loss. Per-key encryption is safe.
    if encrypted is not None and isinstance(encrypted, dict):
        input_keys = set(data.keys())
        output_keys = set(encrypted.keys())
        added_keys = output_keys - input_keys
        removed_keys = input_keys - output_keys
        if added_keys or removed_keys:
            raise EncryptionKeyError(
                f"JSON encryptor must preserve key structure for SQL JSONB merge compatibility. "
                f"Added keys: {added_keys or 'none'}, removed keys: {removed_keys or 'none'}. "
                f"Use per-key encryption (transform values, not keys) instead of envelope patterns."
            )

    # Always store the context marker when encrypting (even if context is empty)
    # This marker is used during decryption to know if data was encrypted
    if encrypted is not None and isinstance(encrypted, dict):
        encrypted[ENCRYPTION_CONTEXT_KEY] = context_dict

    await logger.adebug(
        "Encrypted JSON data",
        model_type=model_type,
        field=field,
        context_stored=bool(context_dict),
    )
    return encrypted


def extract_encryption_context_from_data(
    data: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Extract and parse the encryption context from a data dict.

    Use this to extract the encryption context BEFORE calling decrypt_response,
    since decrypt_response strips the context key from the data.

    Args:
        data: The data dict that may contain an encryption context

    Returns:
        The parsed encryption context dict, or None if not present
    """
    if data is None:
        return None

    return data.get(ENCRYPTION_CONTEXT_KEY)


async def decrypt_json_if_needed(
    data: dict[str, Any] | None,
    encryption_instance: Encryption | None,
    model_type: ModelType,
    field: str | None = None,
) -> dict[str, Any] | None:
    """Decrypt JSON data dict if encryption is configured and data was encrypted.

    Only calls the decryptor if the data contains the ENCRYPTION_CONTEXT_KEY marker,
    which indicates it was encrypted. This ensures plaintext data passes through
    unchanged, which is important during mixed-state scenarios where some endpoints
    encrypt on write but others don't yet.

    Args:
        data: The data dict (encrypted or plaintext)
        encryption_instance: The encryption instance (or None if no encryption)
        model_type: The type of model (e.g., "thread", "assistant", "run")
        field: The specific field being decrypted (e.g., "metadata", "context")

    Returns:
        Decrypted data dict (without reserved key), or original if not encrypted
    """
    if data is None or encryption_instance is None:
        return data

    # Only decrypt if data was actually encrypted (has the context marker)
    if ENCRYPTION_CONTEXT_KEY not in data:
        return data

    decryptor = encryption_instance.get_json_decryptor(model_type)
    if decryptor is None:
        return data

    context_dict = data[ENCRYPTION_CONTEXT_KEY]
    # Remove key before passing to user's decryptor to avoid duplication
    # (context is already passed via ctx.metadata)
    data = {k: v for k, v in data.items() if k != ENCRYPTION_CONTEXT_KEY}

    ctx = EncryptionContext(model=model_type, field=field, metadata=context_dict)
    decrypted = await decryptor(ctx, data)

    # Ensure reserved key is removed from output (in case decryptor didn't handle it)
    if ENCRYPTION_CONTEXT_KEY in decrypted:
        decrypted = {k: v for k, v in decrypted.items() if k != ENCRYPTION_CONTEXT_KEY}

    await logger.adebug(
        "Decrypted JSON data",
        model_type=model_type,
        field=field,
        context_retrieved=bool(context_dict),
    )
    return decrypted


async def _decrypt_field(
    obj: dict[str, Any],
    field_name: str,
    encryption_instance: Encryption,
    model_type: ModelType,
) -> tuple[str, Any]:
    """Decrypt a single field, returning (field_name, decrypted_value).

    Fields defined in NESTED_ENCRYPTED_SUBFIELDS have their subfields decrypted
    recursively (e.g., run.kwargs.config.configurable).

    Returns (field_name, None) if field doesn't exist or is falsy.
    """
    if not obj.get(field_name):
        return (field_name, obj.get(field_name))

    value = obj[field_name]
    # Database fields come back as either:
    # - dict: already parsed JSONB (psycopg JSON adapter)
    # - bytes/bytearray/memoryview/str: raw JSON to parse (psycopg binary mode)
    # - Fragment: wrapper around bytes (used by serde layer)
    if isinstance(value, dict):
        pass  # already parsed
    elif isinstance(value, (bytes, bytearray, memoryview, str, Fragment)):
        value = json_loads(value)
    else:
        raise TypeError(
            f"Cannot decrypt field '{field_name}': expected dict or JSON-serialized "
            f"bytes/str, got {type(value).__name__}"
        )

    decrypted = await decrypt_json_if_needed(
        value, encryption_instance, model_type, field=field_name
    )

    # Recursively decrypt subfields defined in NESTED_ENCRYPTED_SUBFIELDS.
    # This handles nested structures like run.kwargs.config.configurable where each
    # level needs individual encryption to preserve structure for SQL JSONB operations.
    nested_key = (model_type, field_name)
    if nested_key in NESTED_ENCRYPTED_SUBFIELDS and decrypted is not None:
        results = await asyncio.gather(
            *[
                _decrypt_field(decrypted, sf, encryption_instance, model_type)
                for sf in NESTED_ENCRYPTED_SUBFIELDS[nested_key]
                if sf in decrypted
            ]
        )
        for sf_name, sf_value in results:
            decrypted[sf_name] = sf_value

    return (field_name, decrypted)


async def _decrypt_object(
    obj: dict[str, Any],
    model_type: ModelType,
    fields: list[str],
    encryption_instance: Encryption,
) -> None:
    """Decrypt all specified fields in a single object (in parallel).

    Only processes fields that exist in the object to avoid adding new fields.
    """
    results = await asyncio.gather(
        *[
            _decrypt_field(obj, f, encryption_instance, model_type)
            for f in fields
            if f in obj
        ]
    )
    for field_name, value in results:
        obj[field_name] = value


async def decrypt_response(
    obj: Mapping[str, Any],
    model_type: ModelType,
    fields: list[str],
    encryption_instance: Encryption | None = None,
) -> dict[str, Any]:
    """Decrypt specified fields in a response object (from database).

    IMPORTANT: This function only parses and decrypts fields when encryption is
    enabled. When encryption is disabled, the original object is returned as-is
    (no copy, no parsing). This is intentional: some fields can be very large,
    and we want to avoid parsing overhead when the bytes can be passed through
    directly to the response. Callers that need parsed dicts regardless of
    encryption state should use json_loads() on the fields they need to inspect.

    When encryption IS enabled, this parses bytes/memoryview/Fragment to dicts
    before decryption, and returns a shallow copy with decrypted fields.

    Fields defined in NESTED_ENCRYPTED_SUBFIELDS have their subfields decrypted
    recursively (e.g., config.configurable, config.metadata).

    Args:
        obj: Single mapping from database (fields may be bytes or already-parsed dicts, not mutated)
        model_type: Type identifier passed to EncryptionContext.model (e.g., "run", "cron", "thread")
        fields: List of field names to decrypt (e.g., ["metadata", "kwargs"])
        encryption_instance: Optional encryption instance (auto-fetched if None)

    Returns:
        Original object if encryption disabled, otherwise new dict with decrypted fields
    """
    if encryption_instance is None:
        encryption_instance = get_encryption_instance()
        if encryption_instance is None:
            return obj  # type: ignore[return-value]

    result = dict(obj)
    await _decrypt_object(result, model_type, fields, encryption_instance)
    return result


async def decrypt_responses(
    objects: Sequence[Mapping[str, Any]],
    model_type: ModelType,
    fields: list[str],
    encryption_instance: Encryption | None = None,
) -> list[dict[str, Any]]:
    """Decrypt specified fields in multiple response objects (from database).

    IMPORTANT: This function only parses and decrypts fields when encryption is
    enabled. When encryption is disabled, the original sequence is returned as-is
    (no copies, no parsing). This is intentional: some fields can be very large,
    and we want to avoid parsing overhead when the bytes can be passed through
    directly to the response. Callers that need parsed dicts regardless of
    encryption state should use json_loads() on the fields they need to inspect.

    When encryption IS enabled, this parses bytes/memoryview/Fragment to dicts
    before decryption, and returns a new list of shallow copies with decrypted fields.

    Fields defined in NESTED_ENCRYPTED_SUBFIELDS have their subfields decrypted
    recursively (e.g., config.configurable, config.metadata).

    Args:
        objects: Sequence of mappings from database (fields may be bytes or already-parsed dicts, not mutated)
        model_type: Type identifier passed to EncryptionContext.model (e.g., "run", "cron", "thread")
        fields: List of field names to decrypt (e.g., ["metadata", "kwargs"])
        encryption_instance: Optional encryption instance (auto-fetched if None)

    Returns:
        Original sequence if encryption disabled, otherwise new list with decrypted fields
    """
    if encryption_instance is None:
        encryption_instance = get_encryption_instance()
        if encryption_instance is None:
            return objects  # type: ignore[return-value]

    results = [dict(obj) for obj in objects]
    await asyncio.gather(
        *[
            _decrypt_object(result, model_type, fields, encryption_instance)
            for result in results
        ]
    )
    return results


async def _encrypt_field(
    data: Mapping[str, Any],
    field_name: str,
    encryption_instance: Encryption,
    model_type: ModelType,
) -> tuple[str, Any]:
    """Encrypt a single field, returning (field_name, encrypted_value).

    Fields defined in NESTED_ENCRYPTED_SUBFIELDS have their subfields extracted
    and encrypted separately, then added back. This preserves the nested structure
    for SQL JSONB operations while encrypting each level individually.

    Returns (field_name, None) if field doesn't exist or is None.
    """
    if field_name not in data or data[field_name] is None:
        return (field_name, data.get(field_name))

    field_data = data[field_name]

    # Check if this field has subfields that need separate encryption
    nested_key = (model_type, field_name)
    subfields_to_extract: dict[str, Any] = {}

    if nested_key in NESTED_ENCRYPTED_SUBFIELDS and isinstance(field_data, dict):
        for subfield in NESTED_ENCRYPTED_SUBFIELDS[nested_key]:
            subfield_value = field_data.get(subfield)
            if subfield_value and isinstance(subfield_value, dict):
                subfields_to_extract[subfield] = subfield_value

        if subfields_to_extract:
            # Create a copy without subfields for the first encryption pass
            field_data = {
                k: v for k, v in field_data.items() if k not in subfields_to_extract
            }

    encrypted = await encrypt_json_if_needed(
        field_data,
        encryption_instance,
        model_type,
        field=field_name,
    )

    # Recursively encrypt extracted subfields and add them back
    if subfields_to_extract and isinstance(encrypted, dict):
        subfield_results = await asyncio.gather(
            *[
                _encrypt_field(
                    {sf_name: sf_value},
                    sf_name,
                    encryption_instance,
                    model_type,
                )
                for sf_name, sf_value in subfields_to_extract.items()
            ]
        )
        for sf_name, sf_encrypted in subfield_results:
            encrypted[sf_name] = sf_encrypted

    return (field_name, encrypted)


async def encrypt_request(
    data: Mapping[str, Any],
    model_type: ModelType,
    fields: list[str],
    encryption_instance: Encryption | None = None,
) -> dict[str, Any]:
    """Encrypt specified fields in request data before passing to ops layer (in parallel).

    This is a generic helper that handles encryption for any object type.
    It uses the ContextVar to get encryption context (set by middleware or endpoint).

    When encryption is disabled, the original data is returned as-is (no copy).
    When encryption IS enabled, returns a shallow copy with encrypted fields.

    Fields defined in NESTED_ENCRYPTED_SUBFIELDS have their subfields encrypted
    recursively (e.g., config.configurable, config.metadata).

    Only processes fields that exist in the data to avoid adding new fields.

    Args:
        data: Request data mapping to encrypt (not mutated)
        model_type: Type identifier passed to EncryptionContext.model (e.g., "run", "cron", "thread")
        fields: List of field names to encrypt (e.g., ["metadata", "kwargs"])
        encryption_instance: Optional encryption instance (auto-fetched if None)

    Returns:
        Original data if encryption disabled, otherwise new dict with encrypted fields

    Example:
        encrypted = await encrypt_request(
            payload,
            "run",
            ["metadata"]
        )
    """
    if encryption_instance is None:
        encryption_instance = get_encryption_instance()
        if encryption_instance is None:
            return data  # type: ignore[return-value]

    result = dict(data)
    encrypted_fields = await asyncio.gather(
        *[
            _encrypt_field(data, f, encryption_instance, model_type)
            for f in fields
            if f in data
        ]
    )
    for field_name, value in encrypted_fields:
        result[field_name] = value

    return result
