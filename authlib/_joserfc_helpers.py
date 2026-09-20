from typing import Any

from joserfc.jwk import KeySet
from joserfc.jwk import import_key

from authlib.common.encoding import json_loads
from authlib.deprecate import JOSE_REMOVAL_VERSION
from authlib.deprecate import deprecate


def import_any_key(data: Any):
    if _is_authlib_jose_key(data):
        deprecate("Please use joserfc to import keys.", version=JOSE_REMOVAL_VERSION)
        return import_key(data.as_dict(is_private=not data.public_only))

    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{") and text.endswith("}"):
            data = json_loads(text)

    if isinstance(data, (str, bytes)):
        deprecate(
            "Please use OctKey, RSAKey, ECKey, OKPKey, and KeySet directly.",
            version=JOSE_REMOVAL_VERSION,
        )
        return import_key(data)

    if isinstance(data, dict):
        if "keys" in data:
            deprecate(
                "Please `KeySet.import_key_set` from `joserfc.jwk` to import jwks.",
                version=JOSE_REMOVAL_VERSION,
            )
            return KeySet.import_key_set(data)
        return import_key(data)
    return data


def _is_authlib_jose_key(data: Any) -> bool:
    """Detect a legacy ``authlib.jose`` key instance without importing
    ``authlib.jose`` (which emits a deprecation warning) and without
    relying on ``sys.modules`` probing."""
    cls = type(data)
    return (
        cls.__module__.startswith("authlib.jose")
        and hasattr(data, "as_dict")
        and hasattr(data, "public_only")
    )
