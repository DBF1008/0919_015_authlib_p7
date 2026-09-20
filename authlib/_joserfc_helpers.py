from typing import Any

from joserfc.jwk import KeySet
from joserfc.jwk import import_key

from authlib.common.encoding import json_loads
from authlib.deprecate import deprecate

_USE_JOSERFC_MESSAGE = "Please use joserfc to import keys."
_USE_KEY_CLS_MESSAGE = "Please use OctKey, RSAKey, ECKey, OKPKey, and KeySet directly."
_USE_KEY_SET_MESSAGE = (
    "Please `KeySet.import_key_set` from `joserfc.jwk` to import jwks."
)


def import_any_key(data: Any):
    """Import a key of any supported type.

    This is the migration path from ``authlib.jose`` to ``joserfc``;
    legacy authlib keys are converted into joserfc keys.
    """
    if _is_authlib_key(data):
        deprecate(_USE_JOSERFC_MESSAGE, version="2.0.0")
        return import_key(data.as_dict(is_private=not data.public_only))

    if (
        isinstance(data, str)
        and data.strip().startswith("{")
        and data.strip().endswith("}")
    ):
        deprecate(_USE_KEY_CLS_MESSAGE, version="2.0.0")
        data = json_loads(data)

    if isinstance(data, (str, bytes)):
        deprecate(_USE_KEY_CLS_MESSAGE, version="2.0.0")
        return import_key(data)

    if isinstance(data, dict):
        if "keys" in data:
            deprecate(_USE_KEY_SET_MESSAGE, version="2.0.0")
            return KeySet.import_key_set(data)
        return import_key(data)
    return data


def _is_authlib_key(data: Any) -> bool:
    """Detect a legacy ``authlib.jose`` key instance.

    The check inspects the class hierarchy of the object instead of
    probing ``sys.modules``, so it stays reliable no matter how (and
    when) ``authlib.jose`` was imported, and it does not import the
    deprecated ``authlib.jose`` module itself.
    """
    return any(
        cls.__name__ == "Key" and cls.__module__ == "authlib.jose.rfc7517.base_key"
        for cls in type(data).__mro__
    )
