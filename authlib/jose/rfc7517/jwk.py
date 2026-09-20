from authlib.common.encoding import json_loads

from ._cryptography_key import load_pem_key
from .key_set import KeySet

_NOT_FOUND = object()


class JsonWebKey:
    JWK_KEY_CLS = {}

    #: cache of concrete raw key type -> Key class, so that ``import_key``
    #: dispatches in O(1) instead of probing every registered key class
    _RAW_KEY_CLS_CACHE = {}
    _RAW_KEY_CLS_CACHE_SRC = None

    @classmethod
    def generate_key(cls, kty, crv_or_size, options=None, is_private=False):
        """Generate a Key with the given key type, curve name or bit size.

        :param kty: string of ``oct``, ``RSA``, ``EC``, ``OKP``
        :param crv_or_size: curve name or bit size
        :param options: a dict of other options for Key
        :param is_private: create a private key or public key
        :return: Key instance
        """
        key_cls = cls.JWK_KEY_CLS[kty]
        return key_cls.generate_key(crv_or_size, options, is_private)

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a Key from bytes, string, PEM or dict.

        This is the single entry point for importing JWK keys; PEM
        parsing is delegated to ``load_pem_key``.

        :return: Key instance
        """
        kty = None
        if options is not None:
            kty = options.get("kty")

        if kty is None and isinstance(raw, dict):
            kty = raw.get("kty")

        if kty is None:
            password = options.get("password") if options is not None else None
            raw_key = load_pem_key(raw, password=password)
            key_cls = cls.find_key_cls(raw_key)
            if key_cls is None:
                raise ValueError("Unable to determine the key type")
            return key_cls.import_key(raw_key, options)

        key_cls = cls.JWK_KEY_CLS[kty]
        return key_cls.import_key(raw, options)

    @classmethod
    def find_key_cls(cls, raw_key):
        """Find the registered Key class for a raw cryptography key."""
        if cls._RAW_KEY_CLS_CACHE_SRC != cls.JWK_KEY_CLS:
            cls._RAW_KEY_CLS_CACHE = {}
            cls._RAW_KEY_CLS_CACHE_SRC = dict(cls.JWK_KEY_CLS)

        raw_type = type(raw_key)
        key_cls = cls._RAW_KEY_CLS_CACHE.get(raw_type, _NOT_FOUND)
        if key_cls is _NOT_FOUND:
            key_cls = None
            for candidate in cls.JWK_KEY_CLS.values():
                if candidate.validate_raw_key(raw_key):
                    key_cls = candidate
                    break
            cls._RAW_KEY_CLS_CACHE[raw_type] = key_cls
        return key_cls

    @classmethod
    def import_key_set(cls, raw):
        """Import KeySet from string, dict or a list of keys.

        :return: KeySet instance
        """
        raw = _transform_raw_key(raw)
        if isinstance(raw, dict) and "keys" in raw:
            keys = raw.get("keys")
            return KeySet([cls.import_key(k) for k in keys])
        raise ValueError("Invalid key set format")


def _transform_raw_key(raw):
    if isinstance(raw, str) and raw.startswith("{") and raw.endswith("}"):
        return json_loads(raw)
    elif isinstance(raw, (tuple, list)):
        return {"keys": raw}
    return raw
