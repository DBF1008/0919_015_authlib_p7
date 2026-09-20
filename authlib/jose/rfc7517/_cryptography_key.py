from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.x509 import load_pem_x509_certificate

from authlib.common.encoding import to_bytes


def load_pem_key(raw, ssh_type=None, key_type=None, password=None):
    raw = to_bytes(raw)
    password = to_bytes(password)

    if ssh_type and raw.startswith(ssh_type):
        return load_ssh_public_key(raw, backend=default_backend())

    if key_type == "public":
        return load_pem_public_key(raw, backend=default_backend())

    if key_type == "private" or password is not None:
        return _load_pem_private_key(raw, password)

    if b"PUBLIC" in raw:
        return load_pem_public_key(raw, backend=default_backend())

    if b"PRIVATE" in raw:
        return _load_pem_private_key(raw, password)

    if b"CERTIFICATE" in raw:
        cert = load_pem_x509_certificate(raw, default_backend())
        return cert.public_key()

    try:
        return _load_pem_private_key(raw, password)
    except ValueError:
        return load_pem_public_key(raw, backend=default_backend())


def _load_pem_private_key(raw, password=None):
    try:
        return load_pem_private_key(raw, password=password, backend=default_backend())
    except TypeError as error:
        if password is None:
            # cryptography raises TypeError when the key is encrypted but
            # no password was given; recover with a clear error so callers
            # can retry with a password.
            raise ValueError(
                "The private key is encrypted, please provide a password"
            ) from error
        raise
