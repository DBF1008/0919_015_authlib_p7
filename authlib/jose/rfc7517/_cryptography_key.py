from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.x509 import load_pem_x509_certificate

from authlib.common.encoding import to_bytes

#: marker of an encrypted PEM private key
ENCRYPTED_PEM_MARKER = b"ENCRYPTED"


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
    """Load a PEM private key, with recovery for password mismatches.

    Instead of propagating the low level cryptography errors, this
    helper recovers from the two common password problems:

    - the key is encrypted but no password was given: a clear
      ``ValueError`` is raised so callers know a password is required
    - a password was given for a key that is not encrypted: the key
      is loaded again without the password
    """
    if password is None and ENCRYPTED_PEM_MARKER in raw:
        raise ValueError("Password is required to load the encrypted private key")
    try:
        return load_pem_private_key(raw, password=password, backend=default_backend())
    except (TypeError, ValueError):
        if password is not None and ENCRYPTED_PEM_MARKER not in raw:
            # the key is not encrypted, recover by loading without password
            return load_pem_private_key(raw, password=None, backend=default_backend())
        raise
