import re
import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter("always", AuthlibDeprecationWarning)

#: deprecation versions use semantic versioning (``X.Y.Z``), in line
#: with the release version defined in ``authlib.consts``
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def deprecate(message, version=None, stacklevel=3):
    if version:
        version = _normalize_version(version)
        message += f"\nIt will be compatible before version {version}."

    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=stacklevel)


def _normalize_version(version):
    """Normalize a version string to semantic versioning (``X.Y.Z``)."""
    version = str(version).strip()
    if _SEMVER_RE.match(version):
        return version
    if re.match(r"^\d+\.\d+$", version):
        return f"{version}.0"
    if re.match(r"^\d+$", version):
        return f"{version}.0.0"
    raise ValueError(
        f"Invalid deprecation version: {version!r}, expected a semantic version"
    )
