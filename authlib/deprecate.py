import warnings

# Deprecation schedule. Versions follow semantic versioning and are aligned
# with the project version plan (``authlib.consts.version``, consumed by
# ``pyproject.toml`` and built via the ``Makefile`` ``build`` target):
#
# - ``NEXT_MINOR_VERSION``: deprecations announced during the current minor
#   cycle become mandatory (or are removed) in the next minor release.
# - ``JOSE_REMOVAL_VERSION``: ``authlib.jose`` is removed in favor of the
#   external ``joserfc`` package.
NEXT_MINOR_VERSION = "1.8.0"
JOSE_REMOVAL_VERSION = "2.0.0"


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter("always", AuthlibDeprecationWarning)


def deprecate(message, version=None, stacklevel=3):
    if version:
        message += f"\nIt will be compatible before version {version}."

    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=stacklevel)
