import pytest

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.deprecate import deprecate


def test_deprecate_semver_version():
    with pytest.warns(AuthlibDeprecationWarning, match="2.0.0"):
        deprecate("message", version="2.0.0")


def test_deprecate_normalizes_short_version():
    with pytest.warns(AuthlibDeprecationWarning, match="1.8.0"):
        deprecate("message", version="1.8")

    with pytest.warns(AuthlibDeprecationWarning, match="2.0.0"):
        deprecate("message", version="2")


def test_deprecate_invalid_version():
    with pytest.raises(ValueError):
        deprecate("message", version="1.8-beta")


def test_deprecate_without_version():
    with pytest.warns(AuthlibDeprecationWarning, match="message"):
        deprecate("message")
