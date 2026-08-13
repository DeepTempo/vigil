"""Tests for the `default_on_error` decorator in core/exceptions.py.

It replaces 53 identical try/except bodies across eight modules, so the
behaviour it centralises — swallow, log, return the default — has to hold, and
mutable defaults must not be shared between calls.
"""

import pytest

from core.exceptions import default_on_error

pytestmark = pytest.mark.unit


def test_returns_value_when_no_error():
    @default_on_error(None)
    def ok(a, b=2):
        return a + b

    assert ok(1) == 3
    assert ok(1, b=10) == 11


@pytest.mark.parametrize("default", [None, False, 0])
def test_returns_scalar_default_on_error(default):
    @default_on_error(default)
    def boom():
        raise RuntimeError("nope")

    assert boom() is default or boom() == default


def test_factory_default_is_not_shared_between_calls():
    """The reason mutable defaults are passed as `list`/`dict`, not [] / {}."""

    @default_on_error(list)
    def boom():
        raise RuntimeError("nope")

    first = boom()
    assert first == []
    first.append("mutated by a caller")
    assert boom() == [], "second call saw the first call's mutation"


def test_dict_factory_default():
    @default_on_error(dict)
    def boom():
        raise RuntimeError("nope")

    assert boom() == {}


def test_error_is_logged_with_traceback(caplog):
    @default_on_error(None)
    def boom():
        raise RuntimeError("the real cause")

    with caplog.at_level("ERROR"):
        assert boom() is None

    assert "boom failed" in caplog.text
    assert "the real cause" in caplog.text  # traceback retained, not swallowed


def test_metadata_is_preserved():
    @default_on_error(None)
    def documented(x):
        """A docstring."""
        return x

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "A docstring."


def test_does_not_swallow_keyboard_interrupt():
    """BaseException must still propagate — only Exception is caught."""

    @default_on_error(None)
    def interrupted():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        interrupted()
