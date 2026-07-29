"""Email delivery module location tests."""

import importlib.util


def test_backend_email_service_is_the_canonical_module():
    from backend.services import email_service

    assert email_service.send_email.__module__ == "backend.services.email_service"
    assert hasattr(email_service, "ConsoleBackend")
    assert hasattr(email_service, "SMTPBackend")


def test_legacy_root_email_service_module_is_removed():
    assert importlib.util.find_spec("services.email_service") is None
