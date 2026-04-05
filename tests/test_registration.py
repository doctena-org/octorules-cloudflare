"""Tests that extension registration wires up correctly."""

from octorules.extensions import _apply_extensions, _format_extensions

import octorules_cloudflare  # noqa: F401 — triggers __init__.py registration

# --- bot management ---


def test_bot_management_format_registered():
    assert "cloudflare_bot_management" in _format_extensions


def test_bot_management_apply_registered():
    assert "cloudflare_bot_management" in _apply_extensions


# --- URL normalization ---


def test_url_normalization_format_registered():
    assert "cloudflare_url_normalization" in _format_extensions


def test_url_normalization_apply_registered():
    assert "cloudflare_url_normalization" in _apply_extensions


# --- zone security ---


def test_zone_security_format_registered():
    assert "cloudflare_zone_security" in _format_extensions


def test_zone_security_apply_registered():
    assert "cloudflare_zone_security" in _apply_extensions


# --- leaked credential check ---


def test_leaked_credentials_format_registered():
    assert "cloudflare_leaked_credential_check" in _format_extensions


def test_leaked_credentials_apply_registered():
    assert "cloudflare_leaked_credential_check" in _apply_extensions


# --- content scanning ---


def test_content_scanning_format_registered():
    assert "cloudflare_content_scanning" in _format_extensions


def test_content_scanning_apply_registered():
    assert "cloudflare_content_scanning" in _apply_extensions
