"""Tests that extension registration wires up correctly."""

from octorules.dumper import _clean_rule
from octorules.extensions import _apply_extensions, _format_extensions
from octorules.phases import get_api_fields

import octorules_cloudflare  # noqa: F401 — triggers __init__.py registration

# --- API field strip set ---


def test_logging_not_stripped_from_rule():
    # Regression: ``logging.enabled`` is user-controllable and Cloudflare's
    # PUT default is ``true``. Stripping it on dump → omitting it on sync
    # silently flips ``logging.enabled: false`` rules to ``true``, turning
    # quiet skip rules into firewall_event emitters and exploding Logpush
    # volume. See CHANGELOG 0.8.2.
    assert "logging" not in get_api_fields("rule")


def test_dump_roundtrip_preserves_logging_disabled():
    # End-to-end: a rule with ``logging.enabled: false`` must survive the
    # dump path. This is the field that, if dropped, would re-enable per-
    # match firewall_event emission on every sync.
    rule = {
        "ref": "skip-loud-rule",
        "logging": {"enabled": False},
        "expression": '(http.host ne "www.example.com")',
        "action": "skip",
        "action_parameters": {"ruleset": "current"},
    }
    cleaned = _clean_rule(rule, default_action=None)
    assert cleaned["logging"] == {"enabled": False}


def test_dump_roundtrip_preserves_logging_enabled():
    # Symmetry: ``logging.enabled: true`` also round-trips, so the YAML
    # remains an honest mirror of Cloudflare state.
    rule = {
        "ref": "rule-with-logging",
        "logging": {"enabled": True},
        "expression": "true",
        "action": "log",
    }
    cleaned = _clean_rule(rule, default_action=None)
    assert cleaned["logging"] == {"enabled": True}


def test_expected_rule_api_fields_only():
    # Pin the strip set so anyone adding a new entry has to think about
    # whether it's truly server-only or user-controllable (the bug pattern).
    assert get_api_fields("rule") == frozenset({"id", "version", "last_updated", "categories"})


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
