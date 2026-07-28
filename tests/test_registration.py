"""Tests that extension registration wires up correctly."""

from octorules.dumper import _clean_rule
from octorules.extensions import _format_extensions
from octorules.phases import get_api_fields

import octorules_cloudflare  # noqa: F401 — triggers __init__.py registration


def _plan_keys() -> set[str]:
    """Plan keys the provider exposes.

    Apply is reached through ``provider.extensions`` rather than a registry,
    so this asserts on what core actually walks.
    """
    from octorules_cloudflare.provider import CloudflareProvider

    inst = object.__new__(CloudflareProvider)
    return {e.plan_key() for e in CloudflareProvider.extensions.fget(inst)}


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
    assert "cloudflare.bot_management" in _format_extensions


def test_bot_management_apply_registered():
    assert "cloudflare.bot_management" in _plan_keys()


# --- URL normalization ---


def test_url_normalization_format_registered():
    assert "cloudflare.url_normalization_settings" in _format_extensions


def test_url_normalization_apply_registered():
    assert "cloudflare.url_normalization_settings" in _plan_keys()


# --- zone security ---


def test_zone_security_format_registered():
    assert "cloudflare.zone_security" in _format_extensions


def test_zone_security_apply_registered():
    assert "cloudflare.zone_security" in _plan_keys()


# --- leaked credential check ---


def test_leaked_credentials_format_registered():
    assert "cloudflare.leaked_credential_check" in _format_extensions


def test_leaked_credentials_apply_registered():
    assert "cloudflare.leaked_credential_check" in _plan_keys()


# --- content scanning ---


def test_content_scanning_format_registered():
    assert "cloudflare.content_scanning" in _format_extensions


def test_content_scanning_apply_registered():
    assert "cloudflare.content_scanning" in _plan_keys()
