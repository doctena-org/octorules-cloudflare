"""Tests for the security.txt (RFC 9116) settings extension and provider methods."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_cloudflare._security_txt import (
    SecurityTxtChange,
    SecurityTxtPlan,
    _apply_security_txt,
    _finalize_security_txt,
    _validate_security_txt,
    canonicalize_expires,
    diff_security_txt,
    normalize_security_txt,
)
from octorules_cloudflare.provider import CloudflareProvider

SECTION = "cloudflare.security_txt"


def _scope():
    return Scope(zone_id="zone-1", label="example.com")


def _settings(**overrides):
    base = {
        "enabled": True,
        "contact": ["mailto:security@example.com"],
        "expires": "2033-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# canonicalize_expires
# ---------------------------------------------------------------------------
class TestCanonicalizeExpires:
    def test_z_suffix_string_is_already_canonical(self):
        assert canonicalize_expires("2033-01-01T00:00:00Z") == "2033-01-01T00:00:00Z"

    def test_offset_string_converts_to_utc(self):
        assert canonicalize_expires("2033-01-01T02:00:00+02:00") == "2033-01-01T00:00:00Z"

    def test_datetime_converts(self):
        dt = datetime(2033, 1, 1, tzinfo=timezone.utc)
        assert canonicalize_expires(dt) == "2033-01-01T00:00:00Z"

    def test_naive_datetime_is_treated_as_utc(self):
        assert canonicalize_expires(datetime(2033, 1, 1)) == "2033-01-01T00:00:00Z"

    def test_unparseable_string_returned_unchanged(self):
        assert canonicalize_expires("next year") == "next year"

    def test_non_string_returned_unchanged(self):
        assert canonicalize_expires(12345) == 12345


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_none_fields_are_dropped(self):
        raw = {"enabled": True, "contact": None, "hiring": None}
        assert normalize_security_txt(raw) == {"enabled": True}

    def test_expires_datetime_becomes_canonical_string(self):
        raw = {"expires": datetime(2033, 1, 1, tzinfo=timezone.utc)}
        assert normalize_security_txt(raw) == {"expires": "2033-01-01T00:00:00Z"}

    def test_list_entries_are_strings(self):
        raw = {"contact": ["mailto:a@example.com"]}
        assert normalize_security_txt(raw) == {"contact": ["mailto:a@example.com"]}

    def test_empty_input(self):
        assert normalize_security_txt({}) == {}


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_matching_settings_are_no_change(self):
        plan = diff_security_txt(_settings(), _settings())
        assert not plan.has_changes

    def test_unmentioned_current_fields_never_drive_a_diff(self):
        current = _settings(hiring=["https://example.com/jobs"])
        plan = diff_security_txt(current, {"enabled": True})
        assert not plan.has_changes

    def test_expires_compares_canonically_across_formats(self):
        current = _settings(expires="2033-01-01T00:00:00Z")
        desired = _settings(expires="2033-01-01T02:00:00+02:00")
        plan = diff_security_txt(current, desired)
        assert not plan.has_changes

    def test_unconfigured_zone_proposes_everything(self):
        plan = diff_security_txt({}, _settings())
        assert {c.field for c in plan.changes} == {"contact", "enabled", "expires"}

    def test_list_order_is_significant(self):
        current = _settings(contact=["mailto:a@example.com", "https://example.com/report"])
        desired = _settings(contact=["https://example.com/report", "mailto:a@example.com"])
        plan = diff_security_txt(current, desired)
        assert [c.field for c in plan.changes] == ["contact"]

    def test_plan_carries_full_current_state(self):
        current = _settings(hiring=["https://example.com/jobs"])
        plan = diff_security_txt(current, {"enabled": False})
        assert plan.current_settings == current


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_changes_land_in_extension_plans(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_security_txt(zp, {}, _scope(), MagicMock(), ({}, _settings()))
        assert SECTION in zp.extension_plans

    def test_no_changes_adds_nothing(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_security_txt(zp, {}, _scope(), MagicMock(), (_settings(), _settings()))
        assert zp.extension_plans == {}

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_security_txt(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_resends_unmanaged_current_fields(self):
        """The endpoint is a whole-object PUT: fields the zone file does not
        manage must ride along or the API would clear them."""
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_security_txt.return_value = {}
        current = _settings(hiring=["https://example.com/jobs"])
        plan = diff_security_txt(current, {"enabled": False})
        synced, error = _apply_security_txt(MagicMock(), [plan], _scope(), provider)
        assert error is None
        assert SECTION in synced
        payload = provider.update_security_txt.call_args[0][1]
        assert payload["enabled"] is False
        assert payload["hiring"] == ["https://example.com/jobs"]
        assert payload["contact"] == ["mailto:security@example.com"]

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        plan = SecurityTxtPlan(changes=[SecurityTxtChange("enabled", True, True)])
        synced, error = _apply_security_txt(MagicMock(), [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_security_txt.assert_not_called()

    def test_apply_verifies_by_rereading(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_security_txt.return_value = {}
        plan = diff_security_txt({}, _settings())
        _apply_security_txt(MagicMock(), [plan], _scope(), provider)
        provider.get_security_txt.assert_called_once()


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def _validate(self, settings):
        errors: list[str] = []
        lines: list[str] = []
        _validate_security_txt({SECTION: settings}, "zone", errors, lines)
        return errors, lines

    def test_valid_settings(self):
        errors, lines = self._validate(_settings())
        assert errors == []
        assert lines == []

    def test_unknown_field_rejected(self):
        errors, _ = self._validate(_settings(bogus=1))
        assert len(errors) == 1
        assert "bogus" in errors[0]

    def test_non_bool_enabled_rejected(self):
        errors, _ = self._validate(_settings(enabled="yes"))
        assert any("enabled" in e for e in errors)

    def test_non_list_contact_rejected(self):
        errors, _ = self._validate(_settings(contact="mailto:a@example.com"))
        assert any("contact must be a list" in e for e in errors)

    def test_bare_email_contact_rejected(self):
        errors, _ = self._validate(_settings(contact=["security@example.com"]))
        assert any("mailto" in e for e in errors)

    def test_enabled_without_contact_rejected(self):
        settings = _settings()
        del settings["contact"]
        errors, _ = self._validate(settings)
        assert any("contact" in e and "RFC 9116" in e for e in errors)

    def test_enabled_without_expires_rejected(self):
        settings = _settings()
        del settings["expires"]
        errors, _ = self._validate(settings)
        assert any("expires" in e and "RFC 9116" in e for e in errors)

    def test_disabled_without_contact_passes(self):
        errors, lines = self._validate({"enabled": False})
        assert errors == []
        assert lines == []

    def test_unparseable_expires_rejected(self):
        errors, _ = self._validate(_settings(expires="next year"))
        assert any("ISO-8601" in e for e in errors)

    def test_past_expires_warns(self):
        errors, lines = self._validate(_settings(expires="2020-01-01T00:00:00Z"))
        assert errors == []
        assert len(lines) == 1
        assert "in the past" in lines[0]

    def test_datetime_expires_accepted(self):
        errors, lines = self._validate(_settings(expires=datetime(2033, 1, 1)))
        assert errors == []
        assert lines == []

    def test_non_dict_section_is_ignored(self):
        errors: list[str] = []
        _validate_security_txt({SECTION: ["not", "a", "dict"]}, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderSecurityTxt:
    def _provider(self, mock_cf_client):
        return CloudflareProvider(client=mock_cf_client)

    def test_get_normalizes_response(self, mock_cf_client):
        mock_cf_client.security_txt.get.return_value = {
            "enabled": True,
            "contact": ["mailto:security@example.com"],
            "expires": datetime(2033, 1, 1, tzinfo=timezone.utc),
            "hiring": None,
        }
        provider = self._provider(mock_cf_client)
        result = provider.get_security_txt(_scope())
        assert result == {
            "contact": ["mailto:security@example.com"],
            "enabled": True,
            "expires": "2033-01-01T00:00:00Z",
        }
        mock_cf_client.security_txt.get.assert_called_once_with(zone_id="zone-1")

    def test_get_unconfigured_returns_empty(self, mock_cf_client):
        mock_cf_client.security_txt.get.return_value = None
        provider = self._provider(mock_cf_client)
        assert provider.get_security_txt(_scope()) == {}

    def test_update_passes_fields_as_kwargs(self, mock_cf_client):
        provider = self._provider(mock_cf_client)
        provider.update_security_txt(_scope(), _settings())
        mock_cf_client.security_txt.update.assert_called_once_with(zone_id="zone-1", **_settings())
