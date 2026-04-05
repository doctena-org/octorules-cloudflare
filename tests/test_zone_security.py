"""Tests for zone security settings extension and provider methods."""

from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare._zone_security import (
    ZoneSecurityChange,
    ZoneSecurityFormatter,
    ZoneSecurityPlan,
    _apply_zone_security,
    _dump_zone_security,
    _finalize_zone_security,
    _prefetch_zone_security,
    _validate_zone_security,
    diff_zone_security,
    normalize_zone_security,
)

from .mocks import MockRule


def _zs(zone_id: str = "zone-123", label: str = "example.com") -> Scope:
    return Scope(zone_id=zone_id, label=label)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_basic(self):
        raw = {
            "security_level": "high",
            "challenge_passage": 1800,
            "browser_integrity_check": "on",
        }
        result = normalize_zone_security(raw)
        assert result == raw

    def test_coerces_types(self):
        raw = {
            "security_level": 123,
            "challenge_passage": "3600",
            "browser_integrity_check": True,
        }
        result = normalize_zone_security(raw)
        assert result["security_level"] == "123"
        assert result["challenge_passage"] == 3600
        assert result["browser_integrity_check"] == "True"

    def test_empty(self):
        assert normalize_zone_security({}) == {}

    def test_none_values_skipped(self):
        raw = {"security_level": None, "challenge_passage": 300}
        result = normalize_zone_security(raw)
        assert "security_level" not in result
        assert result["challenge_passage"] == 300

    def test_partial(self):
        raw = {"security_level": "medium"}
        result = normalize_zone_security(raw)
        assert result == {"security_level": "medium"}


# ---------------------------------------------------------------------------
# Denormalize (normalize is idempotent — re-normalizing yields same output)
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_denormalize_full(self):
        """Normalized form with all 3 fields re-normalizes identically."""
        normalized = {
            "security_level": "high",
            "challenge_passage": 1800,
            "browser_integrity_check": "on",
        }
        assert normalize_zone_security(normalized) == normalized

    def test_denormalize_partial(self):
        """Normalized form with only 1 field re-normalizes identically."""
        normalized = {"challenge_passage": 3600}
        assert normalize_zone_security(normalized) == normalized

    def test_denormalize_empty(self):
        """Empty dict re-normalizes to empty dict."""
        assert normalize_zone_security({}) == {}


# ---------------------------------------------------------------------------
# Round-trip (raw API -> normalize -> re-normalize is stable)
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_round_trip(self):
        """normalize then re-normalize preserves data."""
        raw = {
            "security_level": 123,
            "challenge_passage": "3600",
            "browser_integrity_check": True,
        }
        first = normalize_zone_security(raw)
        second = normalize_zone_security(first)
        assert first == second


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffZoneSecurity:
    def test_no_changes(self):
        settings = {"security_level": "high", "challenge_passage": 1800}
        plan = diff_zone_security(settings, settings)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        current = {"security_level": "medium", "challenge_passage": 1800}
        desired = {"security_level": "high", "challenge_passage": 1800}
        plan = diff_zone_security(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "security_level"
        assert plan.changes[0].current == "medium"
        assert plan.changes[0].desired == "high"

    def test_partial_desired(self):
        current = {"security_level": "medium", "challenge_passage": 1800}
        desired = {"security_level": "high"}
        plan = diff_zone_security(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1

    def test_new_field(self):
        current = {"security_level": "medium"}
        desired = {"security_level": "medium", "browser_integrity_check": "on"}
        plan = diff_zone_security(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "browser_integrity_check"
        assert plan.changes[0].current is None
        assert plan.changes[0].desired == "on"

    def test_multiple_changes(self):
        current = {"challenge_passage": 300, "security_level": "low"}
        desired = {"challenge_passage": 3600, "security_level": "high"}
        plan = diff_zone_security(current, desired)
        assert plan.total_changes == 2


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = ZoneSecurityChange(field="security_level", current="low", desired="high")
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = ZoneSecurityChange(field="security_level", current="high", desired="high")
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "low", "high")])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = ZoneSecurityPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0

    def test_count_changes_mixed(self):
        """total_changes counts only changes where current != desired."""
        plan = ZoneSecurityPlan(
            changes=[
                ZoneSecurityChange("security_level", "low", "high"),  # changed
                ZoneSecurityChange("challenge_passage", 1800, 1800),  # unchanged
                ZoneSecurityChange("browser_integrity_check", "off", "on"),  # changed
            ]
        )
        assert plan.has_changes is True
        assert plan.total_changes == 2


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_zone_security({}, _zs(), MagicMock())
        assert result is None

    def test_fetches_settings(self):
        provider = MagicMock()
        provider.get_zone_security_settings.return_value = {
            "security_level": "high",
            "challenge_passage": 1800,
        }
        all_desired = {"cloudflare_zone_security": {"security_level": "medium"}}
        result = _prefetch_zone_security(all_desired, _zs(), provider)
        assert result is not None
        current, desired = result
        assert current["security_level"] == "high"
        assert desired["security_level"] == "medium"

    def test_api_failure_handled_gracefully(self):
        provider = MagicMock()
        provider.get_zone_security_settings.side_effect = ProviderError("API down")
        all_desired = {"cloudflare_zone_security": {"security_level": "high"}}
        result = _prefetch_zone_security(all_desired, _zs(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        provider = MagicMock()
        provider.get_zone_security_settings.side_effect = ProviderAuthError("forbidden")
        all_desired = {"cloudflare_zone_security": {"security_level": "high"}}
        with pytest.raises(ProviderAuthError):
            _prefetch_zone_security(all_desired, _zs(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"security_level": "low"}
        desired = {"security_level": "high"}
        ctx = (current, desired)

        _finalize_zone_security(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_zone_security" in zp.extension_plans
        plan = zp.extension_plans["cloudflare_zone_security"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"security_level": "high"}
        desired = {"security_level": "high"}
        ctx = (current, desired)

        _finalize_zone_security(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_zone_security" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_zone_security(zp, {}, _zs(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ZoneSecurityPlan(
            changes=[
                ZoneSecurityChange("security_level", "low", "high"),
                ZoneSecurityChange("challenge_passage", 300, 3600),
            ]
        )
        synced, error = _apply_zone_security(zp, [plan], _zs(), provider)
        assert error is None
        assert "cloudflare_zone_security" in synced
        provider.update_zone_security_settings.assert_called_once()
        call_args = provider.update_zone_security_settings.call_args
        payload = call_args[0][1]
        assert payload["security_level"] == "high"
        assert payload["challenge_passage"] == 3600

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "high", "high")])
        synced, error = _apply_zone_security(zp, [plan], _zs(), provider)
        assert synced == []
        assert error is None
        provider.update_zone_security_settings.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_zone_security(MagicMock(), [], _zs(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_settings(self):
        desired = {
            "cloudflare_zone_security": {
                "security_level": "high",
                "challenge_passage": 1800,
                "browser_integrity_check": "on",
            }
        }
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_security_level(self):
        desired = {"cloudflare_zone_security": {"security_level": "extreme"}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "security_level" in errors[0]
        assert "extreme" in errors[0]

    def test_invalid_challenge_passage_type(self):
        desired = {"cloudflare_zone_security": {"challenge_passage": "not_a_number"}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "challenge_passage" in errors[0]

    def test_invalid_challenge_passage_bool(self):
        desired = {"cloudflare_zone_security": {"challenge_passage": True}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "challenge_passage" in errors[0]

    def test_challenge_passage_too_low(self):
        desired = {"cloudflare_zone_security": {"challenge_passage": 100}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "300" in errors[0]

    def test_challenge_passage_too_high(self):
        desired = {"cloudflare_zone_security": {"challenge_passage": 100000}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "86400" in errors[0]

    def test_challenge_passage_boundary_valid(self):
        for val in (300, 86400):
            desired = {"cloudflare_zone_security": {"challenge_passage": val}}
            errors: list[str] = []
            _validate_zone_security(desired, "zone", errors, [])
            assert errors == [], f"Expected no errors for {val}"

    def test_invalid_browser_integrity_check(self):
        desired = {"cloudflare_zone_security": {"browser_integrity_check": "yes"}}
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "browser_integrity_check" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_zone_security({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_zone_security({"cloudflare_zone_security": "not-a-dict"}, "zone", errors, [])
        assert errors == []

    def test_multiple_errors(self):
        desired = {
            "cloudflare_zone_security": {
                "security_level": "extreme",
                "challenge_passage": 50,
                "browser_integrity_check": "yes",
            }
        }
        errors: list[str] = []
        _validate_zone_security(desired, "zone", errors, [])
        assert len(errors) == 3


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_settings(self):
        provider = MagicMock()
        provider.get_zone_security_settings.return_value = {
            "security_level": "high",
            "challenge_passage": 1800,
        }
        result = _dump_zone_security(_zs(), provider, None)
        assert "cloudflare_zone_security" in result
        assert result["cloudflare_zone_security"]["security_level"] == "high"

    def test_dump_api_failure(self):
        provider = MagicMock()
        provider.get_zone_security_settings.side_effect = ProviderError("down")
        result = _dump_zone_security(_zs(), provider, None)
        assert result is None

    def test_dump_empty_settings(self):
        provider = MagicMock()
        provider.get_zone_security_settings.return_value = {}
        result = _dump_zone_security(_zs(), provider, None)
        assert result is None

    def test_dump_auth_error_returns_none(self):
        """ProviderAuthError in dump degrades gracefully (returns None)."""
        provider = MagicMock()
        provider.get_zone_security_settings.side_effect = ProviderAuthError("forbidden")
        result = _dump_zone_security(_zs(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Format extension — format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(
            changes=[
                ZoneSecurityChange("security_level", "low", "high"),
                ZoneSecurityChange("challenge_passage", 300, 3600),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "zone_security.security_level" in lines[0]
        assert "'low'" in lines[0]
        assert "'high'" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "zone_security.challenge_passage" in lines[1]

    def test_skips_no_change(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "high", "high")])
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = ZoneSecurityFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "low", "high")])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]


# ---------------------------------------------------------------------------
# Format extension — format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(
            changes=[
                ZoneSecurityChange("security_level", "low", "high"),
                ZoneSecurityChange("challenge_passage", 300, 3600),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "security_level"

    def test_skips_no_change(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "high", "high")])
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = ZoneSecurityFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension — format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "low", "high")])
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "zone_security.security_level" in lines[0]

    def test_skips_no_change(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "high", "high")])
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_empty_plans(self):
        fmt = ZoneSecurityFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension — format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(
            changes=[
                ZoneSecurityChange("security_level", "low", "high"),
                ZoneSecurityChange("challenge_passage", 300, 3600),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "Modify" in html
        assert "zone_security.security_level" in html
        assert "&rarr;" in html

    def test_empty_plans(self):
        fmt = ZoneSecurityFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)

    def test_skips_no_change(self):
        """Plan with no actual changes returns (0,0,0,0)."""
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "high", "high")])
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Format extension — format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = ZoneSecurityFormatter()
        plan = ZoneSecurityPlan(changes=[ZoneSecurityChange("security_level", "low", "high")])
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "zone_security"
        assert entry["provider_id"] == "cloudflare_zone_security"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 1

    def test_no_drift(self):
        fmt = ZoneSecurityFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetZoneSecurity:
    def test_get_zone_security_settings(self, mock_cf_client):
        """get_zone_security_settings fetches 3 settings individually."""
        mock_cf_client.zones.settings.get.side_effect = [
            MockRule({"value": "high"}),
            MockRule({"value": 1800}),
            MockRule({"value": "on"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = _zs()
        result = provider.get_zone_security_settings(scope)
        assert result["security_level"] == "high"
        assert result["challenge_passage"] == 1800
        assert result["browser_integrity_check"] == "on"
        assert mock_cf_client.zones.settings.get.call_count == 3

    def test_get_zone_security_settings_skips_not_found(self, mock_cf_client):
        """Settings that return NotFoundError are skipped."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.zones.settings.get.side_effect = [
            MockRule({"value": "high"}),
            NotFoundError(message="Not found", response=mock_response, body=None),
            MockRule({"value": "on"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = _zs()
        result = provider.get_zone_security_settings(scope)
        assert result["security_level"] == "high"
        assert "challenge_passage" not in result
        assert result["browser_integrity_check"] == "on"

    def test_get_zone_security_settings_empty(self, mock_cf_client):
        """All settings NotFound returns empty dict."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.zones.settings.get.side_effect = NotFoundError(
            message="Not found", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_zone_security_settings(_zs())
        assert result == {}

    def test_get_zone_security_auth_error(self, mock_cf_client):
        """AuthenticationError wraps as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.zones.settings.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.get_zone_security_settings(_zs())


class TestProviderUpdateZoneSecurity:
    def test_update_zone_security_settings(self, mock_cf_client):
        """update_zone_security_settings calls edit for each setting."""
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = _zs()
        provider.update_zone_security_settings(
            scope, {"security_level": "high", "challenge_passage": 3600}
        )
        assert mock_cf_client.zones.settings.edit.call_count == 2

    def test_update_skips_unknown_keys(self, mock_cf_client):
        """Unknown keys are logged and skipped."""
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = _zs()
        provider.update_zone_security_settings(scope, {"unknown_setting": "value"})
        mock_cf_client.zones.settings.edit.assert_not_called()

    def test_update_auth_error(self, mock_cf_client):
        """AuthenticationError wraps as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.zones.settings.edit.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.update_zone_security_settings(_zs(), {"security_level": "high"})
