"""Tests for content scanning extension and provider methods."""

import logging
from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare._content_scanning import (
    ContentScanningChange,
    ContentScanningFormatter,
    ContentScanningPlan,
    _apply_content_scanning,
    _dump_content_scanning,
    _finalize_content_scanning,
    _normalize_expression,
    _normalize_expressions,
    _prefetch_content_scanning,
    _validate_content_scanning,
    diff_content_scanning,
    normalize_content_scanning_config,
)

from .mocks import MockRule


def _zs(zone_id: str = "zone-123", label: str = "example.com") -> Scope:
    return Scope(zone_id=zone_id, label=label)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_normalize_expression(self):
        expr = {
            "id": "e1",
            "payload": 'lookup_json_string(http.request.body.raw, "file")',
            "extra": "val",
        }
        result = _normalize_expression(expr)
        assert result == {"payload": 'lookup_json_string(http.request.body.raw, "file")'}

    def test_normalize_expression_missing_payload(self):
        result = _normalize_expression({})
        assert result == {"payload": ""}

    def test_normalize_expressions_sorts(self):
        exprs = [
            {"payload": "b_payload"},
            {"payload": "a_payload"},
        ]
        result = _normalize_expressions(exprs)
        assert result[0]["payload"] == "a_payload"
        assert result[1]["payload"] == "b_payload"

    def test_normalize_config(self):
        result = normalize_content_scanning_config(
            True,
            [{"id": "e1", "payload": "test_payload"}],
        )
        assert result["enabled"] is True
        assert len(result["custom_expressions"]) == 1
        assert result["custom_expressions"][0] == {"payload": "test_payload"}

    def test_normalize_config_no_expressions(self):
        result = normalize_content_scanning_config(False, [])
        assert result == {"enabled": False}


# ---------------------------------------------------------------------------
# Denormalize (normalize is idempotent — re-normalizing yields same output)
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_denormalize_config(self):
        """Normalized form with enabled + expressions re-normalizes identically."""
        config = normalize_content_scanning_config(True, [{"payload": "test_payload"}])
        second = normalize_content_scanning_config(
            config["enabled"], config.get("custom_expressions", [])
        )
        assert config == second

    def test_denormalize_partial(self):
        """Normalized form with only enabled re-normalizes identically."""
        config = normalize_content_scanning_config(False, [])
        second = normalize_content_scanning_config(
            config["enabled"], config.get("custom_expressions", [])
        )
        assert config == second


# ---------------------------------------------------------------------------
# Round-trip (raw API -> normalize -> re-normalize is stable)
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_round_trip(self):
        """normalize then re-normalize preserves data across multiple expressions."""
        first = normalize_content_scanning_config(
            True,
            [
                {"id": "e2", "payload": "b_payload", "extra": "x"},
                {"id": "e1", "payload": "a_payload"},
            ],
        )
        second = normalize_content_scanning_config(
            first["enabled"], first.get("custom_expressions", [])
        )
        assert first == second
        # Verify sorting was applied
        assert first["custom_expressions"][0]["payload"] == "a_payload"


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffContentScanning:
    def test_no_changes(self):
        config = {
            "enabled": True,
            "custom_expressions": [{"payload": "test"}],
        }
        plan = diff_content_scanning(config, config)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_enabled_change(self):
        current = {"enabled": False}
        desired = {"enabled": True}
        plan = diff_content_scanning(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "enabled"

    def test_expressions_change(self):
        current = {
            "enabled": True,
            "custom_expressions": [{"payload": "old"}],
        }
        desired = {
            "enabled": True,
            "custom_expressions": [{"payload": "new"}],
        }
        plan = diff_content_scanning(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "custom_expressions"

    def test_partial_desired(self):
        current = {
            "enabled": True,
            "custom_expressions": [{"payload": "test"}],
        }
        desired = {"enabled": False}
        plan = diff_content_scanning(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "enabled"

    def test_both_changes(self):
        current = {
            "enabled": False,
            "custom_expressions": [{"payload": "old"}],
        }
        desired = {
            "enabled": True,
            "custom_expressions": [{"payload": "new"}],
        }
        plan = diff_content_scanning(current, desired)
        assert plan.total_changes == 2

    def test_expressions_order_independent(self):
        """Expressions are normalized and sorted, so order doesn't matter."""
        current = {
            "custom_expressions": [
                {"payload": "b_payload"},
                {"payload": "a_payload"},
            ]
        }
        desired = {
            "custom_expressions": [
                {"payload": "a_payload"},
                {"payload": "b_payload"},
            ]
        }
        plan = diff_content_scanning(current, desired)
        assert not plan.has_changes


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = ContentScanningChange(field="enabled", current=False, desired=True)
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = ContentScanningChange(field="enabled", current=True, desired=True)
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = ContentScanningPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_content_scanning({}, _zs(), MagicMock())
        assert result is None

    def test_fetches_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.return_value = {
            "enabled": True,
            "custom_expressions": [{"payload": "test"}],
        }
        all_desired = {"cloudflare_content_scanning": {"enabled": True}}
        result = _prefetch_content_scanning(all_desired, _zs(), provider)
        assert result is not None
        current, desired = result
        assert current["enabled"] is True
        assert desired["enabled"] is True

    def test_api_failure_handled_gracefully(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.side_effect = ProviderError("API down")
        all_desired = {"cloudflare_content_scanning": {"enabled": True}}
        result = _prefetch_content_scanning(all_desired, _zs(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.side_effect = ProviderAuthError("forbidden")
        all_desired = {"cloudflare_content_scanning": {"enabled": True}}
        with pytest.raises(ProviderAuthError):
            _prefetch_content_scanning(all_desired, _zs(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"enabled": False}
        desired = {"enabled": True}
        ctx = (current, desired)

        _finalize_content_scanning(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_content_scanning" in zp.extension_plans

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"enabled": True}
        desired = {"enabled": True}
        ctx = (current, desired)

        _finalize_content_scanning(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_content_scanning" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_content_scanning(zp, {}, _zs(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_enabled_change(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        synced, error = _apply_content_scanning(zp, [plan], _zs(), provider)
        assert error is None
        assert "cloudflare_content_scanning:enabled" in synced
        provider.update_content_scanning_enabled.assert_called_once_with(_zs(), True)

    def test_apply_expressions_change(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        cur_exprs = [{"payload": "old"}]
        des_exprs = [{"payload": "new"}]
        plan = ContentScanningPlan(
            changes=[ContentScanningChange("custom_expressions", cur_exprs, des_exprs)]
        )
        synced, error = _apply_content_scanning(zp, [plan], _zs(), provider)
        assert error is None
        assert "cloudflare_content_scanning:custom_expressions" in synced
        provider.sync_content_scanning_expressions.assert_called_once()

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", True, True)])
        synced, error = _apply_content_scanning(zp, [plan], _zs(), provider)
        assert synced == []
        assert error is None

    def test_empty_plans(self):
        synced, error = _apply_content_scanning(MagicMock(), [], _zs(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_config(self):
        desired = {
            "cloudflare_content_scanning": {
                "enabled": True,
                "custom_expressions": [
                    {"payload": 'lookup_json_string(http.request.body.raw, "file")'}
                ],
            }
        }
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_enabled(self):
        desired = {"cloudflare_content_scanning": {"enabled": "yes"}}
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "enabled" in errors[0]

    def test_invalid_expressions_not_list(self):
        desired = {"cloudflare_content_scanning": {"custom_expressions": "not-a-list"}}
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "list" in errors[0]

    def test_invalid_expression_not_dict(self):
        desired = {"cloudflare_content_scanning": {"custom_expressions": ["not-a-dict"]}}
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "dict" in errors[0]

    def test_invalid_expression_missing_payload(self):
        desired = {
            "cloudflare_content_scanning": {"custom_expressions": [{"not_payload": "value"}]}
        }
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "payload" in errors[0]

    def test_invalid_expression_empty_payload(self):
        desired = {"cloudflare_content_scanning": {"custom_expressions": [{"payload": ""}]}}
        errors: list[str] = []
        _validate_content_scanning(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "payload" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_content_scanning({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_content_scanning(
            {"cloudflare_content_scanning": "not-a-dict"}, "zone", errors, []
        )
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.return_value = {
            "enabled": True,
            "custom_expressions": [{"payload": "test"}],
        }
        result = _dump_content_scanning(_zs(), provider, None)
        assert "cloudflare_content_scanning" in result

    def test_dump_api_failure(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.side_effect = ProviderError("down")
        result = _dump_content_scanning(_zs(), provider, None)
        assert result is None

    def test_dump_empty_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.return_value = {}
        result = _dump_content_scanning(_zs(), provider, None)
        assert result is None

    def test_dump_auth_error_returns_none(self):
        """ProviderAuthError in dump degrades gracefully (returns None)."""
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.side_effect = ProviderAuthError("forbidden")
        result = _dump_content_scanning(_zs(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Format extension — format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 1
        assert "content_scanning.enabled" in lines[0]
        assert lines[0].startswith("  ~ ")

    def test_skips_no_change(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", True, True)])
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = ContentScanningFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]


# ---------------------------------------------------------------------------
# Format extension — format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert result[0]["changes"][0]["field"] == "enabled"

    def test_skips_no_change(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", True, True)])
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = ContentScanningFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension — format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert "content_scanning.enabled" in lines[0]

    def test_empty_plans(self):
        fmt = ContentScanningFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension — format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 1, 0)
        html = "\n".join(lines)
        assert "Modify" in html
        assert "content_scanning.enabled" in html

    def test_empty_plans(self):
        fmt = ContentScanningFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []


# ---------------------------------------------------------------------------
# Format extension — format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = ContentScanningFormatter()
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "content_scanning"
        assert entry["provider_id"] == "cloudflare_content_scanning"
        assert entry["status"] == "drifted"

    def test_no_drift(self):
        fmt = ContentScanningFormatter()
        result = fmt.format_report([], zone_has_drift=False, phases_data=[])
        assert result is False


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetContentScanning:
    def test_get_content_scanning(self, mock_cf_client):
        """get_content_scanning fetches enabled status + expressions."""
        mock_cf_client.content_scanning.settings.get.return_value = MockRule({"value": "enabled"})
        mock_cf_client.content_scanning.payloads.list.return_value = [
            MockRule({"id": "e1", "payload": "test_payload"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_content_scanning(_zs())
        assert result["enabled"] is True
        assert len(result["custom_expressions"]) == 1
        assert result["custom_expressions"][0] == {"payload": "test_payload"}

    def test_get_content_scanning_disabled(self, mock_cf_client):
        """Disabled with no expressions."""
        mock_cf_client.content_scanning.settings.get.return_value = MockRule({"value": "disabled"})
        mock_cf_client.content_scanning.payloads.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_content_scanning(_zs())
        assert result["enabled"] is False
        assert "custom_expressions" not in result

    def test_get_content_scanning_enabled_bool(self, mock_cf_client):
        """Handles enabled as a boolean field."""
        mock_cf_client.content_scanning.settings.get.return_value = MockRule({"enabled": True})
        mock_cf_client.content_scanning.payloads.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_content_scanning(_zs())
        assert result["enabled"] is True

    def test_get_auth_error(self, mock_cf_client):
        """AuthenticationError wraps as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.content_scanning.settings.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.get_content_scanning(_zs())


class TestProviderUpdateContentScanningEnabled:
    def test_enable(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.update_content_scanning_enabled(_zs(), True)
        mock_cf_client.content_scanning.enable.assert_called_once_with(zone_id="zone-123")
        mock_cf_client.content_scanning.disable.assert_not_called()

    def test_disable(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.update_content_scanning_enabled(_zs(), False)
        mock_cf_client.content_scanning.disable.assert_called_once_with(zone_id="zone-123")
        mock_cf_client.content_scanning.enable.assert_not_called()


class TestProviderSyncContentScanningExpressions:
    def test_create_new_expression(self, mock_cf_client):
        """New expressions are created via bulk create."""
        mock_cf_client.content_scanning.payloads.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_content_scanning_expressions(
            _zs(),
            current=[],
            desired=[{"payload": "new_payload"}],
        )
        mock_cf_client.content_scanning.payloads.create.assert_called_once_with(
            zone_id="zone-123",
            body=[{"payload": "new_payload"}],
        )

    def test_delete_removed_expression(self, mock_cf_client):
        """Expression not in desired is deleted."""
        mock_cf_client.content_scanning.payloads.list.return_value = [
            MockRule({"id": "e1", "payload": "old_payload"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_content_scanning_expressions(
            _zs(),
            current=[{"payload": "old_payload"}],
            desired=[],
        )
        mock_cf_client.content_scanning.payloads.delete.assert_called_once_with(
            "e1", zone_id="zone-123"
        )

    def test_unchanged_expression_not_touched(self, mock_cf_client):
        """Unchanged expression is neither created nor deleted."""
        mock_cf_client.content_scanning.payloads.list.return_value = [
            MockRule({"id": "e1", "payload": "keep_me"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_content_scanning_expressions(
            _zs(),
            current=[{"payload": "keep_me"}],
            desired=[{"payload": "keep_me"}],
        )
        mock_cf_client.content_scanning.payloads.create.assert_not_called()
        mock_cf_client.content_scanning.payloads.delete.assert_not_called()

    def test_mixed_create_and_delete(self, mock_cf_client):
        """Simultaneous create and delete."""
        mock_cf_client.content_scanning.payloads.list.return_value = [
            MockRule({"id": "e1", "payload": "old"}),
            MockRule({"id": "e2", "payload": "keep"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_content_scanning_expressions(
            _zs(),
            current=[{"payload": "old"}, {"payload": "keep"}],
            desired=[{"payload": "keep"}, {"payload": "new"}],
        )
        # Old is deleted
        mock_cf_client.content_scanning.payloads.delete.assert_called_once_with(
            "e1", zone_id="zone-123"
        )
        # New is created
        mock_cf_client.content_scanning.payloads.create.assert_called_once_with(
            zone_id="zone-123",
            body=[{"payload": "new"}],
        )


class TestReadBackVerification:
    def test_enable_warns_when_toggle_does_not_take(self, caplog):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_content_scanning.return_value = {"enabled": False}
        plan = ContentScanningPlan(changes=[ContentScanningChange("enabled", False, True)])
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            synced, error = _apply_content_scanning(
                MagicMock(), [plan], Scope(zone_id="z1", label="example.com"), provider
            )
        assert error is None
        assert "cloudflare_content_scanning:enabled" in synced
        assert "enabled" in caplog.text
        assert "reads back" in caplog.text
