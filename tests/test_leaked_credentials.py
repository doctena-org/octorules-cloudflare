"""Tests for leaked credential check extension and provider methods."""

import logging
from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare._leaked_credentials import (
    LeakedCredentialChange,
    LeakedCredentialFormatter,
    LeakedCredentialPlan,
    _apply_leaked_credentials,
    _dump_leaked_credentials,
    _finalize_leaked_credentials,
    _normalize_detection,
    _normalize_detections,
    _prefetch_leaked_credentials,
    _validate_leaked_credentials,
    diff_leaked_credentials,
    normalize_leaked_credential_config,
)

from .mocks import MockRule


def _zs(zone_id: str = "zone-123", label: str = "example.com") -> Scope:
    return Scope(zone_id=zone_id, label=label)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_normalize_detection(self):
        det = {"id": "det-1", "username": "u_expr", "password": "p_expr", "extra": "field"}
        result = _normalize_detection(det)
        assert result == {"username": "u_expr", "password": "p_expr"}

    def test_normalize_detection_missing_fields(self):
        result = _normalize_detection({})
        assert result == {"username": "", "password": ""}

    def test_normalize_detections_sorts(self):
        dets = [
            {"username": "b_user", "password": "b_pass"},
            {"username": "a_user", "password": "a_pass"},
        ]
        result = _normalize_detections(dets)
        assert result[0]["username"] == "a_user"
        assert result[1]["username"] == "b_user"

    def test_normalize_config(self):
        result = normalize_leaked_credential_config(
            True,
            [{"id": "d1", "username": "u1", "password": "p1"}],
        )
        assert result["enabled"] is True
        assert len(result["detections"]) == 1
        assert result["detections"][0] == {"username": "u1", "password": "p1"}

    def test_normalize_config_no_detections(self):
        result = normalize_leaked_credential_config(False, [])
        assert result == {"enabled": False}

    def test_normalize_config_empty_detections(self):
        result = normalize_leaked_credential_config(True, [])
        assert result == {"enabled": True}


# ---------------------------------------------------------------------------
# Denormalize (normalize is idempotent — re-normalizing yields same output)
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_denormalize_config(self):
        """Normalized form with enabled + detections re-normalizes identically."""
        config = normalize_leaked_credential_config(True, [{"username": "u1", "password": "p1"}])
        # Re-normalize: feed back through the same pipeline
        second = normalize_leaked_credential_config(config["enabled"], config.get("detections", []))
        assert config == second

    def test_denormalize_partial(self):
        """Normalized form with only enabled re-normalizes identically."""
        config = normalize_leaked_credential_config(False, [])
        second = normalize_leaked_credential_config(config["enabled"], config.get("detections", []))
        assert config == second


# ---------------------------------------------------------------------------
# Round-trip (raw API -> normalize -> re-normalize is stable)
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_round_trip(self):
        """normalize then re-normalize preserves data across multiple detections."""
        first = normalize_leaked_credential_config(
            True,
            [
                {"id": "d2", "username": "b_user", "password": "b_pass", "extra": "x"},
                {"id": "d1", "username": "a_user", "password": "a_pass"},
            ],
        )
        second = normalize_leaked_credential_config(first["enabled"], first.get("detections", []))
        assert first == second
        # Verify sorting was applied
        assert first["detections"][0]["username"] == "a_user"


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffLeakedCredentials:
    def test_no_changes(self):
        config = {
            "enabled": True,
            "detections": [{"username": "u1", "password": "p1"}],
        }
        plan = diff_leaked_credentials(config, config)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_enabled_change(self):
        current = {"enabled": False}
        desired = {"enabled": True}
        plan = diff_leaked_credentials(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "enabled"
        assert plan.changes[0].current is False
        assert plan.changes[0].desired is True

    def test_detections_change(self):
        current = {
            "enabled": True,
            "detections": [{"username": "u1", "password": "p1"}],
        }
        desired = {
            "enabled": True,
            "detections": [
                {"username": "u1", "password": "p1"},
                {"username": "u2", "password": "p2"},
            ],
        }
        plan = diff_leaked_credentials(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "detections"

    def test_partial_desired_enabled_only(self):
        current = {
            "enabled": False,
            "detections": [{"username": "u1", "password": "p1"}],
        }
        desired = {"enabled": True}
        plan = diff_leaked_credentials(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "enabled"

    def test_both_changes(self):
        current = {
            "enabled": False,
            "detections": [{"username": "u1", "password": "old"}],
        }
        desired = {
            "enabled": True,
            "detections": [{"username": "u1", "password": "new"}],
        }
        plan = diff_leaked_credentials(current, desired)
        assert plan.total_changes == 2

    def test_detections_order_independent(self):
        """Detections are normalized and sorted, so order doesn't matter."""
        current = {
            "detections": [
                {"username": "b", "password": "bp"},
                {"username": "a", "password": "ap"},
            ]
        }
        desired = {
            "detections": [
                {"username": "a", "password": "ap"},
                {"username": "b", "password": "bp"},
            ]
        }
        plan = diff_leaked_credentials(current, desired)
        assert not plan.has_changes


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = LeakedCredentialChange(field="enabled", current=False, desired=True)
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = LeakedCredentialChange(field="enabled", current=True, desired=True)
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = LeakedCredentialPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_leaked_credentials({}, _zs(), MagicMock())
        assert result is None

    def test_fetches_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.return_value = {
            "enabled": True,
            "detections": [{"username": "u1", "password": "p1"}],
        }
        all_desired = {"cloudflare_leaked_credential_check": {"enabled": True}}
        result = _prefetch_leaked_credentials(all_desired, _zs(), provider)
        assert result is not None
        current, desired = result
        assert current["enabled"] is True
        assert desired["enabled"] is True

    def test_api_failure_handled_gracefully(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.side_effect = ProviderError("API down")
        all_desired = {"cloudflare_leaked_credential_check": {"enabled": True}}
        result = _prefetch_leaked_credentials(all_desired, _zs(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.side_effect = ProviderAuthError("forbidden")
        all_desired = {"cloudflare_leaked_credential_check": {"enabled": True}}
        with pytest.raises(ProviderAuthError):
            _prefetch_leaked_credentials(all_desired, _zs(), provider)


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

        _finalize_leaked_credentials(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_leaked_credential_check" in zp.extension_plans

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"enabled": True}
        desired = {"enabled": True}
        ctx = (current, desired)

        _finalize_leaked_credentials(zp, {}, _zs(), MagicMock(), ctx)
        assert "cloudflare_leaked_credential_check" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_leaked_credentials(zp, {}, _zs(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_enabled_change(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        synced, error = _apply_leaked_credentials(zp, [plan], _zs(), provider)
        assert error is None
        assert "cloudflare_leaked_credential_check:enabled" in synced
        provider.update_leaked_credential_check_enabled.assert_called_once_with(_zs(), True)

    def test_apply_detections_change(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        cur_dets = [{"username": "u1", "password": "old"}]
        des_dets = [{"username": "u1", "password": "new"}]
        plan = LeakedCredentialPlan(
            changes=[LeakedCredentialChange("detections", cur_dets, des_dets)]
        )
        synced, error = _apply_leaked_credentials(zp, [plan], _zs(), provider)
        assert error is None
        assert "cloudflare_leaked_credential_check:detections" in synced
        provider.sync_leaked_credential_detections.assert_called_once()

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", True, True)])
        synced, error = _apply_leaked_credentials(zp, [plan], _zs(), provider)
        assert synced == []
        assert error is None

    def test_empty_plans(self):
        synced, error = _apply_leaked_credentials(MagicMock(), [], _zs(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_config(self):
        desired = {
            "cloudflare_leaked_credential_check": {
                "enabled": True,
                "detections": [
                    {
                        "username": 'lookup_json_string(http.request.body.raw, "user")',
                        "password": 'lookup_json_string(http.request.body.raw, "pass")',
                    },
                ],
            }
        }
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_enabled(self):
        desired = {"cloudflare_leaked_credential_check": {"enabled": "yes"}}
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "enabled" in errors[0]

    def test_invalid_detections_not_list(self):
        desired = {"cloudflare_leaked_credential_check": {"detections": "not-a-list"}}
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "list" in errors[0]

    def test_invalid_detection_not_dict(self):
        desired = {"cloudflare_leaked_credential_check": {"detections": ["not-a-dict"]}}
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "dict" in errors[0]

    def test_invalid_detection_missing_username(self):
        desired = {"cloudflare_leaked_credential_check": {"detections": [{"password": "p_expr"}]}}
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "username" in errors[0]

    def test_invalid_detection_empty_password(self):
        desired = {
            "cloudflare_leaked_credential_check": {
                "detections": [{"username": "u_expr", "password": ""}]
            }
        }
        errors: list[str] = []
        _validate_leaked_credentials(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "password" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_leaked_credentials({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_leaked_credentials(
            {"cloudflare_leaked_credential_check": "not-a-dict"}, "zone", errors, []
        )
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.return_value = {
            "enabled": True,
            "detections": [{"username": "u1", "password": "p1"}],
        }
        result = _dump_leaked_credentials(_zs(), provider, None)
        assert "cloudflare_leaked_credential_check" in result

    def test_dump_api_failure(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.side_effect = ProviderError("down")
        result = _dump_leaked_credentials(_zs(), provider, None)
        assert result is None

    def test_dump_empty_config(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.return_value = {}
        result = _dump_leaked_credentials(_zs(), provider, None)
        assert result is None

    def test_dump_auth_error_returns_none(self):
        """ProviderAuthError in dump degrades gracefully (returns None)."""
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.side_effect = ProviderAuthError("forbidden")
        result = _dump_leaked_credentials(_zs(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Format extension — format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 1
        assert "leaked_credential_check.enabled" in lines[0]
        assert lines[0].startswith("  ~ ")

    def test_skips_no_change(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", True, True)])
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = LeakedCredentialFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]


# ---------------------------------------------------------------------------
# Format extension — format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert result[0]["changes"][0]["field"] == "enabled"

    def test_skips_no_change(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", True, True)])
        assert fmt.format_json([plan]) == []


# ---------------------------------------------------------------------------
# Format extension — format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert "leaked_credential_check.enabled" in lines[0]

    def test_empty_plans(self):
        fmt = LeakedCredentialFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension — format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 1, 0)
        html = "\n".join(lines)
        assert "Modify" in html
        assert "leaked_credential_check.enabled" in html

    def test_empty_plans(self):
        fmt = LeakedCredentialFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []


# ---------------------------------------------------------------------------
# Format extension — format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = LeakedCredentialFormatter()
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "leaked_credential_check"
        assert entry["provider_id"] == "cloudflare_leaked_credential_check"
        assert entry["status"] == "drifted"

    def test_no_drift(self):
        fmt = LeakedCredentialFormatter()
        result = fmt.format_report([], zone_has_drift=False, phases_data=[])
        assert result is False


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetLeakedCredentialCheck:
    def test_get_leaked_credential_check(self, mock_cf_client):
        """get_leaked_credential_check fetches enabled status + detections."""
        mock_cf_client.leaked_credential_checks.get.return_value = MockRule({"enabled": True})
        mock_cf_client.leaked_credential_checks.detections.list.return_value = [
            MockRule({"id": "d1", "username": "u1", "password": "p1"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_leaked_credential_check(_zs())
        assert result["enabled"] is True
        assert len(result["detections"]) == 1
        assert result["detections"][0] == {"username": "u1", "password": "p1"}

    def test_get_leaked_credential_check_disabled(self, mock_cf_client):
        """Disabled with no detections."""
        mock_cf_client.leaked_credential_checks.get.return_value = MockRule({"enabled": False})
        mock_cf_client.leaked_credential_checks.detections.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_leaked_credential_check(_zs())
        assert result["enabled"] is False
        assert "detections" not in result

    def test_get_auth_error(self, mock_cf_client):
        """AuthenticationError wraps as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.leaked_credential_checks.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.get_leaked_credential_check(_zs())


class TestProviderUpdateLeakedCredentialEnabled:
    def test_enable(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.update_leaked_credential_check_enabled(_zs(), True)
        mock_cf_client.leaked_credential_checks.create.assert_called_once_with(
            zone_id="zone-123", enabled=True
        )

    def test_disable(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.update_leaked_credential_check_enabled(_zs(), False)
        mock_cf_client.leaked_credential_checks.create.assert_called_once_with(
            zone_id="zone-123", enabled=False
        )


class TestProviderSyncLeakedCredentialDetections:
    def test_create_new_detection(self, mock_cf_client):
        """New detection is created when username not in current."""
        mock_cf_client.leaked_credential_checks.detections.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_leaked_credential_detections(
            _zs(),
            current=[],
            desired=[{"username": "u1", "password": "p1"}],
        )
        mock_cf_client.leaked_credential_checks.detections.create.assert_called_once_with(
            zone_id="zone-123", username="u1", password="p1"
        )

    def test_delete_removed_detection(self, mock_cf_client):
        """Detection not in desired is deleted."""
        mock_cf_client.leaked_credential_checks.detections.list.return_value = [
            MockRule({"id": "d1", "username": "u1", "password": "p1"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_leaked_credential_detections(
            _zs(),
            current=[{"username": "u1", "password": "p1"}],
            desired=[],
        )
        mock_cf_client.leaked_credential_checks.detections.delete.assert_called_once_with(
            "d1", zone_id="zone-123"
        )

    def test_update_changed_password(self, mock_cf_client):
        """Detection with changed password is updated."""
        mock_cf_client.leaked_credential_checks.detections.list.return_value = [
            MockRule({"id": "d1", "username": "u1", "password": "old"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_leaked_credential_detections(
            _zs(),
            current=[{"username": "u1", "password": "old"}],
            desired=[{"username": "u1", "password": "new"}],
        )
        mock_cf_client.leaked_credential_checks.detections.update.assert_called_once_with(
            "d1", zone_id="zone-123", username="u1", password="new"
        )

    def test_unchanged_detection_not_touched(self, mock_cf_client):
        """Unchanged detection is not updated or deleted."""
        mock_cf_client.leaked_credential_checks.detections.list.return_value = [
            MockRule({"id": "d1", "username": "u1", "password": "p1"}),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.sync_leaked_credential_detections(
            _zs(),
            current=[{"username": "u1", "password": "p1"}],
            desired=[{"username": "u1", "password": "p1"}],
        )
        mock_cf_client.leaked_credential_checks.detections.create.assert_not_called()
        mock_cf_client.leaked_credential_checks.detections.update.assert_not_called()
        mock_cf_client.leaked_credential_checks.detections.delete.assert_not_called()


class TestReadBackVerification:
    def test_enable_warns_when_toggle_does_not_take(self, caplog):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_leaked_credential_check.return_value = {"enabled": False}
        plan = LeakedCredentialPlan(changes=[LeakedCredentialChange("enabled", False, True)])
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            synced, error = _apply_leaked_credentials(
                MagicMock(), [plan], Scope(zone_id="z1", label="example.com"), provider
            )
        assert error is None
        assert "cloudflare_leaked_credential_check:enabled" in synced
        assert "enabled" in caplog.text
        assert "reads back" in caplog.text
