"""Tests for Cloudflare bot management settings normalization and extension hooks."""

import logging
from unittest.mock import MagicMock

from cloudflare import Cloudflare
from octorules.provider.base import Scope

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare._bot_management import (
    BotManagementChange,
    BotManagementFormatter,
    BotManagementPlan,
    _apply_bot_management,
    _dump_bot_management,
    _finalize_bot_management,
    _prefetch_bot_management,
    _validate_bot_management,
    denormalize_bot_management,
    diff_bot_management,
    normalize_bot_management,
)


def _scope(zone_id: str = "test-zone-id") -> Scope:
    return Scope(zone_id=zone_id, label="test-zone")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalizeBotManagement:
    def test_basic_fields(self):
        raw = {
            "fight_mode": True,
            "enable_js": False,
            "ai_bots_protection": "block",
            "suppress_session_score": False,
            "using_latest_model": True,
        }
        result = normalize_bot_management(raw)
        assert result["fight_mode"] is True
        assert result["enable_js"] is False
        assert result["ai_bots_protection"] == "block"
        assert result["suppress_session_score"] is False
        assert result["using_latest_model"] is True

    def test_empty(self):
        assert normalize_bot_management({}) == {}

    def test_none_values_skipped(self):
        raw = {"fight_mode": None, "enable_js": True}
        result = normalize_bot_management(raw)
        assert "fight_mode" not in result
        assert result["enable_js"] is True

    def test_partial_fields(self):
        raw = {"fight_mode": True, "ai_bots_protection": "disabled"}
        result = normalize_bot_management(raw)
        assert result == {"fight_mode": True, "ai_bots_protection": "disabled"}
        assert "enable_js" not in result

    def test_crawler_protection_preserved(self):
        raw = {"crawler_protection": "enabled", "fight_mode": True}
        result = normalize_bot_management(raw)
        assert result["crawler_protection"] == "enabled"

    def test_auto_update_model_preserved(self):
        raw = {"auto_update_model": True, "fight_mode": False}
        result = normalize_bot_management(raw)
        assert result["auto_update_model"] is True


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalizeBotManagement:
    def test_partial_update(self):
        """Only specified fields are included in the output."""
        settings = {"fight_mode": True}
        result = denormalize_bot_management(settings)
        assert result == {"fight_mode": True}
        assert "enable_js" not in result

    def test_excludes_using_latest_model(self):
        """using_latest_model is read-only and always excluded."""
        settings = {
            "fight_mode": True,
            "using_latest_model": True,
        }
        result = denormalize_bot_management(settings)
        assert "using_latest_model" not in result
        assert result == {"fight_mode": True}

    def test_all_writable_fields(self):
        settings = {
            "fight_mode": True,
            "enable_js": True,
            "ai_bots_protection": "block",
            "suppress_session_score": False,
        }
        result = denormalize_bot_management(settings)
        assert result == settings

    def test_crawler_protection_preserved(self):
        settings = {"crawler_protection": "enabled"}
        result = denormalize_bot_management(settings)
        assert result["crawler_protection"] == "enabled"

    def test_auto_update_model_preserved(self):
        settings = {"auto_update_model": True}
        result = denormalize_bot_management(settings)
        assert result["auto_update_model"] is True

    def test_empty(self):
        assert denormalize_bot_management({}) == {}


# ---------------------------------------------------------------------------
# Normalization round-trip
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_round_trip(self):
        raw = {
            "fight_mode": True,
            "enable_js": False,
            "ai_bots_protection": "block",
            "suppress_session_score": True,
        }
        normalized = normalize_bot_management(raw)
        denormalized = denormalize_bot_management(normalized)
        # All writable fields survive the round-trip
        assert denormalized["fight_mode"] is True
        assert denormalized["enable_js"] is False
        assert denormalized["ai_bots_protection"] == "block"
        assert denormalized["suppress_session_score"] is True

    def test_round_trip_with_read_only(self):
        """Read-only field is stripped during denormalization."""
        raw = {
            "fight_mode": True,
            "using_latest_model": True,
        }
        normalized = normalize_bot_management(raw)
        assert "using_latest_model" in normalized
        denormalized = denormalize_bot_management(normalized)
        assert "using_latest_model" not in denormalized

    def test_round_trip_crawler_protection_and_auto_update_model(self):
        """crawler_protection and auto_update_model survive normalize/denormalize."""
        raw = {
            "fight_mode": True,
            "crawler_protection": "enabled",
            "auto_update_model": False,
        }
        normalized = normalize_bot_management(raw)
        assert normalized["crawler_protection"] == "enabled"
        assert normalized["auto_update_model"] is False
        denormalized = denormalize_bot_management(normalized)
        assert denormalized["crawler_protection"] == "enabled"
        assert denormalized["auto_update_model"] is False


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffBotManagement:
    def test_no_changes(self):
        settings = {"fight_mode": True, "enable_js": False}
        plan = diff_bot_management(settings, settings)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        current = {"fight_mode": False, "enable_js": True}
        desired = {"fight_mode": True, "enable_js": True}
        plan = diff_bot_management(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "fight_mode"
        assert plan.changes[0].current is False
        assert plan.changes[0].desired is True

    def test_partial_desired(self):
        """Only keys present in desired produce changes."""
        current = {"fight_mode": False, "enable_js": True, "ai_bots_protection": "block"}
        desired = {"fight_mode": True}
        plan = diff_bot_management(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "fight_mode"

    def test_new_field_is_unsupported(self):
        """A field absent from a non-empty live response is plan/product
        gated — it becomes an `unsupported` note, never a phantom Modify
        that apply could never close."""
        current = {"fight_mode": True}
        desired = {"fight_mode": True, "ai_bots_protection": "block"}
        plan = diff_bot_management(current, desired)
        assert not plan.has_changes
        assert plan.changes == []
        assert plan.unsupported == ["ai_bots_protection"]

    def test_multiple_changes(self):
        current = {"enable_js": False, "fight_mode": False}
        desired = {"enable_js": True, "fight_mode": True}
        plan = diff_bot_management(current, desired)
        assert plan.total_changes == 2


class TestUnsupportedFields:
    """Fields declared in YAML that the zone's live config never returns."""

    def test_phantom_modify_suppressed(self):
        # A zone running Super Bot Fight Mode never returns fight_mode;
        # `fight_mode: false` in YAML used to plan as `None -> False` on
        # every run, a Modify the update call could never make converge.
        current = {"enable_js": False, "ai_bots_protection": "disabled"}
        desired = {"fight_mode": False, "enable_js": False}
        plan = diff_bot_management(current, desired)
        assert not plan.has_changes
        assert plan.unsupported == ["fight_mode"]

    def test_truthy_desired_is_also_unsupported(self):
        # Even a truthy value can't converge if the zone doesn't expose
        # the field — it must surface as a note, not a perpetual Modify.
        current = {"enable_js": False}
        desired = {"fight_mode": True, "enable_js": True}
        plan = diff_bot_management(current, desired)
        assert plan.total_changes == 1
        assert plan.changes[0].field == "enable_js"
        assert plan.unsupported == ["fight_mode"]

    def test_empty_current_keeps_legacy_diff(self):
        # An empty live read (fetch failure) means field support is
        # unknown: everything stays diffable so apply can recover.
        desired = {"fight_mode": False, "enable_js": True}
        plan = diff_bot_management({}, desired)
        assert plan.total_changes == 2
        assert plan.unsupported == []

    def test_finalize_appends_plan_for_unsupported_only(self):
        zp = MagicMock()
        zp.extension_plans = {}
        current = {"enable_js": False}
        desired = {"fight_mode": False, "enable_js": False}
        _finalize_bot_management(zp, {}, _scope(), MagicMock(), (current, desired))
        plan = zp.extension_plans["cloudflare_bot_management"][0]
        assert not plan.has_changes
        assert plan.unsupported == ["fight_mode"]

    def test_finalize_warns_for_unsupported(self, caplog):
        # Plan output only renders zones with actual changes, so the
        # warning is the guaranteed signal for notes-only zones.
        zp = MagicMock()
        zp.extension_plans = {}
        current = {"enable_js": False}
        desired = {"fight_mode": False, "enable_js": False}
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            _finalize_bot_management(zp, {}, _scope(), MagicMock(), (current, desired))
        assert "fight_mode" in caplog.text
        assert "not exposed on zone" in caplog.text

    def test_format_text_renders_note(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[], unsupported=["fight_mode"])
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 1
        assert "fight_mode" in lines[0]
        assert "not exposed" in lines[0]
        assert "~" not in lines[0]

    def test_format_markdown_renders_note(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[], unsupported=["fight_mode"])
        lines = fmt.format_markdown([plan], [])
        assert len(lines) == 1
        assert "not exposed on this zone" in lines[0]

    def test_format_json_includes_unsupported(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(
            changes=[BotManagementChange("enable_js", False, True)],
            unsupported=["fight_mode"],
        )
        result = fmt.format_json([plan])
        assert result == [
            {
                "changes": [{"field": "enable_js", "current": False, "desired": True}],
                "unsupported": ["fight_mode"],
            }
        ]

    def test_read_only_field_mismatch_is_not_a_change(self):
        # using_latest_model is returned by the API but excluded from the
        # PATCH body (read-only), so diffing it would plan a Modify that
        # apply can never make converge — e.g. when Cloudflare ships a new
        # detection model and the zone briefly reports False.
        current = {"using_latest_model": False, "enable_js": False}
        desired = {"using_latest_model": True, "enable_js": False}
        plan = diff_bot_management(current, desired)
        assert not plan.has_changes
        assert plan.unsupported == []

    def test_format_html_renders_note(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[], unsupported=["fight_mode"])
        lines: list[str] = []
        _adds, _removes, modifies, _others = fmt.format_html([plan], lines)
        assert modifies == 0
        html = "\n".join(lines)
        assert "<td>Note</td>" in html
        assert "bot_management.fight_mode" in html
        assert "not exposed on this zone" in html

    def test_format_report_unsupported_is_not_drift(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[], unsupported=["fight_mode"])
        phases_data: list = []
        drift = fmt.format_report([plan], False, phases_data)
        assert drift is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = BotManagementChange(field="fight_mode", current=False, desired=True)
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = BotManagementChange(field="fight_mode", current=True, desired=True)
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = BotManagementPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_bot_management({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_settings(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.return_value = {
            "fight_mode": True,
            "enable_js": False,
        }
        all_desired = {"cloudflare_bot_management": {"fight_mode": False}}
        result = _prefetch_bot_management(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert current["fight_mode"] is True
        assert desired["fight_mode"] is False

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.side_effect = ProviderError("API down")
        all_desired = {"cloudflare_bot_management": {"fight_mode": True}}
        result = _prefetch_bot_management(all_desired, _scope(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.side_effect = ProviderAuthError("forbidden")
        all_desired = {"cloudflare_bot_management": {"fight_mode": True}}
        with pytest.raises(ProviderAuthError):
            _prefetch_bot_management(all_desired, _scope(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"fight_mode": False, "enable_js": True}
        desired = {"fight_mode": True}
        ctx = (current, desired)

        _finalize_bot_management(zp, {}, _scope(), MagicMock(), ctx)
        assert "cloudflare_bot_management" in zp.extension_plans
        plan = zp.extension_plans["cloudflare_bot_management"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"fight_mode": True}
        desired = {"fight_mode": True}
        ctx = (current, desired)

        _finalize_bot_management(zp, {}, _scope(), MagicMock(), ctx)
        assert "cloudflare_bot_management" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_bot_management(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = BotManagementPlan(
            changes=[
                BotManagementChange("fight_mode", False, True),
                BotManagementChange("ai_bots_protection", "disabled", "block"),
            ]
        )
        synced, error = _apply_bot_management(zp, [plan], _scope(), provider)
        assert error is None
        assert "cloudflare_bot_management" in synced
        provider.update_bot_management.assert_called_once()
        call_args = provider.update_bot_management.call_args
        payload = call_args[0][1]
        assert payload["fight_mode"] is True
        assert payload["ai_bots_protection"] == "block"

    def test_apply_warns_when_value_does_not_take(self, caplog):
        provider = MagicMock(spec=CloudflareProvider)
        # Cloudflare "accepted" the update but the value did not stick.
        provider.get_bot_management.return_value = {"fight_mode": False}
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            synced, error = _apply_bot_management(MagicMock(), [plan], _scope(), provider)
        assert error is None
        assert synced == ["cloudflare_bot_management"]
        provider.get_bot_management.assert_called_once()
        assert "fight_mode" in caplog.text
        assert "reads back" in caplog.text

    def test_apply_no_warning_when_value_takes(self, caplog):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.return_value = {"fight_mode": True}
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            _apply_bot_management(MagicMock(), [plan], _scope(), provider)
        assert caplog.text == ""

    def test_apply_read_back_failure_does_not_fail_apply(self, caplog):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.side_effect = ProviderError("boom")
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare._settings_common"):
            synced, error = _apply_bot_management(MagicMock(), [plan], _scope(), provider)
        assert error is None
        assert synced == ["cloudflare_bot_management"]
        assert "skipping verification" in caplog.text

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        synced, error = _apply_bot_management(zp, [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_bot_management.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_bot_management(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_settings(self):
        desired = {
            "cloudflare_bot_management": {
                "fight_mode": True,
                "enable_js": False,
                "ai_bots_protection": "block",
                "suppress_session_score": False,
            }
        }
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_ai_bots_protection(self):
        desired = {"cloudflare_bot_management": {"ai_bots_protection": "allow"}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "ai_bots_protection" in errors[0]
        assert "allow" in errors[0]

    def test_invalid_bool_field(self):
        desired = {"cloudflare_bot_management": {"fight_mode": "yes"}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "fight_mode" in errors[0]
        assert "boolean" in errors[0]

    def test_invalid_multiple_bool_fields(self):
        desired = {
            "cloudflare_bot_management": {
                "fight_mode": "yes",
                "enable_js": 1,
                "suppress_session_score": "no",
            }
        }
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 3

    def test_validate_invalid_crawler_protection(self):
        desired = {"cloudflare_bot_management": {"crawler_protection": "bogus"}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "crawler_protection" in errors[0]
        assert "'bogus'" in errors[0]

    def test_validate_valid_crawler_protection(self):
        desired = {"cloudflare_bot_management": {"crawler_protection": "enabled"}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert errors == []

    def test_validate_invalid_auto_update_model(self):
        desired = {"cloudflare_bot_management": {"auto_update_model": "yes"}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "auto_update_model" in errors[0]
        assert "boolean" in errors[0]

    def test_read_only_field_rejected(self):
        desired = {"cloudflare_bot_management": {"using_latest_model": True}}
        errors: list[str] = []
        _validate_bot_management(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "read-only" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_bot_management({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_bot_management({"cloudflare_bot_management": "not-a-dict"}, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_settings(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.return_value = {
            "fight_mode": True,
            "enable_js": False,
            "ai_bots_protection": "block",
        }
        result = _dump_bot_management(_scope(), provider, None)
        assert "cloudflare_bot_management" in result
        assert result["cloudflare_bot_management"]["fight_mode"] is True

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.side_effect = ProviderError("down")
        result = _dump_bot_management(_scope(), provider, None)
        assert result is None

    def test_dump_empty_settings(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.return_value = {}
        result = _dump_bot_management(_scope(), provider, None)
        assert result is None

    def test_dump_auth_error_returns_none(self):
        """ProviderAuthError in dump degrades gracefully (returns None)."""
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_bot_management.side_effect = ProviderAuthError("forbidden")
        result = _dump_bot_management(_scope(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Format extension -- format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(
            changes=[
                BotManagementChange("fight_mode", False, True),
                BotManagementChange("ai_bots_protection", "disabled", "block"),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "bot_management.fight_mode" in lines[0]
        assert "False" in lines[0]
        assert "True" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "bot_management.ai_bots_protection" in lines[1]

    def test_skips_no_change(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = BotManagementFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]
        assert "bot_management.fight_mode" in lines[0]


# ---------------------------------------------------------------------------
# Format extension -- format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(
            changes=[
                BotManagementChange("fight_mode", False, True),
                BotManagementChange("ai_bots_protection", "disabled", "block"),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "fight_mode"
        assert changes[0]["current"] is False
        assert changes[0]["desired"] is True
        assert changes[1]["field"] == "ai_bots_protection"
        assert changes[1]["current"] == "disabled"
        assert changes[1]["desired"] == "block"

    def test_skips_no_change(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = BotManagementFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", False, True)])
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "bot_management.fight_mode" in lines[0]

    def test_skips_no_change(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_empty_plans(self):
        fmt = BotManagementFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(
            changes=[
                BotManagementChange("fight_mode", False, True),
                BotManagementChange("ai_bots_protection", "disabled", "block"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "bot_management.fight_mode" in html
        assert "bot_management.ai_bots_protection" in html
        assert "&rarr;" in html
        assert "Updates=2" in html

    def test_skips_no_change(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_empty_plans(self):
        fmt = BotManagementFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_escapes_special_chars(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", "<script>", True)])
        lines: list[str] = []
        fmt.format_html([plan], lines)
        html = "\n".join(lines)
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.replace("&lt;script&gt;", "")


# ---------------------------------------------------------------------------
# Format extension -- format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(
            changes=[
                BotManagementChange("fight_mode", False, True),
                BotManagementChange("ai_bots_protection", "disabled", "block"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "bot_management"
        assert entry["provider_id"] == "cloudflare_bot_management"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 2
        assert entry["adds"] == 0
        assert entry["removes"] == 0

    def test_preserves_incoming_drift(self):
        fmt = BotManagementFormatter()
        plan = BotManagementPlan(changes=[BotManagementChange("fight_mode", True, True)])
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []

    def test_no_drift(self):
        fmt = BotManagementFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetBotManagement:
    def test_get_bot_management(self):
        from octorules_cloudflare.provider import CloudflareProvider

        mock_client = MagicMock(spec=Cloudflare)
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "fight_mode": True,
            "enable_js": False,
            "ai_bots_protection": "block",
            "suppress_session_score": False,
            "using_latest_model": True,
        }
        mock_client.bot_management.get.return_value = mock_result
        provider = CloudflareProvider(client=mock_client)
        scope = _scope()
        result = provider.get_bot_management(scope)
        assert result["fight_mode"] is True
        assert result["enable_js"] is False
        assert result["ai_bots_protection"] == "block"
        mock_client.bot_management.get.assert_called_once_with(zone_id="test-zone-id")


class TestProviderUpdateBotManagement:
    def test_update_bot_management(self):
        from octorules_cloudflare.provider import CloudflareProvider

        mock_client = MagicMock(spec=Cloudflare)
        provider = CloudflareProvider(client=mock_client)
        scope = _scope()
        provider.update_bot_management(scope, {"fight_mode": True, "enable_js": False})
        mock_client.bot_management.update.assert_called_once_with(
            zone_id="test-zone-id",
            fight_mode=True,
            enable_js=False,
        )
