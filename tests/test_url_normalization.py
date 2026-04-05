"""Tests for Cloudflare URL normalization settings and extension hooks."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_cloudflare._url_normalization import (
    UrlNormalizationChange,
    UrlNormalizationFormatter,
    UrlNormalizationPlan,
    _apply_url_normalization,
    _dump_url_normalization,
    _finalize_url_normalization,
    _prefetch_url_normalization,
    _validate_url_normalization,
    denormalize_url_normalization,
    diff_url_normalization,
    normalize_url_normalization,
)


def _scope(zone_id: str = "test-zone-id") -> Scope:
    return Scope(zone_id=zone_id, label="test-zone")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalizeUrlNormalization:
    def test_basic_fields(self):
        raw = {"scope": "incoming", "type": "cloudflare"}
        result = normalize_url_normalization(raw)
        assert result["scope"] == "incoming"
        assert result["type"] == "cloudflare"

    def test_empty(self):
        assert normalize_url_normalization({}) == {}

    def test_none_values_skipped(self):
        raw = {"scope": None, "type": "rfc3986"}
        result = normalize_url_normalization(raw)
        assert "scope" not in result
        assert result["type"] == "rfc3986"

    def test_partial_fields(self):
        raw = {"scope": "both"}
        result = normalize_url_normalization(raw)
        assert result == {"scope": "both"}
        assert "type" not in result


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalizeUrlNormalization:
    def test_partial_update(self):
        settings = {"scope": "both"}
        result = denormalize_url_normalization(settings)
        assert result == {"scope": "both"}
        assert "type" not in result

    def test_all_fields(self):
        settings = {"scope": "incoming", "type": "cloudflare"}
        result = denormalize_url_normalization(settings)
        assert result == {"scope": "incoming", "type": "cloudflare"}

    def test_empty(self):
        assert denormalize_url_normalization({}) == {}


# ---------------------------------------------------------------------------
# Normalization round-trip
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_round_trip(self):
        raw = {"scope": "incoming", "type": "cloudflare"}
        normalized = normalize_url_normalization(raw)
        denormalized = denormalize_url_normalization(normalized)
        assert denormalized == raw

    def test_round_trip_partial(self):
        raw = {"type": "rfc3986"}
        normalized = normalize_url_normalization(raw)
        denormalized = denormalize_url_normalization(normalized)
        assert denormalized == raw


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffUrlNormalization:
    def test_no_changes(self):
        settings = {"scope": "incoming", "type": "cloudflare"}
        plan = diff_url_normalization(settings, settings)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        current = {"scope": "incoming", "type": "cloudflare"}
        desired = {"scope": "both", "type": "cloudflare"}
        plan = diff_url_normalization(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "scope"
        assert plan.changes[0].current == "incoming"
        assert plan.changes[0].desired == "both"

    def test_partial_desired(self):
        current = {"scope": "incoming", "type": "cloudflare"}
        desired = {"type": "rfc3986"}
        plan = diff_url_normalization(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "type"

    def test_new_field(self):
        current = {"scope": "incoming"}
        desired = {"scope": "incoming", "type": "rfc3986"}
        plan = diff_url_normalization(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "type"
        assert plan.changes[0].current is None
        assert plan.changes[0].desired == "rfc3986"

    def test_multiple_changes(self):
        current = {"scope": "incoming", "type": "cloudflare"}
        desired = {"scope": "both", "type": "rfc3986"}
        plan = diff_url_normalization(current, desired)
        assert plan.total_changes == 2


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = UrlNormalizationChange(field="scope", current="incoming", desired="both")
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = UrlNormalizationChange(field="scope", current="incoming", desired="incoming")
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = UrlNormalizationPlan(changes=[UrlNormalizationChange("scope", "incoming", "both")])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = UrlNormalizationPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_url_normalization({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_settings(self):
        provider = MagicMock()
        provider.get_url_normalization.return_value = {
            "scope": "incoming",
            "type": "cloudflare",
        }
        all_desired = {"cloudflare_url_normalization": {"scope": "both"}}
        result = _prefetch_url_normalization(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert current["scope"] == "incoming"
        assert desired["scope"] == "both"

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_url_normalization.side_effect = ProviderError("API down")
        all_desired = {"cloudflare_url_normalization": {"scope": "both"}}
        result = _prefetch_url_normalization(all_desired, _scope(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_url_normalization.side_effect = ProviderAuthError("forbidden")
        all_desired = {"cloudflare_url_normalization": {"scope": "both"}}
        with pytest.raises(ProviderAuthError):
            _prefetch_url_normalization(all_desired, _scope(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"scope": "incoming", "type": "cloudflare"}
        desired = {"scope": "both"}
        ctx = (current, desired)

        _finalize_url_normalization(zp, {}, _scope(), MagicMock(), ctx)
        assert "cloudflare_url_normalization" in zp.extension_plans
        plan = zp.extension_plans["cloudflare_url_normalization"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"scope": "incoming"}
        desired = {"scope": "incoming"}
        ctx = (current, desired)

        _finalize_url_normalization(zp, {}, _scope(), MagicMock(), ctx)
        assert "cloudflare_url_normalization" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_url_normalization(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "rfc3986"),
            ]
        )
        synced, error = _apply_url_normalization(zp, [plan], _scope(), provider)
        assert error is None
        assert "cloudflare_url_normalization" in synced
        provider.update_url_normalization.assert_called_once()
        call_args = provider.update_url_normalization.call_args
        payload = call_args[0][1]
        assert payload["scope"] == "both"
        assert payload["type"] == "rfc3986"

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        synced, error = _apply_url_normalization(zp, [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_url_normalization.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_url_normalization(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_settings(self):
        desired = {
            "cloudflare_url_normalization": {
                "scope": "incoming",
                "type": "cloudflare",
            }
        }
        errors: list[str] = []
        _validate_url_normalization(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_scope(self):
        desired = {"cloudflare_url_normalization": {"scope": "outgoing"}}
        errors: list[str] = []
        _validate_url_normalization(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "scope" in errors[0]
        assert "outgoing" in errors[0]

    def test_invalid_type(self):
        desired = {"cloudflare_url_normalization": {"type": "custom"}}
        errors: list[str] = []
        _validate_url_normalization(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "type" in errors[0]
        assert "custom" in errors[0]

    def test_multiple_errors(self):
        desired = {
            "cloudflare_url_normalization": {
                "scope": "outgoing",
                "type": "custom",
            }
        }
        errors: list[str] = []
        _validate_url_normalization(desired, "zone", errors, [])
        assert len(errors) == 2

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_url_normalization({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_url_normalization(
            {"cloudflare_url_normalization": "not-a-dict"}, "zone", errors, []
        )
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_settings(self):
        provider = MagicMock()
        provider.get_url_normalization.return_value = {
            "scope": "incoming",
            "type": "cloudflare",
        }
        result = _dump_url_normalization(_scope(), provider, None)
        assert "cloudflare_url_normalization" in result
        assert result["cloudflare_url_normalization"]["scope"] == "incoming"

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_url_normalization.side_effect = ProviderError("down")
        result = _dump_url_normalization(_scope(), provider, None)
        assert result is None

    def test_dump_empty_settings(self):
        provider = MagicMock()
        provider.get_url_normalization.return_value = {}
        result = _dump_url_normalization(_scope(), provider, None)
        assert result is None

    def test_dump_auth_error_returns_none(self):
        """ProviderAuthError in dump degrades gracefully (returns None)."""
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_url_normalization.side_effect = ProviderAuthError("forbidden")
        result = _dump_url_normalization(_scope(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Format extension -- format_plan and count_changes
# ---------------------------------------------------------------------------
class TestFormatPlanAndCount:
    def test_format_plan(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(changes=[UrlNormalizationChange("scope", "incoming", "both")])
        lines = fmt.format_plan([plan], "my-zone")
        assert len(lines) == 1
        assert "my-zone" in lines[0]
        assert "incoming" in lines[0]
        assert "both" in lines[0]

    def test_count_changes(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "cloudflare"),  # no change
            ]
        )
        assert fmt.count_changes([plan]) == 1

    def test_empty(self):
        fmt = UrlNormalizationFormatter()
        assert fmt.format_plan([], "z") == []
        assert fmt.count_changes([]) == 0


# ---------------------------------------------------------------------------
# Format extension -- format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "rfc3986"),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "url_normalization.scope" in lines[0]
        assert "'incoming'" in lines[0]
        assert "'both'" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "url_normalization.type" in lines[1]

    def test_skips_no_change(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = UrlNormalizationFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(changes=[UrlNormalizationChange("scope", "incoming", "both")])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]
        assert "url_normalization.scope" in lines[0]


# ---------------------------------------------------------------------------
# Format extension -- format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "rfc3986"),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "scope"
        assert changes[0]["current"] == "incoming"
        assert changes[0]["desired"] == "both"
        assert changes[1]["field"] == "type"
        assert changes[1]["current"] == "cloudflare"
        assert changes[1]["desired"] == "rfc3986"

    def test_skips_no_change(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = UrlNormalizationFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(changes=[UrlNormalizationChange("scope", "incoming", "both")])
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "url_normalization.scope" in lines[0]

    def test_skips_no_change(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_empty_plans(self):
        fmt = UrlNormalizationFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "rfc3986"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "url_normalization.scope" in html
        assert "url_normalization.type" in html
        assert "&rarr;" in html
        assert "Updates=2" in html

    def test_skips_no_change(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_empty_plans(self):
        fmt = UrlNormalizationFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_escapes_special_chars(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(changes=[UrlNormalizationChange("scope", "<script>", "both")])
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
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[
                UrlNormalizationChange("scope", "incoming", "both"),
                UrlNormalizationChange("type", "cloudflare", "rfc3986"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "url_normalization_settings"
        assert entry["provider_id"] == "cloudflare_url_normalization"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 2
        assert entry["adds"] == 0
        assert entry["removes"] == 0

    def test_preserves_incoming_drift(self):
        fmt = UrlNormalizationFormatter()
        plan = UrlNormalizationPlan(
            changes=[UrlNormalizationChange("scope", "incoming", "incoming")]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []

    def test_no_drift(self):
        fmt = UrlNormalizationFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetUrlNormalization:
    def test_get_url_normalization(self):
        from octorules_cloudflare.provider import CloudflareProvider

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "scope": "incoming",
            "type": "cloudflare",
        }
        mock_client.url_normalization.get.return_value = mock_result
        provider = CloudflareProvider(client=mock_client)
        scope = _scope()
        result = provider.get_url_normalization(scope)
        assert result["scope"] == "incoming"
        assert result["type"] == "cloudflare"
        mock_client.url_normalization.get.assert_called_once_with(zone_id="test-zone-id")


class TestProviderUpdateUrlNormalization:
    def test_update_url_normalization(self):
        from octorules_cloudflare.provider import CloudflareProvider

        mock_client = MagicMock()
        provider = CloudflareProvider(client=mock_client)
        scope = _scope()
        provider.update_url_normalization(scope, {"scope": "both", "type": "rfc3986"})
        mock_client.url_normalization.update.assert_called_once_with(
            zone_id="test-zone-id",
            scope="both",
            type="rfc3986",
        )
