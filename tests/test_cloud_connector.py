"""Tests for the Cloud Connector extension and provider methods."""

from unittest.mock import MagicMock

import pytest
from octorules.planner import ChangeType
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare._cloud_connector import (
    PLAN_KEY,
    _apply_cloud_connector,
    _dump_cloud_connector,
    _finalize_cloud_connector,
    _prefetch_cloud_connector,
    _validate_cloud_connector,
    diff_cloud_connector_rules,
    prepare_cloud_connector_rules,
)
from octorules_cloudflare.provider import CloudflareProvider

SECTION = "cloudflare.cloud_connector_rules"


def _scope():
    return Scope(zone_id="zone-1", label="example.com")


def _rule(**overrides):
    base = {
        "description": "assets",
        "expression": 'starts_with(http.request.uri.path, "/assets/")',
        "provider": "cloudflare_r2",
        "parameters": {"host": "assets.account-a.r2.cloudflarestorage.com"},
    }
    base.update(overrides)
    return base


def _current_rule(**overrides):
    base = _rule(id="cc-rule-1", enabled=True)
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Preparation
# ---------------------------------------------------------------------------
class TestPrepare:
    def test_enabled_defaults_to_true(self):
        prepared = prepare_cloud_connector_rules([_rule()])
        assert prepared[0]["enabled"] is True

    def test_explicit_enabled_false_is_preserved(self):
        prepared = prepare_cloud_connector_rules([_rule(enabled=False)])
        assert prepared[0]["enabled"] is False

    def test_expression_whitespace_is_normalized(self):
        prepared = prepare_cloud_connector_rules([_rule(expression="http.host  eq\n 'a'")])
        assert prepared[0]["expression"] == "http.host eq 'a'"

    def test_originals_are_not_mutated(self):
        rule = _rule()
        prepare_cloud_connector_rules([rule])
        assert "enabled" not in rule


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_identical_rules_are_no_change(self):
        plan = diff_cloud_connector_rules([_rule()], [_current_rule()])
        assert not plan.has_changes

    def test_new_rule_is_an_add(self):
        plan = diff_cloud_connector_rules([_rule()], [])
        assert [(c.change_type, c.ref) for c in plan.changes] == [(ChangeType.ADD, "assets")]

    def test_unlisted_current_rule_is_a_remove(self):
        plan = diff_cloud_connector_rules([], [_current_rule()])
        assert [(c.change_type, c.ref) for c in plan.changes] == [(ChangeType.REMOVE, "assets")]

    def test_field_change_is_a_modify(self):
        plan = diff_cloud_connector_rules([_rule(provider="aws_s3")], [_current_rule()])
        assert [(c.change_type, c.ref) for c in plan.changes] == [(ChangeType.MODIFY, "assets")]

    def test_same_rules_in_a_different_order_is_a_reorder(self):
        a, b = _rule(), _rule(description="media", expression="http.host eq 'a'")
        cur_a = _current_rule()
        cur_b = _current_rule(id="cc-rule-2", description="media", expression="http.host eq 'a'")
        plan = diff_cloud_connector_rules([b, a], [cur_a, cur_b])
        assert [c.change_type for c in plan.changes] == [ChangeType.REORDER]

    def test_persisting_rules_keep_their_api_id(self):
        plan = diff_cloud_connector_rules([_rule(), _rule(description="new")], [_current_rule()])
        by_desc = {r["description"]: r for r in plan.desired_rules}
        assert by_desc["assets"]["id"] == "cc-rule-1"
        assert "id" not in by_desc["new"]

    def test_payload_preserves_yaml_order(self):
        rules = [_rule(description=f"r{i}", expression=f"http.host eq 'h{i}'") for i in range(3)]
        plan = diff_cloud_connector_rules(rules, [])
        assert [r["description"] for r in plan.desired_rules] == ["r0", "r1", "r2"]


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_current_and_desired(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.return_value = [_current_rule()]
        ctx = _prefetch_cloud_connector({SECTION: [_rule()]}, _scope(), provider)
        assert ctx == ([_current_rule()], [_rule()])

    def test_returns_none_without_a_zone(self):
        scope = Scope(zone_id="", label="account")
        assert _prefetch_cloud_connector({SECTION: []}, scope, MagicMock()) is None

    def test_returns_none_when_the_section_is_absent(self):
        provider = MagicMock(spec=CloudflareProvider)
        assert _prefetch_cloud_connector({}, _scope(), provider) is None
        provider.get_cloud_connector_rules.assert_not_called()

    def test_auth_error_propagates(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.side_effect = ProviderAuthError("denied")
        with pytest.raises(ProviderAuthError):
            _prefetch_cloud_connector({SECTION: []}, _scope(), provider)

    def test_provider_error_degrades_to_empty_current(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.side_effect = ProviderError("boom")
        ctx = _prefetch_cloud_connector({SECTION: [_rule()]}, _scope(), provider)
        assert ctx == ([], [_rule()])


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_changes_land_in_extension_plans(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_cloud_connector(zp, {}, _scope(), MagicMock(), ([], [_rule()]))
        assert PLAN_KEY in zp.extension_plans

    def test_no_changes_adds_nothing(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_cloud_connector(zp, {}, _scope(), MagicMock(), ([_current_rule()], [_rule()]))
        assert zp.extension_plans == {}

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_cloud_connector(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_puts_the_full_desired_list(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        zp.zone_name = "example.com"
        plan = diff_cloud_connector_rules([_rule(), _rule(description="new")], [_current_rule()])
        synced, error = _apply_cloud_connector(zp, [plan], _scope(), provider)
        assert error is None
        assert synced == ["example.com/cloud_connector"]
        sent = provider.put_cloud_connector_rules.call_args[0][1]
        assert sent == plan.desired_rules
        assert len(sent) == 2

    def test_reorder_alone_still_puts(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        zp.zone_name = "example.com"
        a, b = _rule(), _rule(description="media", expression="http.host eq 'a'")
        cur_a = _current_rule()
        cur_b = _current_rule(id="cc-rule-2", description="media", expression="http.host eq 'a'")
        plan = diff_cloud_connector_rules([b, a], [cur_a, cur_b])
        _apply_cloud_connector(zp, [plan], _scope(), provider)
        sent = provider.put_cloud_connector_rules.call_args[0][1]
        assert [r["description"] for r in sent] == ["media", "assets"]

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        plan = diff_cloud_connector_rules([_rule()], [_current_rule()])
        synced, error = _apply_cloud_connector(MagicMock(), [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.put_cloud_connector_rules.assert_not_called()


# ---------------------------------------------------------------------------
# Dump hook
# ---------------------------------------------------------------------------
class TestDumpHook:
    def test_dump_strips_api_fields_and_keeps_order(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.return_value = [
            _current_rule(description="second"),
            _current_rule(id="cc-rule-2", description="first"),
        ]
        result = _dump_cloud_connector(_scope(), provider)
        rules = result[SECTION]
        assert [r["description"] for r in rules] == ["second", "first"]
        assert all("id" not in r for r in rules)

    def test_dump_without_rules_returns_none(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.return_value = []
        assert _dump_cloud_connector(_scope(), provider) is None

    def test_dump_without_a_zone_returns_none(self):
        scope = Scope(zone_id="", label="account")
        assert _dump_cloud_connector(scope, MagicMock()) is None

    def test_dump_auth_error_is_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_cloud_connector_rules.side_effect = ProviderAuthError("denied")
        assert _dump_cloud_connector(_scope(), provider) is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def _validate(self, entries):
        errors: list[str] = []
        _validate_cloud_connector({SECTION: entries}, "zone", errors, [])
        return errors

    def test_valid_rule(self):
        assert self._validate([_rule()]) == []

    def test_missing_required_fields(self):
        errors = self._validate([{}])
        assert len(errors) == 3
        for field in ("description", "expression", "provider"):
            assert any(field in e for e in errors)

    def test_invalid_provider(self):
        errors = self._validate([_rule(provider="digitalocean")])
        assert any("digitalocean" in e for e in errors)

    def test_ref_is_rejected_with_a_hint(self):
        errors = self._validate([_rule(ref="assets")])
        assert any("identified by description" in e for e in errors)

    def test_duplicate_description_rejected(self):
        errors = self._validate([_rule(), _rule()])
        assert any("duplicate description" in e for e in errors)

    def test_non_mapping_entry_rejected(self):
        errors = self._validate(["not a rule"])
        assert any("must be a mapping" in e for e in errors)

    def test_unknown_parameters_key_rejected(self):
        errors = self._validate([_rule(parameters={"bucket": "x"})])
        assert any("bucket" in e for e in errors)

    def test_non_list_section_is_ignored(self):
        errors: list[str] = []
        _validate_cloud_connector({SECTION: {"description": "x"}}, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderCloudConnector:
    def test_get_returns_rule_dicts(self, mock_cf_client):
        mock_cf_client.cloud_connector.rules.list.return_value = [_current_rule()]
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_cloud_connector_rules(_scope()) == [_current_rule()]
        mock_cf_client.cloud_connector.rules.list.assert_called_once_with(zone_id="zone-1")

    def test_put_sends_rules_and_returns_count(self, mock_cf_client):
        mock_cf_client.cloud_connector.rules.update.return_value = [_current_rule()]
        provider = CloudflareProvider(client=mock_cf_client)
        count = provider.put_cloud_connector_rules(_scope(), [_rule()])
        assert count == 1
        mock_cf_client.cloud_connector.rules.update.assert_called_once_with(
            zone_id="zone-1", rules=[_rule()]
        )

    def test_put_count_mismatch_logs_warning(self, mock_cf_client, caplog):
        mock_cf_client.cloud_connector.rules.update.return_value = []
        provider = CloudflareProvider(client=mock_cf_client)
        with caplog.at_level("WARNING"):
            count = provider.put_cloud_connector_rules(_scope(), [_rule()])
        assert count == 0
        assert any("sent 1 rule(s)" in r.message for r in caplog.records)
