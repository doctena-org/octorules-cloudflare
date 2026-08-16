"""Tests for the account-scoped alerting (notification policies) extension."""

from unittest.mock import MagicMock

import pytest
from octorules.planner import ChangeType, RuleValidationError
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare._alerting import (
    PLAN_KEY,
    _apply_alerting,
    _dump_alerting,
    _finalize_alerting,
    _policy_kwargs,
    _prefetch_alerting,
    _validate_alerting,
    check_against_available_alerts,
    diff_alerting_policies,
    normalize_alerting_policy,
    resolve_alerting_policy,
    unresolve_alerting_policy,
)
from octorules_cloudflare.provider import CloudflareProvider

SECTION = "cloudflare.alerting_policies"

WEBHOOK_ID = "6421f4d4aaaabbbbccccddddeeeeffff"
ZONE_ID = "0123456789abcdef0123456789abcdef"
WEBHOOK_IDS = {"Ops Slack": WEBHOOK_ID}
ZONE_IDS = {"example.com": ZONE_ID}

AVAILABLE = {
    "dos_attack_l7": [],
    "dedicated_ssl_certificate_event_type": [],
    "incident_alert": [
        {"Key": "incident_impact", "ComparisonOperator": "==", "Range": "0-n"},
    ],
    "clickhouse_alert_fw_ent_anomaly": [
        {"Key": "zones", "ComparisonOperator": "==", "Range": "1-n"},
        {"Key": "services", "ComparisonOperator": "==", "Range": "0-n"},
    ],
}


def _scope():
    return Scope(account_id="acct-1", label="account-a")


def _policy(**overrides):
    """A valid YAML policy entry."""
    base = {
        "name": "Certificate expiring soon",
        "alert_type": "dedicated_ssl_certificate_event_type",
        "enabled": True,
        "mechanisms": {"webhooks": ["$Ops Slack"]},
    }
    base.update(overrides)
    return base


def _current_policy(**overrides):
    """A live API policy dict."""
    base = {
        "id": "policy-1",
        "name": "Certificate expiring soon",
        "alert_type": "dedicated_ssl_certificate_event_type",
        "enabled": True,
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "mechanisms": {"webhooks": [{"id": WEBHOOK_ID}]},
    }
    base.update(overrides)
    return base


def _resolved(**overrides):
    return resolve_alerting_policy(_policy(**overrides), WEBHOOK_IDS, ZONE_IDS)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_api_fields_are_stripped(self):
        normalized = normalize_alerting_policy(_current_policy())
        for key in ("id", "created", "modified"):
            assert key not in normalized

    def test_mechanism_entries_flatten_and_sort(self):
        raw = {"mechanisms": {"email": [{"id": "b@example.com"}, {"id": "a@example.com"}]}}
        normalized = normalize_alerting_policy(raw)
        assert normalized["mechanisms"] == {"email": ["a@example.com", "b@example.com"]}

    def test_empty_mechanism_types_are_dropped(self):
        raw = {"mechanisms": {"email": [], "webhooks": [{"id": WEBHOOK_ID}]}}
        normalized = normalize_alerting_policy(raw)
        assert normalized["mechanisms"] == {"webhooks": [WEBHOOK_ID]}

    def test_filter_values_sort_and_stringify(self):
        raw = {"filters": {"slo": [100, 99]}}
        assert normalize_alerting_policy(raw)["filters"] == {"slo": ["100", "99"]}


# ---------------------------------------------------------------------------
# Reference resolution
# ---------------------------------------------------------------------------
class TestResolution:
    def test_webhook_name_resolves_to_id(self):
        resolved = _resolved()
        assert resolved["mechanisms"]["webhooks"] == [WEBHOOK_ID]

    def test_raw_webhook_id_passes_through(self):
        resolved = _resolved(mechanisms={"webhooks": [WEBHOOK_ID]})
        assert resolved["mechanisms"]["webhooks"] == [WEBHOOK_ID]

    def test_unknown_webhook_name_fails(self):
        with pytest.raises(RuleValidationError, match="does not exist"):
            _resolved(mechanisms={"webhooks": ["$No Such Hook"]})

    def test_zone_name_resolves_to_id(self):
        resolved = _resolved(filters={"zones": ["example.com"]})
        assert resolved["filters"]["zones"] == [ZONE_ID]

    def test_raw_zone_id_passes_through(self):
        resolved = _resolved(filters={"zones": [ZONE_ID]})
        assert resolved["filters"]["zones"] == [ZONE_ID]

    def test_unknown_zone_fails(self):
        with pytest.raises(RuleValidationError, match="zones entry"):
            _resolved(filters={"zones": ["nope.example"]})

    def test_round_trip_back_to_names(self):
        current = normalize_alerting_policy(_current_policy(filters={"zones": [ZONE_ID]}))
        yaml_form = unresolve_alerting_policy(
            current,
            {v: k for k, v in WEBHOOK_IDS.items()},
            {v: k for k, v in ZONE_IDS.items()},
        )
        assert yaml_form["mechanisms"]["webhooks"] == ["$Ops Slack"]
        assert yaml_form["filters"]["zones"] == ["example.com"]

    def test_unknown_ids_stay_as_ids_on_unresolve(self):
        current = normalize_alerting_policy(_current_policy())
        yaml_form = unresolve_alerting_policy(current, {}, {})
        assert yaml_form["mechanisms"]["webhooks"] == [WEBHOOK_ID]


# ---------------------------------------------------------------------------
# Capability validation (available_alerts registry)
# ---------------------------------------------------------------------------
class TestAvailableAlerts:
    def test_known_types_pass(self):
        check_against_available_alerts([_policy()], AVAILABLE, "account-a")

    def test_unknown_type_fails(self):
        with pytest.raises(RuleValidationError, match="not.*available"):
            check_against_available_alerts(
                [_policy(alert_type="not_a_type")], AVAILABLE, "account-a"
            )

    def test_missing_required_filter_fails(self):
        entry = _policy(alert_type="clickhouse_alert_fw_ent_anomaly")
        with pytest.raises(RuleValidationError, match="requires the 'zones' filter"):
            check_against_available_alerts([entry], AVAILABLE, "account-a")

    def test_declared_required_filter_passes(self):
        entry = _policy(
            alert_type="clickhouse_alert_fw_ent_anomaly",
            filters={"zones": [ZONE_ID]},
        )
        check_against_available_alerts([entry], AVAILABLE, "account-a")

    def test_unknown_filter_key_only_warns(self, caplog):
        entry = _policy(filters={"bogus_filter": ["x"]})
        with caplog.at_level("WARNING"):
            check_against_available_alerts([entry], AVAILABLE, "account-a")
        assert any("bogus_filter" in r.message for r in caplog.records)

    def test_empty_registry_skips_all_checks(self):
        check_against_available_alerts([_policy(alert_type="not_a_type")], {}, "account-a")


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_identical_policy_is_no_change(self):
        plans = diff_alerting_policies([_resolved()], [_current_policy()])
        assert plans == []

    def test_enabled_flip_is_one_field_change(self):
        plans = diff_alerting_policies([_resolved()], [_current_policy(enabled=False)])
        assert len(plans) == 1
        assert [(c.change_type, c.ref) for c in plans[0].changes] == [
            (ChangeType.MODIFY, "enabled")
        ]
        assert plans[0].policy_id == "policy-1"

    def test_new_policy_is_a_create(self):
        plans = diff_alerting_policies([_resolved()], [])
        assert plans[0].create is True

    def test_unlisted_current_policy_is_a_delete(self):
        plans = diff_alerting_policies([], [_current_policy()])
        assert plans[0].delete is True
        assert plans[0].policy_id == "policy-1"

    def test_undeclared_optional_fields_never_drive_a_diff(self):
        current = _current_policy(description="set in the dashboard")
        plans = diff_alerting_policies([_resolved()], [current])
        assert plans == []

    def test_mechanism_order_is_not_significant(self):
        desired = _resolved(mechanisms={"email": ["b@example.com", "a@example.com"]})
        current = _current_policy(
            mechanisms={"email": [{"id": "a@example.com"}, {"id": "b@example.com"}]}
        )
        assert diff_alerting_policies([desired], [current]) == []


# ---------------------------------------------------------------------------
# Update payload
# ---------------------------------------------------------------------------
class TestPolicyKwargs:
    def test_undeclared_fields_carry_over_from_current(self):
        current = normalize_alerting_policy(_current_policy(description="keep me", enabled=False))
        kwargs = _policy_kwargs(_resolved(), current)
        assert kwargs["description"] == "keep me"
        assert kwargs["enabled"] is True  # declared -> replaced

    def test_mechanisms_denormalize_to_id_objects(self):
        kwargs = _policy_kwargs(_resolved(), None)
        assert kwargs["mechanisms"] == {"webhooks": [{"id": WEBHOOK_ID}]}

    def test_declared_empty_filters_clear(self):
        current = normalize_alerting_policy(_current_policy(filters={"zones": [ZONE_ID]}))
        kwargs = _policy_kwargs(_resolved(filters={}), current)
        assert kwargs["filters"] == {}


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def _provider(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_alerting_policies.return_value = [_current_policy()]
        provider.get_available_alerts.return_value = AVAILABLE
        provider.get_alerting_webhooks.return_value = [
            {"id": WEBHOOK_ID, "name": "Ops Slack", "type": "slack"}
        ]
        provider.get_zone_id_map.return_value = ZONE_IDS
        return provider

    def test_returns_full_context(self):
        provider = self._provider()
        ctx = _prefetch_alerting({SECTION: [_policy()]}, _scope(), provider)
        current, _desired, webhook_ids, _zone_ids, available = ctx
        assert current == [_current_policy()]
        assert webhook_ids == WEBHOOK_IDS
        assert available == AVAILABLE

    def test_returns_none_on_zone_scope(self):
        scope = Scope(zone_id="zone-1", label="example.com")
        assert _prefetch_alerting({SECTION: []}, scope, self._provider()) is None

    def test_returns_none_when_the_section_is_absent(self):
        provider = self._provider()
        assert _prefetch_alerting({}, _scope(), provider) is None
        provider.get_alerting_policies.assert_not_called()

    def test_zone_map_fetched_only_when_zone_filters_declared(self):
        provider = self._provider()
        _prefetch_alerting({SECTION: [_policy()]}, _scope(), provider)
        provider.get_zone_id_map.assert_not_called()

        _prefetch_alerting(
            {SECTION: [_policy(filters={"zones": ["example.com"]})]}, _scope(), provider
        )
        provider.get_zone_id_map.assert_called_once()

    def test_webhooks_fetched_only_for_dollar_references(self):
        provider = self._provider()
        _prefetch_alerting(
            {SECTION: [_policy(mechanisms={"email": ["a@example.com"]})]},
            _scope(),
            provider,
        )
        provider.get_alerting_webhooks.assert_not_called()

    def test_auth_error_propagates(self):
        provider = self._provider()
        provider.get_alerting_policies.side_effect = ProviderAuthError("denied")
        with pytest.raises(ProviderAuthError):
            _prefetch_alerting({SECTION: []}, _scope(), provider)

    def test_policy_fetch_error_degrades_to_empty_current(self):
        provider = self._provider()
        provider.get_alerting_policies.side_effect = ProviderError("boom")
        ctx = _prefetch_alerting({SECTION: [_policy()]}, _scope(), provider)
        assert ctx[0] == []

    def test_registry_fetch_error_degrades_to_empty_registry(self):
        provider = self._provider()
        provider.get_available_alerts.side_effect = ProviderError("boom")
        ctx = _prefetch_alerting({SECTION: [_policy()]}, _scope(), provider)
        assert ctx[4] == {}


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_changes_land_in_extension_plans(self):
        zp = MagicMock()
        zp.extension_plans = {}
        ctx = ([_current_policy(enabled=False)], [_policy()], WEBHOOK_IDS, ZONE_IDS, AVAILABLE)
        _finalize_alerting(zp, {}, _scope(), MagicMock(), ctx)
        assert PLAN_KEY in zp.extension_plans

    def test_unavailable_alert_type_fails_the_plan(self):
        zp = MagicMock()
        zp.extension_plans = {}
        ctx = ([], [_policy(alert_type="not_a_type")], WEBHOOK_IDS, ZONE_IDS, AVAILABLE)
        with pytest.raises(RuleValidationError):
            _finalize_alerting(zp, {}, _scope(), MagicMock(), ctx)

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_alerting(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_update_sends_the_merged_policy(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        zp.zone_name = "account-a"
        plans = diff_alerting_policies([_resolved()], [_current_policy(enabled=False)])
        synced, error = _apply_alerting(zp, plans, _scope(), provider)
        assert error is None
        assert synced == ["account-a/alerting:Certificate expiring soon"]
        args, kwargs = provider.update_alerting_policy.call_args
        assert args[1] == "policy-1"
        assert kwargs["enabled"] is True
        assert kwargs["alert_type"] == "dedicated_ssl_certificate_event_type"
        assert kwargs["mechanisms"] == {"webhooks": [{"id": WEBHOOK_ID}]}

    def test_create_records_the_new_policy_id(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.create_alerting_policy.return_value = {"id": "new-id"}
        zp = MagicMock()
        zp.zone_name = "account-a"
        plans = diff_alerting_policies([_resolved()], [])
        _apply_alerting(zp, plans, _scope(), provider)
        assert plans[0].policy_id == "new-id"

    def test_delete_calls_the_delete_endpoint(self):
        provider = MagicMock(spec=CloudflareProvider)
        zp = MagicMock()
        zp.zone_name = "account-a"
        plans = diff_alerting_policies([], [_current_policy()])
        _apply_alerting(zp, plans, _scope(), provider)
        provider.delete_alerting_policy.assert_called_once_with(_scope(), "policy-1")


# ---------------------------------------------------------------------------
# Dump hook
# ---------------------------------------------------------------------------
class TestDumpHook:
    def test_dump_translates_ids_to_names(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_alerting_policies.return_value = [
            _current_policy(filters={"zones": [ZONE_ID]})
        ]
        provider.get_alerting_webhooks.return_value = [{"id": WEBHOOK_ID, "name": "Ops Slack"}]
        provider.get_zone_id_map.return_value = ZONE_IDS
        result = _dump_alerting(_scope(), provider)
        policy = result[SECTION][0]
        assert policy["mechanisms"]["webhooks"] == ["$Ops Slack"]
        assert policy["filters"]["zones"] == ["example.com"]
        assert "id" not in policy

    def test_dump_without_policies_returns_none(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_alerting_policies.return_value = []
        assert _dump_alerting(_scope(), provider) is None

    def test_dump_on_zone_scope_returns_none(self):
        scope = Scope(zone_id="zone-1", label="example.com")
        assert _dump_alerting(scope, MagicMock()) is None

    def test_dump_auth_error_is_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_alerting_policies.side_effect = ProviderAuthError("denied")
        assert _dump_alerting(_scope(), provider) is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def _validate(self, entries):
        errors: list[str] = []
        _validate_alerting({SECTION: entries}, "account-a", errors, [])
        return errors

    def test_valid_policy(self):
        assert self._validate([_policy()]) == []

    def test_missing_required_fields(self):
        errors = self._validate([{}])
        for field in ("name", "alert_type", "enabled", "mechanisms"):
            assert any(field in e for e in errors)

    def test_ref_is_rejected_with_a_hint(self):
        errors = self._validate([_policy(ref="cert-expiry")])
        assert any("identified by name" in e for e in errors)

    def test_duplicate_name_rejected(self):
        errors = self._validate([_policy(), _policy()])
        assert any("duplicate name" in e for e in errors)

    def test_empty_mechanisms_rejected(self):
        errors = self._validate([_policy(mechanisms={})])
        assert any("at least one destination" in e for e in errors)

    def test_unknown_mechanism_key_rejected(self):
        errors = self._validate([_policy(mechanisms={"sms": ["+000"]})])
        assert any("sms" in e for e in errors)

    def test_non_list_filter_rejected(self):
        errors = self._validate([_policy(filters={"zones": "example.com"})])
        assert any("must be a list" in e for e in errors)

    def test_non_dict_section_is_ignored(self):
        errors: list[str] = []
        _validate_alerting({SECTION: "nope"}, "account-a", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderAlerting:
    def test_get_policies_returns_dicts(self, mock_cf_client):
        mock_cf_client.alerting.policies.list.return_value = [_current_policy()]
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_alerting_policies(_scope()) == [_current_policy()]
        mock_cf_client.alerting.policies.list.assert_called_once_with(account_id="acct-1")

    def test_create_passes_kwargs_and_returns_response(self, mock_cf_client):
        mock_cf_client.alerting.policies.create.return_value = {"id": "new-id"}
        provider = CloudflareProvider(client=mock_cf_client)
        result = provider.create_alerting_policy(_scope(), name="x", enabled=True)
        assert result == {"id": "new-id"}
        mock_cf_client.alerting.policies.create.assert_called_once_with(
            account_id="acct-1", name="x", enabled=True
        )

    def test_update_addresses_the_policy(self, mock_cf_client):
        provider = CloudflareProvider(client=mock_cf_client)
        provider.update_alerting_policy(_scope(), "policy-1", name="x")
        mock_cf_client.alerting.policies.update.assert_called_once_with(
            "policy-1", account_id="acct-1", name="x"
        )

    def test_delete_addresses_the_policy(self, mock_cf_client):
        provider = CloudflareProvider(client=mock_cf_client)
        provider.delete_alerting_policy(_scope(), "policy-1")
        mock_cf_client.alerting.policies.delete.assert_called_once_with(
            "policy-1", account_id="acct-1"
        )

    def test_available_alerts_flatten_to_type_keys(self, mock_cf_client):
        mock_cf_client.alerting.available_alerts.list.return_value = {
            "SSL/TLS": [
                {
                    "type": "dedicated_ssl_certificate_event_type",
                    "display_name": "Certificate events",
                    "filter_options": None,
                }
            ],
            "Firewall": [
                {
                    "type": "clickhouse_alert_fw_ent_anomaly",
                    "filter_options": [{"Key": "zones", "Range": "1-n"}],
                }
            ],
        }
        provider = CloudflareProvider(client=mock_cf_client)
        available = provider.get_available_alerts(_scope())
        assert available == {
            "dedicated_ssl_certificate_event_type": [],
            "clickhouse_alert_fw_ent_anomaly": [{"Key": "zones", "Range": "1-n"}],
        }

    def test_available_alerts_none_response(self, mock_cf_client):
        mock_cf_client.alerting.available_alerts.list.return_value = None
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_available_alerts(_scope()) == {}

    def test_zone_id_map(self, mock_cf_client):
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = ZONE_ID
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_zone_id_map(_scope()) == ZONE_IDS
