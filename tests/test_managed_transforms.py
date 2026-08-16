"""Tests for the Managed Transforms settings extension and provider methods."""

from unittest.mock import MagicMock

import pytest
from octorules.planner import RuleValidationError
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare._managed_transforms import (
    ManagedTransformsChange,
    ManagedTransformsPlan,
    _apply_managed_transforms,
    _finalize_managed_transforms,
    _prefetch_managed_transforms,
    _validate_managed_transforms,
    check_transform_conflicts,
    diff_managed_transforms,
    extract_conflicts,
    normalize_managed_transforms,
)
from octorules_cloudflare.provider import CloudflareProvider

SECTION = "cloudflare.managed_transforms"


def _scope():
    return Scope(zone_id="zone-1", label="example.com")


def _raw():
    """A live-shaped GET /managed_headers response as a plain dict."""
    return {
        "managed_request_headers": [
            {
                "id": "add_true_client_ip_headers",
                "enabled": False,
                "has_conflict": False,
                "conflicts_with": ["remove_visitor_ip_headers"],
            },
            {
                "id": "add_visitor_location_headers",
                "enabled": False,
                "has_conflict": False,
            },
            {
                "id": "remove_visitor_ip_headers",
                "enabled": False,
                "has_conflict": False,
                "conflicts_with": ["add_true_client_ip_headers"],
            },
        ],
        "managed_response_headers": [
            {"id": "add_security_headers", "enabled": False, "has_conflict": False},
        ],
    }


def _current():
    return normalize_managed_transforms(_raw())


def _conflicts():
    return extract_conflicts(_raw())


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_both_sides_normalize_to_toggle_maps(self):
        assert _current() == {
            "request": {
                "add_true_client_ip_headers": False,
                "add_visitor_location_headers": False,
                "remove_visitor_ip_headers": False,
            },
            "response": {"add_security_headers": False},
        }

    def test_conflict_metadata_is_not_carried(self):
        for side in _current().values():
            for value in side.values():
                assert isinstance(value, bool)

    def test_empty_input(self):
        assert normalize_managed_transforms({}) == {}


class TestExtractConflicts:
    def test_declared_pairs_are_read_from_both_sides(self):
        assert _conflicts() == {
            "add_true_client_ip_headers": ["remove_visitor_ip_headers"],
            "remove_visitor_ip_headers": ["add_true_client_ip_headers"],
        }

    def test_empty_input(self):
        assert extract_conflicts({}) == {}


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_matching_toggle_is_no_change(self):
        plan = diff_managed_transforms(_current(), {"response": {"add_security_headers": False}})
        assert not plan.has_changes

    def test_differing_toggle_is_a_change(self):
        plan = diff_managed_transforms(_current(), {"response": {"add_security_headers": True}})
        assert [(c.field, c.current, c.desired) for c in plan.changes] == [
            ("response.add_security_headers", False, True)
        ]

    def test_unmentioned_transforms_never_drive_a_diff(self):
        plan = diff_managed_transforms(
            _current(), {"request": {"add_visitor_location_headers": False}}
        )
        assert not plan.has_changes

    def test_unknown_transform_is_unsupported_not_a_change(self):
        plan = diff_managed_transforms(_current(), {"request": {"nonexistent_transform": True}})
        assert not plan.has_changes
        assert plan.unsupported == ["request.nonexistent_transform"]

    def test_empty_current_proposes_everything(self):
        """A failed live read means support is unknown -- propose all of it."""
        plan = diff_managed_transforms({}, {"request": {"add_true_client_ip_headers": True}})
        assert [c.field for c in plan.changes] == ["request.add_true_client_ip_headers"]
        assert plan.unsupported == []


# ---------------------------------------------------------------------------
# Conflict check
# ---------------------------------------------------------------------------
class TestConflictCheck:
    def test_yaml_enabling_both_sides_of_a_pair_fails(self):
        desired = {
            "request": {
                "add_true_client_ip_headers": True,
                "remove_visitor_ip_headers": True,
            }
        }
        with pytest.raises(RuleValidationError, match="mutually"):
            check_transform_conflicts(_current(), desired, _conflicts(), "example.com")

    def test_yaml_conflicting_with_a_live_toggle_fails(self):
        current = _current()
        current["request"]["remove_visitor_ip_headers"] = True
        desired = {"request": {"add_true_client_ip_headers": True}}
        with pytest.raises(RuleValidationError, match="already enabled"):
            check_transform_conflicts(current, desired, _conflicts(), "example.com")

    def test_yaml_disabling_one_side_resolves_the_conflict(self):
        current = _current()
        current["request"]["remove_visitor_ip_headers"] = True
        desired = {
            "request": {
                "add_true_client_ip_headers": True,
                "remove_visitor_ip_headers": False,
            }
        }
        check_transform_conflicts(current, desired, _conflicts(), "example.com")

    def test_unmanaged_live_conflict_is_not_this_zone_files_business(self):
        current = _current()
        current["request"]["add_true_client_ip_headers"] = True
        current["request"]["remove_visitor_ip_headers"] = True
        desired = {"response": {"add_security_headers": True}}
        check_transform_conflicts(current, desired, _conflicts(), "example.com")

    def test_no_conflicts_declared_never_fails(self):
        desired = {"request": {"add_true_client_ip_headers": True}}
        check_transform_conflicts(_current(), desired, {}, "example.com")


# ---------------------------------------------------------------------------
# Prefetch hook (custom -- carries conflict metadata)
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_current_desired_and_conflicts(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_managed_transforms_raw.return_value = _raw()
        desired = {"response": {"add_security_headers": True}}
        ctx = _prefetch_managed_transforms({SECTION: desired}, _scope(), provider)
        assert ctx == (_current(), desired, _conflicts())

    def test_returns_none_without_a_zone(self):
        provider = MagicMock(spec=CloudflareProvider)
        scope = Scope(zone_id="", label="account")
        assert _prefetch_managed_transforms({SECTION: {}}, scope, provider) is None

    def test_returns_none_when_the_section_is_absent(self):
        provider = MagicMock(spec=CloudflareProvider)
        assert _prefetch_managed_transforms({}, _scope(), provider) is None
        provider.get_managed_transforms_raw.assert_not_called()

    def test_auth_error_propagates(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_managed_transforms_raw.side_effect = ProviderAuthError("denied")
        with pytest.raises(ProviderAuthError):
            _prefetch_managed_transforms({SECTION: {}}, _scope(), provider)

    def test_provider_error_degrades_to_empty_current(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_managed_transforms_raw.side_effect = ProviderError("boom")
        ctx = _prefetch_managed_transforms({SECTION: {"request": {}}}, _scope(), provider)
        assert ctx == ({}, {"request": {}}, {})

    def test_product_not_enabled_is_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_managed_transforms_raw.side_effect = ProviderError("not enabled")
        assert _prefetch_managed_transforms({SECTION: {}}, _scope(), provider) is None


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_changes_land_in_extension_plans(self):
        zp = MagicMock()
        zp.extension_plans = {}
        desired = {"response": {"add_security_headers": True}}
        _finalize_managed_transforms(
            zp, {}, _scope(), MagicMock(), (_current(), desired, _conflicts())
        )
        assert SECTION in zp.extension_plans

    def test_conflicting_desired_state_fails_the_plan(self):
        zp = MagicMock()
        zp.extension_plans = {}
        desired = {
            "request": {
                "add_true_client_ip_headers": True,
                "remove_visitor_ip_headers": True,
            }
        }
        with pytest.raises(RuleValidationError):
            _finalize_managed_transforms(
                zp, {}, _scope(), MagicMock(), (_current(), desired, _conflicts())
            )

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_managed_transforms(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_sends_only_changed_toggles(self):
        provider = MagicMock(spec=CloudflareProvider)
        provider.get_managed_transforms.return_value = _current()
        plan = ManagedTransformsPlan(
            changes=[
                ManagedTransformsChange("request.add_true_client_ip_headers", False, True),
                ManagedTransformsChange("response.add_security_headers", False, False),
            ]
        )
        synced, error = _apply_managed_transforms(MagicMock(), [plan], _scope(), provider)
        assert error is None
        assert SECTION in synced
        payload = provider.update_managed_transforms.call_args[0][1]
        assert payload == {"request": {"add_true_client_ip_headers": True}}

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudflareProvider)
        plan = ManagedTransformsPlan(
            changes=[ManagedTransformsChange("response.add_security_headers", True, True)]
        )
        synced, error = _apply_managed_transforms(MagicMock(), [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_managed_transforms.assert_not_called()


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def _validate(self, settings):
        errors: list[str] = []
        _validate_managed_transforms({SECTION: settings}, "zone", errors, [])
        return errors

    def test_valid_settings(self):
        assert self._validate({"request": {"add_true_client_ip_headers": True}}) == []

    def test_unknown_top_level_key_rejected(self):
        errors = self._validate({"headers": {}})
        assert len(errors) == 1
        assert "headers" in errors[0]

    def test_non_mapping_side_rejected(self):
        errors = self._validate({"request": ["add_true_client_ip_headers"]})
        assert any("must be a mapping" in e for e in errors)

    def test_non_bool_toggle_rejected(self):
        errors = self._validate({"request": {"add_true_client_ip_headers": "on"}})
        assert any("true or false" in e for e in errors)

    def test_non_dict_section_is_ignored(self):
        errors: list[str] = []
        _validate_managed_transforms({SECTION: "nope"}, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderManagedTransforms:
    def test_get_raw_returns_plain_dict(self, mock_cf_client):
        mock_cf_client.managed_transforms.list.return_value = _raw()
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_managed_transforms_raw(_scope()) == _raw()
        mock_cf_client.managed_transforms.list.assert_called_once_with(zone_id="zone-1")

    def test_get_normalizes(self, mock_cf_client):
        mock_cf_client.managed_transforms.list.return_value = _raw()
        provider = CloudflareProvider(client=mock_cf_client)
        assert provider.get_managed_transforms(_scope()) == _current()

    def test_update_builds_per_side_entry_lists(self, mock_cf_client):
        provider = CloudflareProvider(client=mock_cf_client)
        provider.update_managed_transforms(
            _scope(),
            {
                "request": {"add_true_client_ip_headers": True},
                "response": {"add_security_headers": False},
            },
        )
        mock_cf_client.managed_transforms.edit.assert_called_once_with(
            zone_id="zone-1",
            managed_request_headers=[{"id": "add_true_client_ip_headers", "enabled": True}],
            managed_response_headers=[{"id": "add_security_headers", "enabled": False}],
        )

    def test_update_omits_empty_sides(self, mock_cf_client):
        provider = CloudflareProvider(client=mock_cf_client)
        provider.update_managed_transforms(
            _scope(), {"request": {"add_true_client_ip_headers": True}}
        )
        kwargs = mock_cf_client.managed_transforms.edit.call_args[1]
        assert "managed_response_headers" not in kwargs

    def test_update_with_nothing_to_send_makes_no_call(self, mock_cf_client):
        provider = CloudflareProvider(client=mock_cf_client)
        provider.update_managed_transforms(_scope(), {})
        mock_cf_client.managed_transforms.edit.assert_not_called()
