"""Tests for the phase registry."""

from __future__ import annotations

import pytest
from octorules.phases import (
    ACCOUNT_PROVIDER_IDS,
    ALL_FRIENDLY_NAMES,
    ALL_PROVIDER_IDS,
    PHASE_BY_NAME,
    PHASES,
    ZONE_PROVIDER_IDS,
    get_phase,
    get_phase_by_provider_id,
    suggest_phase,
    unknown_phase_message,
)


class TestPhaseRegistry:
    def test_twenty_three_phases(self):
        assert len(PHASES) == 23

    def test_all_friendly_names_unique(self):
        assert len(ALL_FRIENDLY_NAMES) == len(set(ALL_FRIENDLY_NAMES))

    def test_all_provider_ids_unique(self):
        assert len(ALL_PROVIDER_IDS) == len(set(ALL_PROVIDER_IDS))

    def test_get_phase_redirect(self):
        phase = get_phase("redirect_rules")
        assert phase.provider_id == "http_request_dynamic_redirect"
        assert phase.default_action == "redirect"

    def test_get_phase_cache(self):
        phase = get_phase("cache_rules")
        assert phase.provider_id == "http_request_cache_settings"
        assert phase.default_action == "set_cache_settings"

    def test_waf_no_default_action(self):
        phase = get_phase("waf_custom_rules")
        assert phase.default_action is None

    def test_rate_limiting_no_default_action(self):
        phase = get_phase("rate_limiting_rules")
        assert phase.default_action is None

    def test_unknown_phase_raises(self):
        with pytest.raises(KeyError, match="Unknown phase"):
            get_phase("nonexistent_rules")

    def test_unknown_phase_with_suggestion(self):
        with pytest.raises(KeyError, match="Did you mean 'redirect_rules'"):
            get_phase("redirect_rule")

    def test_unknown_phase_no_suggestion_lists_valid(self):
        with pytest.raises(KeyError, match="Valid phases:"):
            get_phase("zzz_totally_wrong")

    def test_get_phase_by_provider_id(self):
        phase = get_phase_by_provider_id("http_request_dynamic_redirect")
        assert phase.friendly_name == "redirect_rules"

    def test_account_level_phases(self):
        account_phases = [p for p in PHASES if p.account_level]
        assert len(account_phases) == 11
        account_ids = {p.provider_id for p in account_phases}
        assert account_ids == {
            "http_custom_errors",
            "http_request_firewall_custom",
            "http_request_firewall_managed",
            "http_ratelimit",
            "ddos_l7",
            "http_request_redirect",
            "ddos_l4",
            "magic_transit",
            "magic_transit_managed",
            "magic_transit_ratelimit",
            "magic_transit_ids_managed",
        }

    def test_account_provider_ids_list(self):
        assert set(ACCOUNT_PROVIDER_IDS) == {
            "http_custom_errors",
            "http_request_firewall_custom",
            "http_request_firewall_managed",
            "http_ratelimit",
            "ddos_l7",
            "http_request_redirect",
            "ddos_l4",
            "magic_transit",
            "magic_transit_managed",
            "magic_transit_ratelimit",
            "magic_transit_ids_managed",
        }
        assert len(ACCOUNT_PROVIDER_IDS) == 11

    def test_account_provider_ids_subset_of_all(self):
        assert set(ACCOUNT_PROVIDER_IDS).issubset(set(ALL_PROVIDER_IDS))

    def test_non_account_phases(self):
        non_account = [p for p in PHASES if not p.account_level]
        assert len(non_account) == 12

    def test_get_phase_by_provider_id_unknown(self):
        with pytest.raises(KeyError, match="Unknown provider phase"):
            get_phase_by_provider_id("http_nonexistent")

    @pytest.mark.parametrize(
        "name,provider_id",
        [
            ("redirect_rules", "http_request_dynamic_redirect"),
            ("url_rewrite_rules", "http_request_transform"),
            ("request_header_rules", "http_request_late_transform"),
            ("response_header_rules", "http_response_headers_transform"),
            ("config_rules", "http_config_settings"),
            ("origin_rules", "http_request_origin"),
            ("cache_rules", "http_request_cache_settings"),
            ("compression_rules", "http_response_compression"),
            ("custom_error_rules", "http_custom_errors"),
            ("waf_custom_rules", "http_request_firewall_custom"),
            ("waf_managed_rules", "http_request_firewall_managed"),
            ("rate_limiting_rules", "http_ratelimit"),
            ("bot_fight_rules", "http_request_sbfm"),
            ("sensitive_data_detection", "http_response_firewall_managed"),
            ("http_ddos_rules", "ddos_l7"),
            ("bulk_redirect_rules", "http_request_redirect"),
            ("log_custom_fields", "http_log_custom_fields"),
            ("network_ddos_rules", "ddos_l4"),
            ("network_firewall_rules", "magic_transit"),
            ("network_firewall_managed", "magic_transit_managed"),
            ("network_firewall_ratelimit", "magic_transit_ratelimit"),
            ("network_firewall_ids", "magic_transit_ids_managed"),
            ("url_normalization", "http_request_sanitize"),
        ],
    )
    def test_phase_mapping(self, name, provider_id):
        phase = get_phase(name)
        assert phase.provider_id == provider_id


class TestZoneLevelFlag:
    def test_zone_level_default_true(self):
        """Most phases default to zone_level=True."""
        phase = get_phase("redirect_rules")
        assert phase.zone_level is True

    def test_custom_error_rules_zone_and_account(self):
        phase = get_phase("custom_error_rules")
        assert phase.zone_level is True
        assert phase.account_level is True

    def test_waf_phases_both_zone_and_account(self):
        for name in ("waf_custom_rules", "waf_managed_rules", "rate_limiting_rules"):
            phase = get_phase(name)
            assert phase.zone_level is True, f"{name} should be zone_level"
            assert phase.account_level is True, f"{name} should be account_level"

    def test_zone_provider_ids_list(self):
        assert set(ZONE_PROVIDER_IDS) == {p.provider_id for p in PHASES if p.zone_level}

    def test_zone_provider_ids_excludes_account_only(self):
        assert "http_request_redirect" not in ZONE_PROVIDER_IDS
        assert "ddos_l4" not in ZONE_PROVIDER_IDS
        assert "magic_transit" not in ZONE_PROVIDER_IDS

    def test_zone_provider_ids_includes_waf(self):
        assert "http_request_firewall_custom" in ZONE_PROVIDER_IDS
        assert "http_request_firewall_managed" in ZONE_PROVIDER_IDS
        assert "http_ratelimit" in ZONE_PROVIDER_IDS

    def test_zone_provider_ids_includes_custom_errors(self):
        assert "http_custom_errors" in ZONE_PROVIDER_IDS

    def test_zone_provider_ids_includes_new_zone_phases(self):
        assert "ddos_l7" in ZONE_PROVIDER_IDS
        assert "http_log_custom_fields" in ZONE_PROVIDER_IDS
        assert "http_request_sanitize" in ZONE_PROVIDER_IDS

    def test_zone_provider_ids_count(self):
        assert len(ZONE_PROVIDER_IDS) == 17


class TestNewPhases:
    def test_bot_fight_rules(self):
        phase = get_phase("bot_fight_rules")
        assert phase.provider_id == "http_request_sbfm"
        assert phase.default_action is None
        assert phase.zone_level is True
        assert phase.account_level is False

    def test_sensitive_data_detection(self):
        phase = get_phase("sensitive_data_detection")
        assert phase.provider_id == "http_response_firewall_managed"
        assert phase.default_action is None
        assert phase.zone_level is True
        assert phase.account_level is False

    def test_http_ddos_rules(self):
        phase = get_phase("http_ddos_rules")
        assert phase.provider_id == "ddos_l7"
        assert phase.default_action is None
        assert phase.zone_level is True
        assert phase.account_level is True

    def test_bulk_redirect_rules(self):
        phase = get_phase("bulk_redirect_rules")
        assert phase.provider_id == "http_request_redirect"
        assert phase.default_action == "redirect"
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_log_custom_fields(self):
        phase = get_phase("log_custom_fields")
        assert phase.provider_id == "http_log_custom_fields"
        assert phase.default_action == "log_custom_field"
        assert phase.zone_level is True
        assert phase.account_level is False

    def test_network_ddos_rules(self):
        phase = get_phase("network_ddos_rules")
        assert phase.provider_id == "ddos_l4"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_network_firewall_rules(self):
        phase = get_phase("network_firewall_rules")
        assert phase.provider_id == "magic_transit"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_network_firewall_managed(self):
        phase = get_phase("network_firewall_managed")
        assert phase.provider_id == "magic_transit_managed"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_network_firewall_ratelimit(self):
        phase = get_phase("network_firewall_ratelimit")
        assert phase.provider_id == "magic_transit_ratelimit"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_network_firewall_ids(self):
        phase = get_phase("network_firewall_ids")
        assert phase.provider_id == "magic_transit_ids_managed"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_url_normalization(self):
        phase = get_phase("url_normalization")
        assert phase.provider_id == "http_request_sanitize"
        assert phase.default_action is None
        assert phase.zone_level is True
        assert phase.account_level is False


class TestAllFriendlyNamesIncludesNewPhases:
    """Verify all new phase names appear in ALL_FRIENDLY_NAMES."""

    @pytest.mark.parametrize(
        "name",
        [
            "http_ddos_rules",
            "bulk_redirect_rules",
            "log_custom_fields",
            "network_ddos_rules",
            "network_firewall_rules",
            "network_firewall_managed",
            "network_firewall_ratelimit",
            "network_firewall_ids",
            "url_normalization",
        ],
    )
    def test_new_phase_in_all_friendly_names(self, name):
        assert name in ALL_FRIENDLY_NAMES


class TestRenamedPhaseAlias:
    def test_alias_resolves_to_same_phase(self):
        """waf_managed_exceptions alias should resolve to waf_managed_rules."""
        alias_phase = PHASE_BY_NAME["waf_managed_exceptions"]
        canonical_phase = get_phase("waf_managed_rules")
        assert alias_phase is canonical_phase

    def test_alias_not_in_phases_list(self):
        """The alias should not appear in the PHASES list itself."""
        names = [p.friendly_name for p in PHASES]
        assert "waf_managed_exceptions" not in names

    def test_alias_not_in_all_friendly_names(self):
        """ALL_FRIENDLY_NAMES should only have canonical names."""
        assert "waf_managed_exceptions" not in ALL_FRIENDLY_NAMES
        assert "waf_managed_rules" in ALL_FRIENDLY_NAMES

    def test_get_phase_with_alias(self):
        """get_phase should work with the alias name."""
        phase = get_phase("waf_managed_exceptions")
        assert phase.friendly_name == "waf_managed_rules"


class TestPhaseConsistency:
    """Invariant tests for the phase registry."""

    def test_zone_provider_ids_subset_of_all(self):
        assert set(ZONE_PROVIDER_IDS).issubset(set(ALL_PROVIDER_IDS))

    def test_every_phase_has_at_least_one_scope(self):
        """Every phase should work at zone level, account level, or both."""
        for p in PHASES:
            assert p.zone_level or p.account_level, (
                f"Phase {p.friendly_name!r} has neither zone_level nor account_level"
            )

    def test_no_phase_in_both_zone_only_and_account_only(self):
        """Phases with zone_level=False should have account_level=True and vice versa."""
        for p in PHASES:
            if not p.zone_level:
                assert p.account_level, f"{p.friendly_name} has no scope"
            if not p.account_level:
                assert p.zone_level, f"{p.friendly_name} has no scope"

    def test_zone_and_account_phases_cover_all(self):
        """Union of zone and account provider IDs should equal ALL_PROVIDER_IDS."""
        assert set(ZONE_PROVIDER_IDS) | set(ACCOUNT_PROVIDER_IDS) == set(ALL_PROVIDER_IDS)

    def test_phase_by_name_includes_all_canonical_names(self):
        """PHASE_BY_NAME should contain every canonical friendly name."""
        for p in PHASES:
            assert p.friendly_name in PHASE_BY_NAME

    def test_phase_by_name_alias_count(self):
        """PHASE_BY_NAME should have one extra entry for the waf_managed_exceptions alias."""
        assert len(PHASE_BY_NAME) == len(PHASES) + 1


class TestGetPhaseByNewProviderIds:
    def test_get_phase_by_provider_id_sbfm(self):
        phase = get_phase_by_provider_id("http_request_sbfm")
        assert phase.friendly_name == "bot_fight_rules"

    def test_get_phase_by_provider_id_response_firewall_managed(self):
        phase = get_phase_by_provider_id("http_response_firewall_managed")
        assert phase.friendly_name == "sensitive_data_detection"

    def test_get_phase_by_provider_id_request_firewall_managed(self):
        """http_request_firewall_managed should map to waf_managed_rules (not exceptions)."""
        phase = get_phase_by_provider_id("http_request_firewall_managed")
        assert phase.friendly_name == "waf_managed_rules"

    def test_get_phase_by_provider_id_ddos_l7(self):
        phase = get_phase_by_provider_id("ddos_l7")
        assert phase.friendly_name == "http_ddos_rules"

    def test_get_phase_by_provider_id_http_request_redirect(self):
        phase = get_phase_by_provider_id("http_request_redirect")
        assert phase.friendly_name == "bulk_redirect_rules"

    def test_get_phase_by_provider_id_http_log_custom_fields(self):
        phase = get_phase_by_provider_id("http_log_custom_fields")
        assert phase.friendly_name == "log_custom_fields"

    def test_get_phase_by_provider_id_ddos_l4(self):
        phase = get_phase_by_provider_id("ddos_l4")
        assert phase.friendly_name == "network_ddos_rules"

    def test_get_phase_by_provider_id_magic_transit(self):
        phase = get_phase_by_provider_id("magic_transit")
        assert phase.friendly_name == "network_firewall_rules"

    def test_get_phase_by_provider_id_magic_transit_managed(self):
        phase = get_phase_by_provider_id("magic_transit_managed")
        assert phase.friendly_name == "network_firewall_managed"

    def test_get_phase_by_provider_id_magic_transit_ratelimit(self):
        phase = get_phase_by_provider_id("magic_transit_ratelimit")
        assert phase.friendly_name == "network_firewall_ratelimit"

    def test_get_phase_by_provider_id_magic_transit_ids_managed(self):
        phase = get_phase_by_provider_id("magic_transit_ids_managed")
        assert phase.friendly_name == "network_firewall_ids"

    def test_get_phase_by_provider_id_http_request_sanitize(self):
        phase = get_phase_by_provider_id("http_request_sanitize")
        assert phase.friendly_name == "url_normalization"


class TestSuggestPhase:
    def test_close_typo(self):
        assert suggest_phase("redirect_rule") == "redirect_rules"

    def test_missing_suffix(self):
        assert suggest_phase("cache_rule") == "cache_rules"

    def test_swapped_word(self):
        assert suggest_phase("origin_rule") == "origin_rules"

    def test_no_match(self):
        assert suggest_phase("zzz_totally_wrong") is None

    def test_exact_match(self):
        assert suggest_phase("redirect_rules") == "redirect_rules"

    def test_partial_prefix(self):
        # "waf_custom" is close enough to "waf_custom_rules"
        assert suggest_phase("waf_custom") == "waf_custom_rules"

    def test_provider_id_suggests_friendly_name(self):
        assert suggest_phase("http_request_dynamic_redirect") == "redirect_rules"

    def test_provider_id_cache_suggests_friendly(self):
        assert suggest_phase("http_request_cache_settings") == "cache_rules"

    def test_provider_id_ddos_l7_suggests_friendly(self):
        assert suggest_phase("ddos_l7") == "http_ddos_rules"

    def test_provider_id_magic_transit_suggests_friendly(self):
        assert suggest_phase("magic_transit") == "network_firewall_rules"

    def test_bulk_redirect_typo(self):
        assert suggest_phase("bulk_redirect_rule") == "bulk_redirect_rules"

    def test_network_firewall_typo(self):
        assert suggest_phase("network_firewall_rule") == "network_firewall_rules"


class TestUnknownPhaseMessage:
    def test_with_suggestion(self):
        msg = unknown_phase_message("redirect_rule")
        assert "Did you mean 'redirect_rules'?" in msg

    def test_without_suggestion(self):
        msg = unknown_phase_message("zzz_totally_wrong")
        assert "Valid phases:" in msg
        assert "redirect_rules" in msg

    def test_provider_id_suggests_friendly(self):
        msg = unknown_phase_message("http_request_dynamic_redirect")
        assert "Did you mean 'redirect_rules'?" in msg
