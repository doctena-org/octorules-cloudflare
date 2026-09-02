"""SSL/TLS zone settings: normalization, partial diffs, apply, and guardrails.

The section mirrors Cloudflare's SSL/TLS tab. Two things here are new to the
settings extensions and carry most of the risk:

* ``security_header`` is nested, so diffs and the post-apply read-back compare
  on subset semantics rather than equality, and apply sends a merged value.
* Some settings are legal but weaken security, so validation reports through
  both channels — errors for the incoherent, warnings for the merely dangerous.
"""

from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope

from octorules_cloudflare._zone_tls import (
    _SETTING_IDS,
    SECTION,
    _apply_zone_tls,
    _validate_zone_tls,
    diff_zone_tls,
    normalize_zone_tls,
)


def _scope():
    return Scope(zone_id="zone-1", label="example.com")


def _hsts(**over):
    """A full HSTS block as Cloudflare returns it (all five sub-keys)."""
    base = {
        "enabled": False,
        "max_age": 0,
        "include_subdomains": False,
        "preload": False,
        "nosniff": False,
    }
    base.update(over)
    return {"strict_transport_security": base}


def _check(settings):
    """Run validation, returning (errors, warnings)."""
    errors, warnings = [], []
    _validate_zone_tls({SECTION: settings}, "example.com", errors, warnings)
    return errors, warnings


class TestSettingIds:
    def test_zero_rtt_maps_to_the_api_id(self):
        """The API id is '0rtt', which is not a usable YAML identifier."""
        assert _SETTING_IDS["zero_rtt"] == "0rtt"

    def test_every_managed_setting_has_an_api_id(self):
        assert all(isinstance(v, str) and v for v in _SETTING_IDS.values())


class TestNormalization:
    def test_scalars_are_strings(self):
        out = normalize_zone_tls({"ssl": "full", "min_tls_version": "1.2", "tls_1_3": "zrt"})
        assert out == {"ssl": "full", "min_tls_version": "1.2", "tls_1_3": "zrt"}

    def test_nested_hsts_shape_is_preserved(self):
        out = normalize_zone_tls({"security_header": _hsts(enabled=True, max_age=31536000)})
        assert out["security_header"]["strict_transport_security"]["enabled"] is True

    def test_nosniff_is_carried(self):
        """The API returns five sub-keys; an earlier spec listed only four."""
        out = normalize_zone_tls({"security_header": _hsts(nosniff=True)})
        assert out["security_header"]["strict_transport_security"]["nosniff"] is True

    def test_non_dict_security_header_is_ignored(self):
        assert "security_header" not in normalize_zone_tls({"security_header": "on"})

    def test_empty_input(self):
        assert normalize_zone_tls({}) == {}


class TestPartialDiff:
    def test_matching_subset_is_no_change(self):
        current = {"security_header": _hsts(enabled=True, max_age=31536000)}
        desired = {"security_header": {"strict_transport_security": {"enabled": True}}}
        assert diff_zone_tls(current, desired).changes == []

    def test_differing_subset_is_a_change(self):
        current = {"security_header": _hsts(enabled=False)}
        desired = {"security_header": {"strict_transport_security": {"enabled": True}}}
        assert [c.field for c in diff_zone_tls(current, desired).changes] == ["security_header"]

    def test_unmentioned_subkeys_never_drive_a_diff(self):
        current = {"security_header": _hsts(enabled=True, max_age=99)}
        desired = {"security_header": {"strict_transport_security": {"enabled": True}}}
        assert diff_zone_tls(current, desired).changes == []

    def test_scalars_still_diff_on_equality(self):
        assert [c.field for c in diff_zone_tls({"ssl": "full"}, {"ssl": "strict"}).changes] == [
            "ssl"
        ]


class TestApplySendsCompleteValue:
    def test_desired_is_merged_onto_current(self):
        """A partial declaration must not reset the sub-keys it omits."""
        current = {"security_header": _hsts(enabled=False, max_age=31536000, nosniff=True)}
        desired = {"security_header": {"strict_transport_security": {"enabled": True}}}
        plan = diff_zone_tls(current, desired)

        provider = MagicMock()
        provider.get_zone_tls_settings.return_value = current
        _apply_zone_tls(None, [plan], _scope(), provider)

        sent = provider.update_zone_tls_settings.call_args[0][1]
        hsts = sent["security_header"]["strict_transport_security"]
        assert hsts["enabled"] is True
        assert hsts["max_age"] == 31536000, "an unmentioned sub-key must survive"
        assert hsts["nosniff"] is True, "an unmentioned sub-key must survive"


class TestEnumValidation:
    @pytest.mark.parametrize(
        ("field", "bad"),
        [
            ("ssl", "on"),
            ("min_tls_version", "1.4"),
            ("tls_1_3", "yes"),
            ("zero_rtt", "zrt"),
            ("always_use_https", "true"),
            ("automatic_https_rewrites", "1"),
        ],
    )
    def test_invalid_enum_is_an_error(self, field, bad):
        errors, _ = _check({field: bad})
        assert any(field in e for e in errors)

    @pytest.mark.parametrize("value", ["off", "flexible", "full", "strict"])
    def test_every_documented_ssl_mode_is_accepted(self, value):
        errors, _ = _check({"ssl": value})
        assert errors == []

    @pytest.mark.parametrize("value", ["on", "off", "zrt"])
    def test_every_documented_tls_1_3_value_is_accepted(self, value):
        errors, _ = _check({"tls_1_3": value})
        assert errors == []


class TestSecurityWarnings:
    """Legal settings whose consequence is easy to miss — warnings, not errors."""

    def test_flexible_ssl_warns(self):
        errors, warnings = _check({"ssl": "flexible"})
        assert errors == []
        assert any("flexible" in w and "plain" in w for w in warnings)

    def test_ssl_off_warns(self):
        _, warnings = _check({"ssl": "off"})
        assert any("no encryption" in w for w in warnings)

    def test_strict_does_not_warn(self):
        """Warning on the correct value is how warnings become noise."""
        errors, warnings = _check({"ssl": "strict"})
        assert (errors, warnings) == ([], [])

    def test_full_does_not_warn(self):
        assert _check({"ssl": "full"}) == ([], [])

    @pytest.mark.parametrize("version", ["1.0", "1.1"])
    def test_deprecated_tls_floor_warns(self, version):
        errors, warnings = _check({"min_tls_version": version})
        assert errors == []
        assert any("RFC 8996" in w for w in warnings)

    @pytest.mark.parametrize("version", ["1.2", "1.3"])
    def test_current_tls_floor_does_not_warn(self, version):
        assert _check({"min_tls_version": version}) == ([], [])


class TestCrossSettingChecks:
    def test_tls_13_floor_with_tls_13_disabled_is_an_error(self):
        errors, _ = _check({"min_tls_version": "1.3", "tls_1_3": "off"})
        assert any("requires TLS 1.3" in e for e in errors)

    def test_tls_13_floor_with_tls_13_on_is_fine(self):
        errors, _ = _check({"min_tls_version": "1.3", "tls_1_3": "on"})
        assert errors == []

    def test_no_rule_relates_tls_1_3_to_zero_rtt(self):
        """Cloudflare does not define 'zrt', so nothing here guesses at it."""
        for tls13 in ("on", "off", "zrt"):
            for zrt in ("on", "off"):
                errors, warnings = _check({"tls_1_3": tls13, "zero_rtt": zrt})
                assert errors == [], f"unexpected error for {tls13}/{zrt}"
                assert warnings == [], f"unexpected warning for {tls13}/{zrt}"


class TestHstsValidation:
    def test_valid_block_passes(self):
        errors, warnings = _check(
            {"security_header": _hsts(enabled=True, max_age=31536000, include_subdomains=True)}
        )
        assert (errors, warnings) == ([], [])

    def test_non_mapping_rejected(self):
        errors, _ = _check({"security_header": "on"})
        assert any("must be a mapping" in e for e in errors)

    def test_unknown_subkey_rejected(self):
        errors, _ = _check({"security_header": {"strict_transport_security": {"maxage": 1}}})
        assert any("unknown field" in e for e in errors)

    def test_unknown_top_level_key_rejected(self):
        errors, _ = _check({"security_header": {"x_frame_options": "DENY"}})
        assert any("unknown key" in e for e in errors)

    def test_non_integer_max_age_rejected(self):
        errors, _ = _check({"security_header": {"strict_transport_security": {"max_age": "1"}}})
        assert any("must be an integer" in e for e in errors)

    def test_negative_max_age_rejected(self):
        errors, _ = _check({"security_header": {"strict_transport_security": {"max_age": -1}}})
        assert any("must not be negative" in e for e in errors)

    def test_non_bool_flag_rejected(self):
        errors, _ = _check({"security_header": {"strict_transport_security": {"enabled": "y"}}})
        assert any("must be true or false" in e for e in errors)

    def test_enabled_with_zero_max_age_is_incoherent(self):
        errors, _ = _check({"security_header": _hsts(enabled=True, max_age=0)})
        assert any("max_age 0" in e for e in errors)

    def test_preload_without_include_subdomains_rejected(self):
        errors, _ = _check({"security_header": _hsts(enabled=True, preload=True, max_age=31536000)})
        assert any("requires include_subdomains" in e for e in errors)

    def test_preload_with_short_max_age_rejected(self):
        errors, _ = _check(
            {
                "security_header": _hsts(
                    enabled=True, preload=True, include_subdomains=True, max_age=86400
                )
            }
        )
        assert any("at least 31536000" in e for e in errors)

    def test_preload_with_always_use_https_off_rejected(self):
        """The preload list requires an HTTP-to-HTTPS redirect on the same host."""
        errors, _ = _check(
            {
                "always_use_https": "off",
                "security_header": _hsts(
                    enabled=True, preload=True, include_subdomains=True, max_age=31536000
                ),
            }
        )
        assert any("always_use_https is 'off'" in e for e in errors)

    def test_fully_compliant_preload_passes(self):
        errors, warnings = _check(
            {
                "always_use_https": "on",
                "security_header": _hsts(
                    enabled=True, preload=True, include_subdomains=True, max_age=31536000
                ),
            }
        )
        assert (errors, warnings) == ([], [])


class TestCiphers:
    """The one list-valued field: order-insensitive, with [] distinct from absent."""

    MODERN = (
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
    )

    # -- normalization ------------------------------------------------------
    def test_normalize_sorts_and_dedupes(self):
        raw = {"ciphers": ["ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA", "AES128-SHA"]}
        assert normalize_zone_tls(raw)["ciphers"] == [
            "AES128-SHA",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ]

    def test_normalize_keeps_the_empty_list(self):
        """[] is the zone's real stored state (use the default list), not absent."""
        assert normalize_zone_tls({"ciphers": []})["ciphers"] == []

    def test_normalize_drops_non_list_values(self):
        assert "ciphers" not in normalize_zone_tls({"ciphers": "AES128-SHA"})

    # -- diff ---------------------------------------------------------------
    def test_order_never_drives_a_diff(self):
        current = {"ciphers": sorted(self.MODERN)}
        desired = {"ciphers": list(reversed(sorted(self.MODERN)))}
        assert not diff_zone_tls(current, desired).has_changes

    def test_duplicates_never_drive_a_diff(self):
        current = {"ciphers": sorted(self.MODERN)}
        desired = {"ciphers": [*self.MODERN, self.MODERN[0]]}
        assert not diff_zone_tls(current, desired).has_changes

    def test_declared_empty_list_diffs_against_a_populated_zone(self):
        """ciphers: [] is a real instruction -- reset to Cloudflare's default."""
        plan = diff_zone_tls({"ciphers": sorted(self.MODERN)}, {"ciphers": []})
        assert [c.field for c in plan.changes] == ["ciphers"]
        assert plan.changes[0].desired == []

    def test_omitted_key_leaves_the_zone_list_alone(self):
        plan = diff_zone_tls({"ciphers": sorted(self.MODERN)}, {"ssl": "strict"})
        assert not any(c.field == "ciphers" for c in plan.changes)

    def test_matching_empty_lists_are_no_change(self):
        assert not diff_zone_tls({"ciphers": []}, {"ciphers": []}).has_changes

    def test_the_change_carries_the_canonical_list(self):
        plan = diff_zone_tls({"ciphers": []}, {"ciphers": list(reversed(sorted(self.MODERN)))})
        assert plan.changes[0].desired == sorted(self.MODERN)

    # -- apply --------------------------------------------------------------
    def test_apply_sends_the_canonical_list(self):
        from octorules_cloudflare.provider import CloudflareProvider

        provider = MagicMock(spec=CloudflareProvider)
        provider.get_zone_tls_settings.return_value = {}
        plan = diff_zone_tls({"ciphers": []}, {"ciphers": list(reversed(sorted(self.MODERN)))})
        _apply_zone_tls(MagicMock(), [plan], _scope(), provider)
        payload = provider.update_zone_tls_settings.call_args[0][1]
        assert payload["ciphers"] == sorted(self.MODERN)

    # -- validation ---------------------------------------------------------
    def test_modern_allowlist_is_clean(self):
        errors, warnings = _check({"ciphers": list(self.MODERN)})
        assert errors == []
        assert warnings == []

    def test_empty_list_is_clean(self):
        errors, warnings = _check({"ciphers": []})
        assert errors == []
        assert warnings == []

    def test_non_list_is_an_error(self):
        errors, _ = _check({"ciphers": "AES128-SHA"})
        assert any("must be a list" in e for e in errors)

    def test_non_string_entry_is_an_error(self):
        errors, _ = _check({"ciphers": [123]})
        assert any("non-empty strings" in e for e in errors)

    def test_duplicate_entry_is_an_error(self):
        errors, _ = _check({"ciphers": [*self.MODERN, self.MODERN[0]]})
        assert any("duplicate" in e for e in errors)

    def test_unknown_name_warns_but_does_not_fail(self):
        errors, warnings = _check({"ciphers": [*self.MODERN, "FUTURE-SUITE-X"]})
        assert errors == []
        assert any("FUTURE-SUITE-X" in w for w in warnings)

    def test_weak_suite_warns_naming_it(self):
        errors, warnings = _check({"ciphers": [*self.MODERN, "AES128-SHA"]})
        assert errors == []
        assert any("AES128-SHA" in w and "forward secrecy" in w for w in warnings)

    def test_handshake_observed_suite_is_recognised_and_weak(self):
        """ECDHE-ECDSA-AES256-SHA: absent from the docs table, seen live."""
        _, warnings = _check({"ciphers": [*self.MODERN, "ECDHE-ECDSA-AES256-SHA"]})
        assert not any("not in Cloudflare's published" in w for w in warnings)
        assert any("ECDHE-ECDSA-AES256-SHA" in w for w in warnings)

    def test_iana_style_name_is_an_error_not_an_unknown_warning(self):
        """The IANA vocabulary can never be right; a merely unknown name can."""
        errors, warnings = _check({"ciphers": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]})
        assert any("IANA-style" in e for e in errors)
        assert not any("not in Cloudflare's published" in w for w in warnings)

    def test_all_unknown_but_plausible_names_never_error(self):
        """Cloudflare adds suites; list freshness must not carry error weight."""
        errors, warnings = _check({"ciphers": ["FUTURE-SUITE-X", "FUTURE-SUITE-Y"]})
        assert errors == []
        assert any("FUTURE-SUITE-X" in w for w in warnings)

    def test_tls13_only_list_is_an_error_with_the_floor_hint(self):
        errors, _ = _check({"ciphers": ["AEAD-AES128-GCM-SHA256"]})
        assert any("min_tls_version" in e for e in errors)

    def test_tls13_names_are_not_unknown(self):
        _, warnings = _check({"ciphers": [*self.MODERN, "AEAD-AES128-GCM-SHA256"]})
        assert not any("not in Cloudflare's published" in w for w in warnings)
