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
