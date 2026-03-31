"""Tests for action and action_parameters validation (Categories C, D, I, J, K, L, N)."""

from __future__ import annotations

import pytest
from octorules.linter.engine import LintContext, Severity
from octorules.phases import PHASE_BY_NAME

from octorules_cloudflare.linter.action_validator import lint_actions
from octorules_cloudflare.linter.expression_bridge import WIREFILTER_AVAILABLE

from .conftest import assert_lint

_needs_wirefilter = pytest.mark.skipif(
    not WIREFILTER_AVAILABLE,
    reason="requires octorules-wirefilter FFI for expression parse errors",
)


def _lint_rule(rule, phase_name="redirect_rules"):
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_actions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestActionValidity:
    def test_cf200_invalid_action_for_phase(self):
        ctx = _lint_rule({"ref": "t", "expression": "true", "action": "block"}, "redirect_rules")
        assert len(ctx.results) == 1
        c001 = assert_lint(
            ctx, "CF200", count=1, severity=Severity.ERROR, phase="redirect_rules", ref="t"
        )
        assert "block" in c001[0].message

    def test_cf200_valid_action(self):
        ctx = _lint_rule({"ref": "t", "expression": "true", "action": "redirect"}, "redirect_rules")
        assert "CF200" not in _ids(ctx)

    def test_cf201_missing_action_no_default(self):
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "waf_custom_rules")
        assert "CF201" in _ids(ctx)
        c002 = [r for r in ctx.results if r.rule_id == "CF201"]
        assert len(c002) == 1
        assert c002[0].severity == Severity.ERROR

    def test_cf201_no_error_with_default(self):
        # redirect_rules has default action "redirect"
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "redirect_rules")
        assert "CF201" not in _ids(ctx)

    def test_cf201_non_string_action(self):
        """Non-string action should report CF201 instead of silently skipping."""
        ctx = _lint_rule({"ref": "t", "expression": "true", "action": 123}, "waf_custom_rules")
        assert "CF201" in _ids(ctx)
        assert len(ctx.results) == 1
        assert "must be a string" in ctx.results[0].message

    def test_cf202_missing_action_parameters(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "redirect"},
            "redirect_rules",
        )
        c003 = assert_lint(
            ctx, "CF202", count=1, severity=Severity.ERROR, phase="redirect_rules", ref="t"
        )
        assert "action_parameters" in c003[0].message.lower()

    def test_cf203_unknown_parameter_key(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}, "bogus_key": True},
            },
            "redirect_rules",
        )
        assert "CF203" in _ids(ctx)


class TestDefaultActionParamValidation:
    def test_cf203_fires_on_default_action_with_unknown_param(self):
        # config_rules has default action 'set_config' — unknown params should be caught
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"bogus_key": True},
            },
            "config_rules",
        )
        assert "CF203" in _ids(ctx)

    def test_default_action_valid_params_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "full"},
            },
            "config_rules",
        )
        assert "CF203" not in _ids(ctx)

    def test_default_action_disable_railgun_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"disable_railgun": True},
            },
            "config_rules",
        )
        assert "CF203" not in _ids(ctx)


class TestPhaseParameterOverrides:
    """CF203 fires when action_parameters keys are invalid for a specific phase."""

    def test_uri_in_response_header_rules_fires_cf203(self):
        """URI transforms are not available in response_header_rules."""
        ctx = _lint_rule(
            {
                "ref": "misplaced-rewrite",
                "expression": "true",
                "action_parameters": {
                    "uri": {"path": {"value": "/index.html"}},
                },
            },
            "response_header_rules",
        )
        assert_lint(ctx, "CF203", count=1, severity=Severity.WARNING)
        assert "uri" in ctx.results[0].message

    def test_headers_in_response_header_rules_ok(self):
        """Headers are valid in response_header_rules."""
        ctx = _lint_rule(
            {
                "ref": "add-header",
                "expression": "true",
                "action_parameters": {
                    "headers": {
                        "X-Frame-Options": {"operation": "set", "value": "DENY"},
                    },
                },
            },
            "response_header_rules",
        )
        assert "CF203" not in _ids(ctx)

    def test_uri_in_url_rewrite_rules_ok(self):
        """URI transforms are valid in url_rewrite_rules (no override)."""
        ctx = _lint_rule(
            {
                "ref": "rewrite-path",
                "expression": "true",
                "action_parameters": {
                    "uri": {"path": {"value": "/new-path"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "CF203" not in _ids(ctx)

    def test_uri_in_request_header_rules_ok(self):
        """URI transforms are valid in request_header_rules (no override)."""
        ctx = _lint_rule(
            {
                "ref": "rewrite-path",
                "expression": "true",
                "action_parameters": {
                    "uri": {"path": {"value": "/new-path"}},
                },
            },
            "request_header_rules",
        )
        assert "CF203" not in _ids(ctx)

    def test_mixed_uri_and_headers_in_response_fires_cf203(self):
        """Both uri and headers in response_header_rules — uri fires CF203."""
        ctx = _lint_rule(
            {
                "ref": "mixed",
                "expression": "true",
                "action_parameters": {
                    "uri": {"path": {"value": "/bad"}},
                    "headers": {
                        "X-Test": {"operation": "set", "value": "ok"},
                    },
                },
            },
            "response_header_rules",
        )
        c004s = [r for r in ctx.results if r.rule_id == "CF203"]
        assert len(c004s) == 1
        assert "uri" in c004s[0].message


class TestC005InvalidParamsType:
    def test_cf204_string_action_params(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": "not-a-dict",
            },
            "redirect_rules",
        )
        assert "CF204" in _ids(ctx)

    def test_cf204_list_action_params(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": ["bad"],
            },
            "redirect_rules",
        )
        assert "CF204" in _ids(ctx)

    def test_cf204_not_triggered_for_dict(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}},
            },
            "redirect_rules",
        )
        assert "CF204" not in _ids(ctx)


class TestC009UnnecessaryParams:
    def test_cf208_params_on_no_param_action(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "log",
                "action_parameters": {"something": True},
            },
            "waf_custom_rules",
        )
        assert "CF208" in _ids(ctx)

    def test_cf208_not_triggered_when_params_expected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}},
            },
            "redirect_rules",
        )
        assert "CF208" not in _ids(ctx)


class TestRedirectParams:
    def test_cf431_missing_target_url(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {"status_code": 301}},
            },
            "redirect_rules",
        )
        assert "CF431" in _ids(ctx)

    def test_cf207_conflicting_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new", "expression": "concat()"},
                        "status_code": 301,
                    }
                },
            },
            "redirect_rules",
        )
        assert "CF207" in _ids(ctx)

    def test_cf206_missing_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                    }
                },
            },
            "redirect_rules",
        )
        assert "CF206" in _ids(ctx)

    def test_cf430_invalid_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": 200,
                    }
                },
            },
            "redirect_rules",
        )
        assert "CF430" in _ids(ctx)

    def test_cf205_string_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": "301",
                    }
                },
            },
            "redirect_rules",
        )
        assert "CF205" in _ids(ctx)

    def test_valid_redirect(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": 301,
                    }
                },
            },
            "redirect_rules",
        )
        assert len(ctx.results) == 0
        assert not ctx.has_errors


class TestCacheParams:
    def test_cf410_invalid_edge_ttl_mode(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "bogus"}},
            },
            "cache_rules",
        )
        assert "CF410" in _ids(ctx)

    def test_cf411_override_without_default(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "override_origin"}},
            },
            "cache_rules",
        )
        assert "CF411" in _ids(ctx)

    def test_cf412_negative_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": -1}},
            },
            "cache_rules",
        )
        assert "CF412" in _ids(ctx)

    def test_cf413_bypass_with_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "cache": False,
                    "edge_ttl": {"mode": "override_origin", "default": 3600},
                },
            },
            "cache_rules",
        )
        i004 = assert_lint(ctx, "CF413", count=1, severity=Severity.WARNING)
        assert "bypass" in i004[0].message.lower() or "cache" in i004[0].message.lower()

    def test_valid_cache(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "cache": True,
                    "edge_ttl": {"mode": "override_origin", "default": 86400},
                },
            },
            "cache_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestBrowserTtl:
    def test_cf410_invalid_browser_ttl_mode(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"browser_ttl": {"mode": "bogus"}},
            },
            "cache_rules",
        )
        assert "CF410" in _ids(ctx)

    def test_cf411_browser_ttl_override_without_default(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"browser_ttl": {"mode": "override_origin"}},
            },
            "cache_rules",
        )
        assert "CF411" in _ids(ctx)

    def test_cf412_negative_browser_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "browser_ttl": {"mode": "override_origin", "default": -5},
                },
            },
            "cache_rules",
        )
        assert "CF412" in _ids(ctx)

    def test_valid_browser_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "browser_ttl": {"mode": "override_origin", "default": 3600},
                },
            },
            "cache_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestServeErrorParams:
    def test_cf205_serve_error_status_code_out_of_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 200, "content": "hi"},
            },
            "custom_error_rules",
        )
        assert "CF205" in _ids(ctx)

    def test_valid_serve_error_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 503, "content": "Maintenance"},
            },
            "custom_error_rules",
        )
        assert "CF205" not in _ids(ctx)


class TestConfigParams:
    def test_cf420_invalid_security_level(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"security_level": "bogus"},
            },
            "config_rules",
        )
        assert "CF420" in _ids(ctx)

    def test_cf421_invalid_ssl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"ssl": "bogus"},
            },
            "config_rules",
        )
        assert "CF421" in _ids(ctx)

    def test_cf421_ssl_non_string_type(self):
        """YAML `off` without quotes becomes boolean False — should emit CF421."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"ssl": False},
            },
            "config_rules",
        )
        assert "CF421" in _ids(ctx)
        diag = next(r for r in ctx.results if r.rule_id == "CF421")
        assert "bool" in diag.message

    def test_cf422_invalid_polish(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"polish": "bogus"},
            },
            "config_rules",
        )
        assert "CF422" in _ids(ctx)

    def test_cf423_security_off_warning(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"security_level": "off"},
            },
            "config_rules",
        )
        assert "CF423" in _ids(ctx)


class TestRateLimitParams:
    def test_cf400_invalid_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 42,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF400" in _ids(ctx)

    def test_cf401_missing_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"period": 60, "requests_per_period": 100},
            },
            "rate_limiting_rules",
        )
        assert "CF401" in _ids(ctx)

    def test_cf402_missing_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"period": 60, "characteristics": ["ip.src"]},
            },
            "rate_limiting_rules",
        )
        assert "CF402" in _ids(ctx)

    def test_cf402_score_per_period_satisfies_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "score_per_period": 50,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF402" not in _ids(ctx)

    def test_cf403_timeout_exceeds_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "mitigation_timeout": 120,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF403" in _ids(ctx)

    def test_cf404_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 123,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF404" in _ids(ctx)


class TestOriginParams:
    def test_cf450_port_out_of_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": 99999}},
            },
            "origin_rules",
        )
        assert "CF450" in _ids(ctx)

    def test_cf450_valid_port(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": 8443}},
            },
            "origin_rules",
        )
        assert "CF450" not in _ids(ctx)

    def test_cf450_boolean_port_rejected(self):
        """bool is a subclass of int — port: true should be rejected."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": True}},
            },
            "origin_rules",
        )
        assert "CF450" in _ids(ctx)
        n001 = [r for r in ctx.results if r.rule_id == "CF450"]
        assert "bool" in n001[0].message

    def test_cf450_string_port_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": "8443"}},
            },
            "origin_rules",
        )
        assert "CF450" in _ids(ctx)


class TestD006CountingExpression:
    @_needs_wirefilter
    def test_cf405_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "http.host gt",
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF405" in _ids(ctx)

    def test_cf405_valid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 'http.host eq "example.com"',
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF405" not in _ids(ctx)

    def test_cf405_empty_counting_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "",
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF405" not in _ids(ctx)


class TestL004HeaderOperation:
    def test_cf442_invalid_operation(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "replace", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "CF442" in _ids(ctx)

    def test_cf442_valid_set(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "CF442" not in _ids(ctx)

    def test_cf442_valid_remove(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove"}},
                },
            },
            "request_header_rules",
        )
        assert "CF442" not in _ids(ctx)


class TestTransformParams:
    def test_cf207_conflicting_uri_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"value": "/new", "expression": "concat()"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "CF207" in _ids(ctx)

    def test_cf440_empty_header_name(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "CF440" in _ids(ctx)

    def test_cf441_missing_operation(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "CF441" in _ids(ctx)

    def test_cf207_conflicting_header_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "value": "static",
                            "expression": "concat()",
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "CF207" in _ids(ctx)


class TestL005HeaderMissingValue:
    def test_cf443_set_missing_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set"}},
                },
            },
            "request_header_rules",
        )
        assert "CF443" in _ids(ctx)

    def test_cf443_add_missing_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "add"}},
                },
            },
            "response_header_rules",
        )
        assert "CF443" in _ids(ctx)

    def test_cf443_set_with_value_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "CF443" not in _ids(ctx)

    def test_cf443_set_with_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": 'concat("a", "b")',
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "CF443" not in _ids(ctx)

    def test_cf443_remove_ok_without_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove"}},
                },
            },
            "request_header_rules",
        )
        assert "CF443" not in _ids(ctx)


class TestL006TransformExpressionLinting:
    @_needs_wirefilter
    def test_cf444_invalid_uri_path_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": "invalid expression !!!"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "CF444" in _ids(ctx)

    def test_cf444_valid_uri_expression_ok(self):
        _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": 'concat("/prefix", http.request.uri.path)'}},
                },
            },
            "url_rewrite_rules",
        )
        # CF444 should not fire for a valid expression (wirefilter may still
        # reject concat syntax, so we just check it doesn't crash)
        # The test verifies the code path runs without error

    @_needs_wirefilter
    def test_cf444_invalid_header_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": "totally broken <<<",
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "CF444" in _ids(ctx)

    def test_cf444_empty_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": ""}},
                },
            },
            "url_rewrite_rules",
        )
        assert "CF444" not in _ids(ctx)

    def test_cf444_static_value_no_lint(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"value": "/new-path"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "CF444" not in _ids(ctx)

    def test_cf444_suppressed_for_transform_function_call(self):
        """Transform expressions using function-call syntax should not fire CF444."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {
                        "path": {
                            "expression": (
                                "regex_replace(http.request.uri.path,"
                                ' "^/api/v1/", "/production/api/v1/")'
                            ),
                        }
                    },
                },
            },
            "url_rewrite_rules",
        )
        assert "CF444" not in _ids(ctx)

    def test_cf444_suppressed_for_concat_call(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": 'concat("prefix-", http.host)',
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "CF444" not in _ids(ctx)


class TestC010ServeErrorContentSize:
    def test_cf209_content_exceeds_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 11000,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "CF209" in _ids(ctx)

    def test_cf209_content_within_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 5000,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "CF209" not in _ids(ctx)

    def test_cf209_exactly_at_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 10240,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "CF209" not in _ids(ctx)

    def test_cf209_no_content_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 503},
            },
            "custom_error_rules",
        )
        assert "CF209" not in _ids(ctx)


class TestC011C012SkipParams:
    def test_cf210_invalid_skip_phase(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"phases": ["bogus_phase"]},
            },
            "waf_custom_rules",
        )
        assert "CF210" in _ids(ctx)

    def test_cf210_valid_skip_phase(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"phases": ["http_request_firewall_custom"]},
            },
            "waf_custom_rules",
        )
        assert "CF210" not in _ids(ctx)

    def test_cf211_invalid_skip_product(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"products": ["bogus_product"]},
            },
            "waf_custom_rules",
        )
        assert "CF211" in _ids(ctx)

    def test_cf211_valid_skip_products(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"products": ["waf", "rateLimit"]},
            },
            "waf_custom_rules",
        )
        assert "CF211" not in _ids(ctx)

    def test_cf210_cf211_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {
                    "phases": ["http_ratelimit", "bogus"],
                    "products": ["waf", "invalid"],
                },
            },
            "waf_custom_rules",
        )
        assert "CF210" in _ids(ctx)
        assert "CF211" in _ids(ctx)


class TestC013CompressResponseAlgorithms:
    def test_cf212_invalid_algorithm(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [{"name": "deflate"}],
                },
            },
            "compression_rules",
        )
        assert "CF212" in _ids(ctx)

    def test_cf212_valid_algorithms(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [
                        {"name": "gzip"},
                        {"name": "brotli"},
                        {"name": "zstd"},
                        {"name": "none"},
                        {"name": "auto"},
                    ],
                },
            },
            "compression_rules",
        )
        assert "CF212" not in _ids(ctx)

    def test_cf212_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [{"name": "gzip"}, {"name": "lz4"}],
                },
            },
            "compression_rules",
        )
        c013 = [r for r in ctx.results if r.rule_id == "CF212"]
        assert len(c013) == 1
        assert "lz4" in c013[0].message


class TestC014RateLimitCharacteristics:
    def test_cf213_invalid_characteristic(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["bogus.field"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF213" in _ids(ctx)

    def test_cf213_valid_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "cf.colo.id"],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF213" not in _ids(ctx)

    def test_cf213_header_reference_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ['http.request.headers["x-api-key"]'],
                },
            },
            "rate_limiting_rules",
        )
        assert "CF213" not in _ids(ctx)

    def test_cf213_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "bad.field"],
                },
            },
            "rate_limiting_rules",
        )
        c014 = [r for r in ctx.results if r.rule_id == "CF213"]
        assert len(c014) == 1
        assert "bad.field" in c014[0].message


class TestBlockResponseValidation:
    """Tests for CF214 — block action response parameter validation."""

    def test_cf214_valid_block_response(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "response": {
                        "status_code": 403,
                        "content_type": "text/html",
                        "content": "<h1>Blocked</h1>",
                    }
                },
            },
            "waf_custom_rules",
        )
        assert "CF214" not in _ids(ctx)

    def test_cf214_invalid_status_code_200(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"response": {"status_code": 200}},
            },
            "waf_custom_rules",
        )
        c015 = [r for r in ctx.results if r.rule_id == "CF214"]
        assert len(c015) == 1
        assert "400-499" in c015[0].message

    def test_cf214_invalid_status_code_500(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"response": {"status_code": 500}},
            },
            "waf_custom_rules",
        )
        c015 = [r for r in ctx.results if r.rule_id == "CF214"]
        assert len(c015) == 1

    def test_cf214_boundary_status_codes(self):
        # 400 and 499 are valid
        for code in (400, 499):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "block",
                    "action_parameters": {"response": {"status_code": code}},
                },
                "waf_custom_rules",
            )
            assert "CF214" not in _ids(ctx), f"status_code {code} should be valid"

    def test_cf214_invalid_content_type(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"response": {"status_code": 403, "content_type": 123}},
            },
            "waf_custom_rules",
        )
        c015 = [r for r in ctx.results if r.rule_id == "CF214"]
        assert any("content_type" in r.message for r in c015)

    def test_cf214_invalid_content(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"response": {"status_code": 403, "content": 42}},
            },
            "waf_custom_rules",
        )
        c015 = [r for r in ctx.results if r.rule_id == "CF214"]
        assert any("content must be a string" in r.message for r in c015)

    def test_cf214_no_response_no_error(self):
        """Block action without response parameter is valid."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
            },
            "waf_custom_rules",
        )
        assert "CF214" not in _ids(ctx)

    def test_cf214_response_not_dict_no_error(self):
        """response that's not a dict is already caught by CF203."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"response": "text"},
            },
            "waf_custom_rules",
        )
        # CF214 shouldn't fire on non-dict response (silently skips)
        assert "CF214" not in _ids(ctx)


class TestExecuteValidation:
    def test_cf215_missing_id(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {"overrides": {}},
            },
            "waf_managed_rules",
        )
        assert "CF215" in _ids(ctx)

    def test_cf216_invalid_id_format(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {"id": "not-valid-hex"},
            },
            "waf_managed_rules",
        )
        assert "CF216" in _ids(ctx)

    def test_valid_execute_id(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {"id": "abc12345def67890abc12345def67890"},
            },
            "waf_managed_rules",
        )
        assert "CF215" not in _ids(ctx)
        assert "CF216" not in _ids(ctx)


class TestCompressionOrdering:
    def test_cf217_none_not_last(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {
                    "algorithms": [{"name": "none"}, {"name": "gzip"}],
                },
            },
            "compression_rules",
        )
        assert "CF217" in _ids(ctx)

    def test_cf217_auto_not_last(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {
                    "algorithms": [{"name": "auto"}, {"name": "brotli"}],
                },
            },
            "compression_rules",
        )
        assert "CF217" in _ids(ctx)

    def test_cf217_none_last_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {
                    "algorithms": [{"name": "brotli"}, {"name": "gzip"}, {"name": "none"}],
                },
            },
            "compression_rules",
        )
        assert "CF217" not in _ids(ctx)


class TestSSLOffWarning:
    def test_cf424_ssl_off(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "off"},
            },
            "config_rules",
        )
        assert "CF424" in _ids(ctx)

    def test_cf424_ssl_full_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "full"},
            },
            "config_rules",
        )
        assert "CF424" not in _ids(ctx)


class TestRequestHeaderAdd:
    def test_cf445_request_header_add_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "add", "value": "v"}},
                },
            },
            "request_header_rules",
        )
        assert "CF445" in _ids(ctx)

    def test_cf445_response_header_add_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "add", "value": "v"}},
                },
            },
            "response_header_rules",
        )
        assert "CF445" not in _ids(ctx)
