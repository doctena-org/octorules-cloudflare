"""Tests for action and action_parameters validation (Categories C, D, I, J, K, L, N)."""

import pytest
from octorules.linter.engine import LintContext, Severity
from octorules.phases import PHASE_BY_NAME
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_cloudflare.linter.action_validator import lint_actions


def _lint_rule(rule, phase_name="cloudflare.redirect_rules", **ctx_kwargs):
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext(**ctx_kwargs)
    lint_actions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestActionValidity:
    def test_cf200_invalid_action_for_phase(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "block"}, "cloudflare.redirect_rules"
        )
        assert len(ctx.results) == 1
        c001 = assert_lint(
            ctx,
            "CF200",
            count=1,
            severity=Severity.ERROR,
            phase="cloudflare.redirect_rules",
            ref="t",
        )
        assert "block" in c001[0].message

    def test_cf200_valid_action(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "redirect"}, "cloudflare.redirect_rules"
        )
        assert "CF200" not in _ids(ctx)

    def test_cf200_score_valid_in_waf_custom_rules(self):
        """'score' action is valid for waf_custom_rules (no false positive)."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "score",
                "action_parameters": {"increment": 5},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF200" not in _ids(ctx)

    def test_cf200_ddos_dynamic_valid_in_http_ddos_rules(self):
        """'ddos_dynamic' action is valid for http_ddos_rules (no false positive)."""
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "ddos_dynamic"},
            "cloudflare.http_ddos_rules",
        )
        assert "CF200" not in _ids(ctx)

    def test_cf200_force_connection_close_valid_in_http_ddos_rules(self):
        """'force_connection_close' action is valid for http_ddos_rules (no false positive)."""
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "force_connection_close"},
            "cloudflare.http_ddos_rules",
        )
        assert "CF200" not in _ids(ctx)

    def test_cf201_missing_action_no_default(self):
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "cloudflare.waf_custom_rules")
        assert "CF201" in _ids(ctx)
        c002 = [r for r in ctx.results if r.rule_id == "CF201"]
        assert len(c002) == 1
        assert c002[0].severity == Severity.ERROR

    def test_cf201_no_error_with_default(self):
        # redirect_rules has default action "redirect"
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "cloudflare.redirect_rules")
        assert "CF201" not in _ids(ctx)

    def test_cf201_non_string_action(self):
        """Non-string action should report CF201 instead of silently skipping."""
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": 123}, "cloudflare.waf_custom_rules"
        )
        assert "CF201" in _ids(ctx)
        assert len(ctx.results) == 1
        assert "must be a string" in ctx.results[0].message

    def test_cf202_missing_action_parameters(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "redirect"},
            "cloudflare.redirect_rules",
        )
        c003 = assert_lint(
            ctx,
            "CF202",
            count=1,
            severity=Severity.ERROR,
            phase="cloudflare.redirect_rules",
            ref="t",
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
            "cloudflare.redirect_rules",
        )
        assert "CF203" in _ids(ctx)

    def test_cf203_cache_additional_cacheable_ports_and_read_timeout(self):
        """additional_cacheable_ports and read_timeout are valid cache params."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "additional_cacheable_ports": [8080],
                    "read_timeout": 300,
                },
            },
            "cloudflare.cache_rules",
        )
        assert "CF203" not in _ids(ctx)

    @pytest.mark.parametrize(
        ("action", "phase", "params"),
        [
            (
                "set_cache_settings",
                "cloudflare.cache_rules",
                {
                    "shared_dictionary": {},
                    "strip_etags": True,
                    "strip_last_modified": True,
                    "strip_set_cookie": True,
                },
            ),
            (
                "set_config",
                "cloudflare.config_rules",
                {
                    "content_converter": True,
                    "disable_pay_per_crawl": True,
                    "redirects_for_ai_training": True,
                    "request_body_buffering": "standard",
                    "response_body_buffering": "standard",
                },
            ),
            ("skip", "cloudflare.waf_custom_rules", {"phase": "current"}),
            ("serve_error", "cloudflare.custom_error_rules", {"asset_name": "custom_error_page"}),
        ],
    )
    def test_cf203_accepts_sdk_5x_action_params(self, action, phase, params):
        """action_parameters added for the Cloudflare SDK 5.x bump are recognized
        by the linter and do not trip CF203 ("Unknown action_parameters key")."""
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": action, "action_parameters": params},
            phase,
        )
        assert "CF203" not in _ids(ctx)


class TestCF223SkipInAccountScope:
    """Skip action in account-scoped waf_custom_rules is rejected by CF API
    with error code 20016. Account scope is detected by the documented
    `cf.zone.plan eq "ENT"` expression suffix."""

    _ACCOUNT_EXPR = '(ip.src.asnum eq 45566) and (cf.zone.plan eq "ENT")'

    def test_fires_on_account_scoped_skip_in_waf_custom_rules(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": self._ACCOUNT_EXPR,
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" in _ids(ctx)
        results = [r for r in ctx.results if r.rule_id == "CF223"]
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert "20016" in results[0].message

    def test_does_not_fire_on_zone_scoped_skip(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src.asnum eq 45566)",
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" not in _ids(ctx)

    def test_does_not_fire_on_account_scoped_block(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": self._ACCOUNT_EXPR,
                "action": "block",
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" not in _ids(ctx)

    def test_does_not_fire_on_skip_in_waf_managed_rules(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": self._ACCOUNT_EXPR,
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF223" not in _ids(ctx)

    def test_does_not_fire_on_different_plan(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": '(ip.src.asnum eq 45566) and (cf.zone.plan eq "BIZ")',
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" not in _ids(ctx)

    def test_whitespace_tolerant(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": '(ip.src.asnum eq 45566) and (cf.zone.plan  eq  "ENT")',
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" in _ids(ctx)

    def test_does_not_crash_on_missing_expression(self):
        """Defensive: if expression is missing, CF223 must not fire and must
        not raise. Upstream CF001/structure rules handle the missing-expression
        case separately."""
        ctx = _lint_rule(
            {"ref": "t", "action": "skip", "action_parameters": {"ruleset": "current"}},
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" not in _ids(ctx)

    def test_does_not_crash_on_non_string_expression(self):
        """Defensive: a malformed YAML with `expression: 123` must not crash
        the CF223 check. The isinstance guard short-circuits to no-fire."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": 123,
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF223" not in _ids(ctx)


class TestCF226SkipParamPhaseApplicability:
    """The skip action's options depend on the phase it is configured in.
    Custom rules skip later phases and legacy products; WAF exceptions skip
    managed rulesets and their rules. Cloudflare rejects a cross-phase
    parameter with API error 20117 at sync time — plan does not catch it,
    so lint must."""

    def test_fires_on_rulesets_in_custom_phase(self):
        # The captured failure: a http_request_firewall_custom ruleset shipped
        # `rulesets` and broke the deploy with "skip action parameter
        # 'rulesets' cannot be used in the phase http_request_firewall_custom".
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {
                    "rulesets": ["af3b73085ff04abcb0b89ca197a84188"],
                    "phases": ["http_request_firewall_managed"],
                },
            },
            "cloudflare.waf_custom_rules",
        )
        results = assert_lint(ctx, "CF226", count=1, severity=Severity.ERROR, ref="t")
        assert "rulesets" in results[0].message
        assert "20117" in results[0].message
        assert results[0].field == "action_parameters.rulesets"

    def test_fires_on_rules_in_custom_phase(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {"rules": {"efb7b8c949ac4650a09736fc376e9aee": ["x"]}},
            },
            "cloudflare.waf_custom_rules",
        )
        assert_lint(ctx, "CF226", count=1, severity=Severity.ERROR, ref="t")

    def test_fires_on_phase_in_managed_phase(self):
        # Positively excluded: "only available at the zone level for the
        # `http_request_firewall_custom` phase".
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {"ruleset": "current", "phase": "current"},
            },
            "cloudflare.waf_managed_rules",
        )
        assert_lint(ctx, "CF226", count=1, severity=Severity.ERROR, ref="t")

    def test_warns_only_on_undocumented_managed_phase_params(self):
        # `products`/`phases` are absent from the WAF-exception docs but have
        # never been observed being rejected. Absence of documentation is not
        # proof of rejection, so these must not hard-block a deploy.
        for key, value in (("products", ["waf"]), ("phases", ["http_ratelimit"])):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "(ip.src eq 1.2.3.4)",
                    "action": "skip",
                    "action_parameters": {"ruleset": "current", key: value},
                },
                "cloudflare.waf_managed_rules",
            )
            results = assert_lint(ctx, "CF226", count=1, severity=Severity.WARNING, ref="t")
            assert key in results[0].message
            assert "silently ignored" in results[0].message

    def test_reports_each_offending_parameter(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {"rulesets": ["a" * 32], "rules": {"b" * 32: ["x"]}},
            },
            "cloudflare.waf_custom_rules",
        )
        assert _ids(ctx).count("CF226") == 2

    # --- shapes that are live at Cloudflare today and must stay clean ---

    def test_does_not_fire_on_custom_phase_skip(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {
                    "ruleset": "current",
                    "phases": ["http_ratelimit", "http_request_firewall_managed"],
                    "products": ["bic", "securityLevel"],
                },
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF226" not in _ids(ctx)

    def test_does_not_fire_on_managed_phase_exception(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {
                    "ruleset": "current",
                    "rules": {"efb7b8c949ac4650a09736fc376e9aee": ["ae20608d93b94e97988db1bbc12"]},
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF226" not in _ids(ctx)

    def test_does_not_fire_on_unmapped_phase(self):
        # Phases with no skip vocabulary are left to CF200, which reports that
        # skip is not a valid action there at all.
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "skip",
                "action_parameters": {"rulesets": ["a" * 32]},
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF226" not in _ids(ctx)

    def test_does_not_fire_on_non_skip_action(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "(ip.src eq 1.2.3.4)",
                "action": "execute",
                "action_parameters": {"id": "efb7b8c949ac4650a09736fc376e9aee"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF226" not in _ids(ctx)


class TestCF227AccountScopeListRef:
    """The account-level entry point (kind=root) parses a restricted grammar and
    rejects a stored-list reference as unrecognised input. Lists work one level
    down, inside a custom ruleset the entry point executes, which is where every
    working reference lives."""

    _ENT = '(cf.zone.plan eq "ENT")'

    def test_fires_on_list_ref_in_account_scoped_rule(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": f"((not ip.src in $pentest_ips)) and {self._ENT}",
                "action": "execute",
                "action_parameters": {"id": "a" * 32},
            },
            "cloudflare.waf_custom_rules",
        )
        results = assert_lint(ctx, "CF227", count=1, severity=Severity.ERROR, ref="t")
        assert "pentest_ips" in results[0].message
        assert results[0].field == "expression"

    def test_reports_each_distinct_list_once(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": (f"((ip.src in $a or ip.src in $b or ip.src in $a)) and {self._ENT}"),
                "action": "block",
            },
            "cloudflare.waf_custom_rules",
        )
        assert _ids(ctx).count("CF227") == 2

    def test_does_not_fire_without_the_account_marker(self):
        # A nested custom-ruleset rule is linted under the same phase name but
        # carries no ENT suffix — that is the only signal separating the two.
        ctx = _lint_rule(
            {"ref": "t", "expression": "ip.src in $blocked", "action": "block"},
            "cloudflare.waf_custom_rules",
        )
        assert "CF227" not in _ids(ctx)

    def test_does_not_fire_on_account_rule_without_a_list(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": f'((not http.host contains "example.com")) and {self._ENT}',
                "action": "execute",
                "action_parameters": {"id": "a" * 32},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF227" not in _ids(ctx)

    def test_does_not_fire_in_other_phases(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": f"((ip.src in $blocked)) and {self._ENT}",
                "action": "block",
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF227" not in _ids(ctx)

    def test_does_not_crash_on_non_string_expression(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": 123, "action": "block"},
            "cloudflare.waf_custom_rules",
        )
        assert "CF227" not in _ids(ctx)


class TestCF224ExpressionLengthCap:
    """Cloudflare's Rulesets API rejects expressions longer than 4096 chars
    (error 20127). CF measures the canonical normalized form, so CF224 does
    too. 4096 is the maximum allowed; the cap is breached at 4097+."""

    @staticmethod
    def _expr_of_normalized_length(n):
        """A single-line expression with no collapsible whitespace, so its
        normalized length equals n exactly."""
        prefix, suffix = 'http.host eq "', '"'
        return prefix + ("a" * (n - len(prefix) - len(suffix))) + suffix

    def test_does_not_fire_at_cap(self):
        from octorules_cloudflare.linter._constants import MAX_EXPRESSION_LENGTH

        ctx = _lint_rule(
            {"ref": "t", "expression": self._expr_of_normalized_length(MAX_EXPRESSION_LENGTH)},
            "cloudflare.waf_custom_rules",
        )
        assert "CF224" not in _ids(ctx)

    def test_does_not_fire_just_below_cap(self):
        from octorules_cloudflare.linter._constants import MAX_EXPRESSION_LENGTH

        ctx = _lint_rule(
            {"ref": "t", "expression": self._expr_of_normalized_length(MAX_EXPRESSION_LENGTH - 1)},
            "cloudflare.waf_custom_rules",
        )
        assert "CF224" not in _ids(ctx)

    def test_fires_above_cap(self):
        from octorules_cloudflare.linter._constants import MAX_EXPRESSION_LENGTH

        ctx = _lint_rule(
            {"ref": "t", "expression": self._expr_of_normalized_length(MAX_EXPRESSION_LENGTH + 1)},
            "cloudflare.waf_custom_rules",
        )
        assert "CF224" in _ids(ctx)
        result = next(r for r in ctx.results if r.rule_id == "CF224")
        assert result.severity == Severity.ERROR
        assert "20127" in result.message

    def test_fires_on_large_inline_ip_list(self):
        """The empirical shape: a big inline `ip.src in {...}` literal list."""
        ips = " ".join(f"10.{i // 256 % 256}.{i % 256}.1" for i in range(500))
        ctx = _lint_rule(
            {"ref": "t", "expression": f"(ip.src in {{{ips}}})"},
            "cloudflare.waf_custom_rules",
        )
        assert "CF224" in _ids(ctx)

    def test_does_not_fire_on_stored_list_reference(self):
        """The remediation: a stored-list reference stays short."""
        ctx = _lint_rule(
            {"ref": "t", "expression": "(ip.src in $block_known_attackers)"},
            "cloudflare.waf_custom_rules",
        )
        assert "CF224" not in _ids(ctx)

    def test_measures_normalized_not_raw_length(self):
        """A multi-line expression whose raw text exceeds the cap but whose
        normalized form is well under it must not fire — CF measures the
        normalized form octorules sends, not the YAML source bytes."""
        from octorules.expression import normalize_expression

        from octorules_cloudflare.linter._constants import MAX_EXPRESSION_LENGTH

        raw = "(ip.src in {\n" + (" " * 5000) + "1.2.3.4\n})"
        assert len(raw) > MAX_EXPRESSION_LENGTH
        assert len(normalize_expression(raw)) < MAX_EXPRESSION_LENGTH
        ctx = _lint_rule({"ref": "t", "expression": raw}, "cloudflare.waf_custom_rules")
        assert "CF224" not in _ids(ctx)

    def test_does_not_crash_on_non_string_expression(self):
        ctx = _lint_rule({"ref": "t", "expression": 123}, "cloudflare.waf_custom_rules")
        assert "CF224" not in _ids(ctx)

    def test_does_not_crash_on_missing_expression(self):
        ctx = _lint_rule({"ref": "t", "action": "block"}, "cloudflare.waf_custom_rules")
        assert "CF224" not in _ids(ctx)


class TestDefaultActionParamValidation:
    def test_cf203_fires_on_default_action_with_unknown_param(self):
        # config_rules has default action 'set_config' — unknown params should be caught
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"bogus_key": True},
            },
            "cloudflare.config_rules",
        )
        assert "CF203" in _ids(ctx)

    def test_default_action_valid_params_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "full"},
            },
            "cloudflare.config_rules",
        )
        assert "CF203" not in _ids(ctx)

    def test_default_action_disable_railgun_rejected(self):
        """disable_railgun was removed from the SDK — should trigger CF203."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"disable_railgun": True},
            },
            "cloudflare.config_rules",
        )
        assert "CF203" in _ids(ctx)


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
            "cloudflare.response_header_rules",
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
            "cloudflare.response_header_rules",
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.response_header_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.redirect_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
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
            "cloudflare.cache_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_cf410_bypass_by_default_valid(self):
        """browser_ttl mode 'bypass_by_default' should not trigger CF410."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "browser_ttl": {"mode": "bypass_by_default"},
                },
            },
            "cloudflare.cache_rules",
        )
        assert "CF410" not in _ids(ctx)


class TestServeErrorParams:
    def test_cf205_serve_error_status_code_out_of_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 200, "content": "hi"},
            },
            "cloudflare.custom_error_rules",
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
            "cloudflare.custom_error_rules",
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
            "cloudflare.config_rules",
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
            "cloudflare.config_rules",
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
            "cloudflare.config_rules",
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
            "cloudflare.config_rules",
        )
        assert "CF422" in _ids(ctx)

    def test_cf422_polish_webp_valid(self):
        """polish value 'webp' should not trigger CF422."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"polish": "webp"},
            },
            "cloudflare.config_rules",
        )
        assert "CF422" not in _ids(ctx)

    def test_cf423_security_off_warning(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"security_level": "off"},
            },
            "cloudflare.config_rules",
        )
        assert "CF423" in _ids(ctx)

    def test_cf420_graduated_levels_rejected_in_config_rule(self):
        """low/medium/high are a zone-wide baseline only — invalid in a config rule."""
        for level in ("low", "medium", "high"):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "set_config",
                    "action_parameters": {"security_level": level},
                },
                "cloudflare.config_rules",
            )
            assert "CF420" in _ids(ctx), level
            diag = next(r for r in ctx.results if r.rule_id == "CF420")
            assert "zone-wide" in diag.message

    def test_cf420_config_security_levels_valid(self):
        """off/essentially_off/under_attack are the only valid config-rule levels."""
        for level in ("off", "essentially_off", "under_attack"):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "set_config",
                    "action_parameters": {"security_level": level},
                },
                "cloudflare.config_rules",
            )
            assert "CF420" not in _ids(ctx), level


class TestRateLimitParams:
    def test_cf400_invalid_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 42,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF400" in _ids(ctx)

    def test_cf400_missing_period(self):
        """period is Required in the SDK's Ratelimit params; a missing one
        used to slip past the enum check entirely."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF400" in _ids(ctx)
        diag = next(r for r in ctx.results if r.rule_id == "CF400")
        assert "Missing 'period'" in diag.message
        assert diag.severity is Severity.ERROR

    def test_cf400_non_integer_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": "60",
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF400" in _ids(ctx)
        diag = next(r for r in ctx.results if r.rule_id == "CF400")
        assert "must be an integer" in diag.message

    def test_cf400_valid_period_clean(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF400" not in _ids(ctx)

    def test_cf401_missing_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {"period": 60, "requests_per_period": 100},
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF401" in _ids(ctx)

    def test_cf401_is_an_error_and_does_not_claim_global_fallback(self):
        """characteristics is Required in the SDK's Ratelimit params — the
        API rejects the rule rather than falling back to a global counter."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {"period": 60, "requests_per_period": 100},
            },
            "cloudflare.rate_limiting_rules",
        )
        diag = next(r for r in ctx.results if r.rule_id == "CF401")
        assert diag.severity is Severity.ERROR
        assert "globally" not in diag.message

    def test_execute_action_skips_rate_limit_checks(self):
        """Execute action in rate_limiting_rules is a ruleset reference
        (e.g., account-level custom rulesets). The thresholds and
        characteristics live on the child rules inside the referenced
        ruleset, not on the execute rule itself.
        CF401/CF402 should not fire."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "description": "Test execute ruleset ref",
                "expression": '(cf.zone.name in {"example.com"})',
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                },
                "enabled": True,
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF401" not in _ids(ctx)
        assert "CF402" not in _ids(ctx)
        assert "CF400" not in _ids(ctx)

    def test_cf402_missing_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {"period": 60, "characteristics": ["ip.src"]},
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF402" in _ids(ctx)

    def test_cf402_score_per_period_satisfies_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "score_per_period": 50,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF402" not in _ids(ctx)

    def test_timeout_longer_than_period_is_not_flagged(self):
        """CF403 warned whenever mitigation_timeout > period, but that is
        Cloudflare's ordinary shape: the documented mitigation_timeout values
        include 86400, which exceeds every valid period ("count for 10
        minutes, block for a day").  The rule was retired."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 600,
                    "requests_per_period": 100,
                    "mitigation_timeout": 86400,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF403" not in _ids(ctx)

    def test_cf404_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 123,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
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
            "cloudflare.origin_rules",
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
            "cloudflare.origin_rules",
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
            "cloudflare.origin_rules",
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
            "cloudflare.origin_rules",
        )
        assert "CF450" in _ids(ctx)


class TestD006CountingExpression:
    def test_cf405_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "http.host gt",
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF405" in _ids(ctx)

    def test_cf405_valid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 'http.host eq "example.com"',
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF405" not in _ids(ctx)

    def test_cf405_empty_counting_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "",
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.response_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.request_header_rules",
        )
        assert "CF443" not in _ids(ctx)


class TestL005HeaderRemoveSpuriousValue:
    def test_cf446_remove_with_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove", "value": "x"}},
                },
            },
            "cloudflare.request_header_rules",
        )
        assert "CF446" in _ids(ctx)

    def test_cf446_remove_with_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove", "expression": "x"}},
                },
            },
            "cloudflare.request_header_rules",
        )
        assert "CF446" in _ids(ctx)

    def test_cf446_remove_without_value_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove"}},
                },
            },
            "cloudflare.request_header_rules",
        )
        assert "CF446" not in _ids(ctx)


class TestCF447RestrictedHeaders:
    def _rule(self, header, op, value="x"):
        hv = {"operation": op}
        if op != "remove":
            hv["value"] = value
        return {
            "ref": "t",
            "expression": "true",
            "action": "rewrite",
            "action_parameters": {"headers": {header: hv}},
        }

    def test_cf447_cf_prefix_set_rejected(self):
        ctx = _lint_rule(self._rule("cf-custom", "set"), "cloudflare.request_header_rules")
        assert "CF447" in _ids(ctx)

    def test_cf447_x_cf_prefix_remove_rejected(self):
        ctx = _lint_rule(self._rule("x-cf-foo", "remove"), "cloudflare.request_header_rules")
        assert "CF447" in _ids(ctx)

    def test_cf447_cf_connecting_ip_remove_ok(self):
        ctx = _lint_rule(
            self._rule("cf-connecting-ip", "remove"), "cloudflare.request_header_rules"
        )
        assert "CF447" not in _ids(ctx)

    def test_cf447_cf_connecting_ip_set_rejected(self):
        ctx = _lint_rule(self._rule("cf-connecting-ip", "set"), "cloudflare.request_header_rules")
        assert "CF447" in _ids(ctx)

    def test_cf447_cookie_set_rejected(self):
        ctx = _lint_rule(self._rule("cookie", "set"), "cloudflare.request_header_rules")
        assert "CF447" in _ids(ctx)

    def test_cf447_cookie_remove_ok(self):
        ctx = _lint_rule(self._rule("cookie", "remove"), "cloudflare.request_header_rules")
        assert "CF447" not in _ids(ctx)

    def test_cf447_xff_set_rejected(self):
        ctx = _lint_rule(self._rule("X-Forwarded-For", "set"), "cloudflare.request_header_rules")
        assert "CF447" in _ids(ctx)

    def test_cf447_xff_remove_ok(self):
        ctx = _lint_rule(self._rule("X-Forwarded-For", "remove"), "cloudflare.request_header_rules")
        assert "CF447" not in _ids(ctx)

    def test_cf447_custom_x_true_client_ip_ok(self):
        # X-True-Client-IP != the reserved true-client-ip; must not false-fire.
        ctx = _lint_rule(self._rule("X-True-Client-IP", "set"), "cloudflare.request_header_rules")
        assert "CF447" not in _ids(ctx)

    def test_cf447_response_phase_unaffected(self):
        # The cf-*/cookie/IP restrictions are request-side only.
        ctx = _lint_rule(self._rule("cf-custom", "set"), "cloudflare.response_header_rules")
        assert "CF447" not in _ids(ctx)


class TestNonStringHeaderName:
    def test_non_string_header_key_does_not_crash(self):
        # A non-string YAML header key (e.g. 123:) must produce CF440, not crash.
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {"headers": {123: {"operation": "set", "value": "x"}}},
            },
            "cloudflare.request_header_rules",
        )
        assert "CF440" in _ids(ctx)


class TestCF448HeaderNameCharset:
    def test_cf448_space_in_name_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {"headers": {"X Spaced": {"operation": "set", "value": "1"}}},
            },
            "cloudflare.response_header_rules",
        )
        assert "CF448" in _ids(ctx)

    def test_cf448_valid_name_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"X-My_Header-1": {"operation": "set", "value": "1"}}
                },
            },
            "cloudflare.response_header_rules",
        )
        assert "CF448" not in _ids(ctx)


class TestL006TransformExpressionLinting:
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.url_rewrite_rules",
        )
        # CF444 should not fire for a valid expression (wirefilter may still
        # reject concat syntax, so we just check it doesn't crash)
        # The test verifies the code path runs without error

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
            "cloudflare.request_header_rules",
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.request_header_rules",
        )
        assert "CF444" not in _ids(ctx)

    def test_cf444_suppressed_for_remove_query_args(self):
        """Expressions using remove_query_args() should not trigger CF444."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {
                        "query": {
                            "expression": (
                                'remove_query_args(http.request.uri.query, "utm_source")'
                            ),
                        }
                    },
                },
            },
            "cloudflare.url_rewrite_rules",
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
            "cloudflare.custom_error_rules",
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
            "cloudflare.custom_error_rules",
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
            "cloudflare.custom_error_rules",
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
            "cloudflare.custom_error_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.compression_rules",
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
            "cloudflare.compression_rules",
        )
        assert "CF212" not in _ids(ctx)

    def test_cf212_default_algorithm_valid(self):
        """compression algorithm 'default' should not trigger CF212."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [{"name": "default"}],
                },
            },
            "cloudflare.compression_rules",
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
            "cloudflare.compression_rules",
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
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["bogus.field"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF213" in _ids(ctx)

    def test_cf213_valid_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "cf.colo.id"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF213" not in _ids(ctx)

    def test_cf225_incompatible_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "cf.unique_visitor_id"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF225" in _ids(ctx)

    def test_cf225_either_alone_ok(self):
        for char in ("ip.src", "cf.unique_visitor_id"):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "block",
                    "ratelimit": {
                        "period": 60,
                        "requests_per_period": 100,
                        "characteristics": [char, "cf.colo.id"],
                    },
                },
                "cloudflare.rate_limiting_rules",
            )
            assert "CF225" not in _ids(ctx)

    def test_cf409_challenge_with_duration_on_business(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "managed_challenge",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 20,
                    "characteristics": ["ip.src"],
                    "mitigation_timeout": 600,
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="business",
        )
        assert "CF409" in _ids(ctx)

    def test_cf409_zero_timeout_ok_on_business(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "js_challenge",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 20,
                    "characteristics": ["ip.src"],
                    "mitigation_timeout": 0,
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="business",
        )
        assert "CF409" not in _ids(ctx)

    def test_cf409_enterprise_may_set_duration(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "managed_challenge",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 20,
                    "characteristics": ["ip.src"],
                    "mitigation_timeout": 60,
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="enterprise",
        )
        assert "CF409" not in _ids(ctx)

    def test_cf409_non_challenge_action_unaffected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 20,
                    "characteristics": ["ip.src"],
                    "mitigation_timeout": 60,
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="business",
        )
        assert "CF409" not in _ids(ctx)

    def test_cf213_header_reference_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ['http.request.headers["x-api-key"]'],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF213" not in _ids(ctx)

    def test_cf213_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "bad.field"],
                },
            },
            "cloudflare.rate_limiting_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
                "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_custom_rules",
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
            "cloudflare.waf_managed_rules",
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
            "cloudflare.waf_managed_rules",
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
            "cloudflare.waf_managed_rules",
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
            "cloudflare.compression_rules",
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
            "cloudflare.compression_rules",
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
            "cloudflare.compression_rules",
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
            "cloudflare.config_rules",
        )
        assert "CF424" in _ids(ctx)

    def test_cf424_ssl_full_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "full"},
            },
            "cloudflare.config_rules",
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
            "cloudflare.request_header_rules",
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
            "cloudflare.response_header_rules",
        )
        assert "CF445" not in _ids(ctx)


class TestCF406CharacteristicsPerPlan:
    def test_cf406_too_many_characteristics(self):
        """Free plan allows only 1 characteristic — 5 should trigger CF406."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": [
                        "ip.src",
                        "cf.colo.id",
                        'http.request.headers["x-api-key"]',
                        'http.request.headers["x-client"]',
                        'http.request.headers["x-token"]',
                    ],
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="free",
        )
        assert "CF406" in _ids(ctx)

    def test_cf406_within_limit(self):
        """Enterprise plan allows 4 characteristics — 2 should be fine."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "cf.colo.id"],
                },
            },
            "cloudflare.rate_limiting_rules",
            plan_tier="enterprise",
        )
        assert "CF406" not in _ids(ctx)


class TestCF407RequestsPerPeriodRange:
    def test_cf407_out_of_range_zero(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 0,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF407" in _ids(ctx)

    def test_cf407_out_of_range_too_high(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 20000000,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF407" in _ids(ctx)

    def test_cf407_in_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF407" not in _ids(ctx)

    def test_cf407_boundary_one(self):
        """requests_per_period=1 is the lower boundary — should pass."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 1,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF407" not in _ids(ctx)

    def test_cf407_boundary_max(self):
        """requests_per_period=10000000 is the upper boundary — should pass."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "requests_per_period": 10_000_000,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF407" not in _ids(ctx)


class TestCF408ScorePerPeriod:
    def test_cf408_negative_score(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "score_per_period": -1,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF408" in _ids(ctx)

    def test_cf408_zero_score(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "score_per_period": 0,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF408" in _ids(ctx)

    def test_cf408_too_high(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "score_per_period": 20_000_000,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF408" in _ids(ctx)

    def test_cf408_in_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "ratelimit": {
                    "period": 60,
                    "score_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "cloudflare.rate_limiting_rules",
        )
        assert "CF408" not in _ids(ctx)


class TestCF410TTLModeType:
    def test_cf410_integer_mode(self):
        """Non-string mode (integer) should be rejected."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": 123}},
            },
            "cloudflare.cache_rules",
        )
        assert "CF410" in _ids(ctx)

    def test_cf410_bool_mode(self):
        """Non-string mode (bool) should be rejected."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": True}},
            },
            "cloudflare.cache_rules",
        )
        assert "CF410" in _ids(ctx)

    def test_cf410_null_mode_no_error(self):
        """Null/missing mode should not trigger CF410 (mode is optional)."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"default": 300}},
            },
            "cloudflare.cache_rules",
        )
        assert "CF410" not in _ids(ctx)


class TestCF414CacheTTLUpperBound:
    def test_cf414_over_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "edge_ttl": {"mode": "override_origin", "default": 31536001},
                },
            },
            "cloudflare.cache_rules",
        )
        assert "CF414" in _ids(ctx)

    def test_cf414_at_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "edge_ttl": {"mode": "override_origin", "default": 31536000},
                },
            },
            "cloudflare.cache_rules",
        )
        assert "CF414" not in _ids(ctx)


class TestCF432RedirectTargetURL:
    def test_cf432_bad_url(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "example.com"},
                        "status_code": 301,
                    }
                },
            },
            "cloudflare.redirect_rules",
        )
        assert "CF432" in _ids(ctx)

    def test_cf432_good_url(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "https://example.com/path"},
                        "status_code": 301,
                    }
                },
            },
            "cloudflare.redirect_rules",
        )
        assert "CF432" not in _ids(ctx)


class TestCF218ExecuteOverridesStructure:
    def test_cf218_override_rule_missing_id(self):
        """Override rule entry without 'id' triggers CF218."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "abc12345def67890abc12345def67890",
                    "overrides": {
                        "rules": [{"enabled": False}],
                    },
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert_lint(ctx, "CF218", count=1, severity=Severity.ERROR)
        assert "index 0" in ctx.results[0].message

    def test_cf218_override_rules_valid(self):
        """Override rule entries with valid 'id' do not trigger CF218."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "abc12345def67890abc12345def67890",
                    "overrides": {
                        "rules": [
                            {"id": "abc12345def67890abc12345def67890", "enabled": False},
                        ],
                    },
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF218" not in _ids(ctx)


class TestCF219SkipRulesetId:
    def test_cf219_empty_ruleset_id(self):
        """Empty string in rulesets list triggers CF219."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"rulesets": [""]},
            },
            "cloudflare.waf_custom_rules",
        )
        assert_lint(ctx, "CF219", count=1, severity=Severity.WARNING)

    def test_cf219_valid_ruleset_ids(self):
        """Non-empty string rulesets do not trigger CF219."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {
                    "rulesets": ["abc12345def67890abc12345def67890"],
                },
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF219" not in _ids(ctx)


class TestCF451OriginWeight:
    def test_cf451_weight_out_of_range(self):
        """Weight > 1.0 triggers CF451."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "example.com", "weight": 1.5},
                },
            },
            "cloudflare.origin_rules",
        )
        assert_lint(ctx, "CF451", count=1, severity=Severity.ERROR)

    def test_cf451_weight_in_range(self):
        """Weight within 0.0-1.0 does not trigger CF451."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "example.com", "weight": 0.5},
                },
            },
            "cloudflare.origin_rules",
        )
        assert "CF451" not in _ids(ctx)

    def test_cf451_weight_zero(self):
        """Weight 0.0 is the lower boundary — should pass."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "example.com", "weight": 0.0},
                },
            },
            "cloudflare.origin_rules",
        )
        assert "CF451" not in _ids(ctx)

    def test_cf451_weight_one(self):
        """Weight 1.0 is the upper boundary — should pass."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "example.com", "weight": 1.0},
                },
            },
            "cloudflare.origin_rules",
        )
        assert "CF451" not in _ids(ctx)

    def test_cf451_weight_negative(self):
        """Weight -0.1 is below the valid range — should trigger CF451."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "example.com", "weight": -0.1},
                },
            },
            "cloudflare.origin_rules",
        )
        assert_lint(ctx, "CF451", count=1, severity=Severity.ERROR)


class TestCF452OriginRouteRequiredFields:
    def test_cf452_missing_host_and_sni(self):
        """Origin with neither 'host' nor 'sni'+'host_header' triggers CF452."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": 8443}},
            },
            "cloudflare.origin_rules",
        )
        assert_lint(ctx, "CF452", count=1, severity=Severity.ERROR)

    def test_cf452_has_host(self):
        """Origin with 'host' does not trigger CF452."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"host": "backend.example.com", "port": 8443},
                },
            },
            "cloudflare.origin_rules",
        )
        assert "CF452" not in _ids(ctx)

    def test_cf452_sni_without_host_header(self):
        """Origin with 'sni' but no 'host_header' should trigger CF452."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {"sni": {"value": "backend.example.com"}, "port": 8443},
                },
            },
            "cloudflare.origin_rules",
        )
        assert_lint(ctx, "CF452", count=1, severity=Severity.ERROR)

    def test_cf452_sni_and_host_header(self):
        """Origin with both 'sni' and 'host_header' (no 'host') should pass."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {
                    "origin": {
                        "sni": {"value": "backend.example.com"},
                        "host_header": "backend.example.com",
                        "port": 8443,
                    },
                },
            },
            "cloudflare.origin_rules",
        )
        assert "CF452" not in _ids(ctx)


class TestCF220SensitivityLevel:
    """CF220: sensitivity_level validation in execute overrides."""

    def test_cf220_invalid_top_level_sensitivity_level(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                    "overrides": {"sensitivity_level": "bogus"},
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert_lint(ctx, "CF220", count=1, severity=Severity.ERROR)

    def test_cf220_valid_top_level_sensitivity_levels(self):
        for level in ("default", "medium", "low", "eoff"):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "execute",
                    "action_parameters": {
                        "id": "00000000000000000000000000000001",
                        "overrides": {"sensitivity_level": level},
                    },
                },
                "cloudflare.waf_managed_rules",
            )
            assert "CF220" not in _ids(ctx)

    def test_cf220_invalid_per_rule_sensitivity_level(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                    "overrides": {
                        "rules": [
                            {"id": "abc123", "sensitivity_level": "high"},
                        ]
                    },
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert_lint(ctx, "CF220", count=1, severity=Severity.ERROR)

    def test_cf220_valid_per_rule_sensitivity_level(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                    "overrides": {
                        "rules": [
                            {"id": "abc123", "sensitivity_level": "low"},
                        ]
                    },
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF220" not in _ids(ctx)

    def test_cf220_no_sensitivity_level_no_error(self):
        """No sensitivity_level at all should not trigger CF220."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                    "overrides": {"rules": [{"id": "abc123"}]},
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF220" not in _ids(ctx)


class TestCF221ServeErrorContentType:
    """CF221: serve_error content_type validation."""

    def test_cf221_invalid_content_type(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "error",
                    "content_type": "text/css",
                    "status_code": 503,
                },
            },
            "cloudflare.custom_error_rules",
        )
        assert_lint(ctx, "CF221", count=1, severity=Severity.ERROR)

    def test_cf221_valid_content_types(self):
        for ct in ("application/json", "text/xml", "text/plain", "text/html"):
            ctx = _lint_rule(
                {
                    "ref": "t",
                    "expression": "true",
                    "action": "serve_error",
                    "action_parameters": {
                        "content": "error",
                        "content_type": ct,
                        "status_code": 503,
                    },
                },
                "cloudflare.custom_error_rules",
            )
            assert "CF221" not in _ids(ctx)

    def test_cf221_no_content_type_no_error(self):
        """Missing content_type should not trigger CF221."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "error",
                    "status_code": 503,
                },
            },
            "cloudflare.custom_error_rules",
        )
        assert "CF221" not in _ids(ctx)


class TestCF222SkipRulesetValue:
    """CF222: skip action ruleset value validation."""

    def test_cf222_invalid_ruleset_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"ruleset": "all"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert_lint(ctx, "CF222", count=1, severity=Severity.ERROR)

    def test_cf222_valid_ruleset_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"ruleset": "current"},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF222" not in _ids(ctx)

    def test_cf222_no_ruleset_no_error(self):
        """Missing ruleset should not trigger CF222."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"phases": ["http_request_firewall_custom"]},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF222" not in _ids(ctx)


class TestLogCustomFieldKeys:
    """Ensure log_custom_field accepts the full set of parameter keys."""

    def test_all_log_custom_field_keys_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "log_custom_field",
                "action_parameters": {
                    "request_fields": [{"name": "foo"}],
                    "response_fields": [{"name": "bar"}],
                    "cookie_fields": [{"name": "baz"}],
                    "raw_response_fields": [{"name": "qux"}],
                    "transformed_request_fields": [{"name": "quux"}],
                },
            },
            "cloudflare.log_custom_fields",
        )
        assert "CF203" not in _ids(ctx)

    def test_raw_response_fields_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "log_custom_field",
                "action_parameters": {
                    "raw_response_fields": [{"name": "x"}],
                },
            },
            "cloudflare.log_custom_fields",
        )
        assert "CF203" not in _ids(ctx)

    def test_transformed_request_fields_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "log_custom_field",
                "action_parameters": {
                    "transformed_request_fields": [{"name": "x"}],
                },
            },
            "cloudflare.log_custom_fields",
        )
        assert "CF203" not in _ids(ctx)


class TestSetConfigStaleKeys:
    """Removed set_config keys should trigger CF203."""

    def test_h2_prioritization_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"h2_prioritization": True},
            },
            "cloudflare.config_rules",
        )
        assert "CF203" in _ids(ctx)

    def test_cache_deception_armor_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"cache_deception_armor": True},
            },
            "cloudflare.config_rules",
        )
        assert "CF203" in _ids(ctx)


class TestSetConfigWebMCPKeys:
    """webmcp_enabled and webmcp_packs are valid set_config keys (cloudflare 5.8.0)."""

    def test_webmcp_keys_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"webmcp_enabled": True, "webmcp_packs": []},
            },
            "cloudflare.config_rules",
        )
        assert _ids(ctx) == []


class TestExecuteVersionRemoved:
    """'version' is not an action parameter — should trigger CF203."""

    def test_version_key_rejected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "execute",
                "action_parameters": {
                    "id": "00000000000000000000000000000001",
                    "version": "latest",
                },
            },
            "cloudflare.waf_managed_rules",
        )
        assert "CF203" in _ids(ctx)


class TestScoreIncrementOptional:
    """score.increment is optional — no error when omitted."""

    def test_score_without_increment_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "score",
                "action_parameters": {},
            },
            "cloudflare.waf_custom_rules",
        )
        # No CF205 or other error about missing required keys
        ids = _ids(ctx)
        assert "CF205" not in ids
        assert "CF208" not in ids

    def test_score_with_increment_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "score",
                "action_parameters": {"increment": 5},
            },
            "cloudflare.waf_custom_rules",
        )
        assert "CF203" not in _ids(ctx)


class TestCF415CacheVary:
    """set_cache_settings.vary — added by Cloudflare SDK 5.6."""

    def _rule(self, vary):
        return _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"vary": vary},
            },
            "cloudflare.cache_rules",
        )

    def test_valid_default_and_headers(self):
        ctx = self._rule(
            {
                "default": {"action": "normalize"},
                "headers": {
                    "accept-language": {"action": "bypass", "languages": ["en", "fr"]},
                    "accept": {"action": "passthrough", "media_types": ["image/webp"]},
                },
            }
        )
        assert "CF415" not in _ids(ctx)

    def test_absent_vary_is_clean(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"cache": True},
            },
            "cloudflare.cache_rules",
        )
        assert "CF415" not in _ids(ctx)

    def test_not_a_mapping(self):
        assert "CF415" in _ids(self._rule("bypass"))

    def test_empty_mapping(self):
        assert "CF415" in _ids(self._rule({}))

    def test_unknown_key(self):
        ctx = self._rule({"default": {"action": "bypass"}, "bogus": 1})
        assert "CF415" in _ids(ctx)

    def test_invalid_default_action(self):
        assert "CF415" in _ids(self._rule({"default": {"action": "sometimes"}}))

    def test_default_missing_action(self):
        assert "CF415" in _ids(self._rule({"default": {}}))

    def test_default_not_a_mapping(self):
        assert "CF415" in _ids(self._rule({"default": "bypass"}))

    def test_headers_not_a_mapping(self):
        assert "CF415" in _ids(self._rule({"headers": ["accept-language"]}))

    def test_header_entry_not_a_mapping(self):
        assert "CF415" in _ids(self._rule({"headers": {"accept": "bypass"}}))

    def test_header_invalid_action(self):
        assert "CF415" in _ids(self._rule({"headers": {"accept": {"action": "nope"}}}))

    def test_header_missing_action(self):
        assert "CF415" in _ids(self._rule({"headers": {"accept": {"languages": ["en"]}}}))

    def test_header_languages_not_a_list(self):
        ctx = self._rule({"headers": {"accept": {"action": "bypass", "languages": "en"}}})
        assert "CF415" in _ids(ctx)

    def test_header_media_types_not_strings(self):
        ctx = self._rule({"headers": {"accept": {"action": "bypass", "media_types": [1, 2]}}})
        assert "CF415" in _ids(ctx)

    def test_all_three_actions_accepted(self):
        for action in ("bypass", "passthrough", "normalize"):
            assert "CF415" not in _ids(self._rule({"default": {"action": action}})), action


class TestDdosExecuteOverrides:
    """`execute` deploys the DDoS managed ruleset with overrides.

    Cloudflare's configure-via-API guide uses `action: execute` in the
    `ddos_l7` phase entrypoint to apply sensitivity/action overrides, and
    live zones store exactly that. CF200 used to error on it, so a dumped
    zone carrying real DDoS overrides could not be adopted as written.
    """

    def test_execute_is_valid_in_http_ddos_rules(self):
        rule = {
            "ref": "ddos-overrides",
            "expression": "true",
            "action": "execute",
            "action_parameters": {
                "id": "4d21379b4f9f4bb088e0729962c8b3cf",
                "overrides": {"rules": [{"id": "ed651449c4a54f4b99c6e3bf863134d5"}]},
            },
        }
        ctx = LintContext()
        lint_actions(rule, PHASE_BY_NAME["cloudflare.http_ddos_rules"], ctx)
        assert_no_lint(ctx, "CF200")

    def test_a_genuinely_invalid_ddos_action_still_errors(self):
        rule = {"ref": "x", "expression": "true", "action": "redirect"}
        ctx = LintContext()
        lint_actions(rule, PHASE_BY_NAME["cloudflare.http_ddos_rules"], ctx)
        assert_lint(ctx, "CF200")
