"""Tests for plan linter (Category H)."""

import pytest
from octorules.linter.engine import LintContext
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_cloudflare.linter.plan_linter import lint_plan_tier


def _lint(rules_data, plan_tier="free"):
    ctx = LintContext(plan_tier=plan_tier)
    lint_plan_tier(rules_data, ctx)
    return ctx


class TestRegexAvailability:
    def test_cf500_regex_on_free_plan(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="free",
        )
        assert_lint(ctx, "CF500")

    def test_cf500_regex_on_pro_plan(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="pro",
        )
        assert_lint(ctx, "CF500")

    def test_cf500_regex_on_business_plan_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="business",
        )
        assert_no_lint(ctx, "CF500")

    def test_cf500_regex_on_enterprise_plan_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="enterprise",
        )
        assert_no_lint(ctx, "CF500")


class TestRuleLimits:
    def test_cf501_exceeds_free_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(11)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="free")
        assert_lint(ctx, "CF501")

    def test_cf501_within_free_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(10)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="free")
        assert_no_lint(ctx, "CF501")

    def test_cf501_enterprise_within_limit(self):
        # Enterprise allows 300 rules per rules-engine phase (CF changelog
        # 2025-02-12 raised it from 125).
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(200)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="enterprise")
        assert_no_lint(ctx, "CF501")

    def test_cf501_enterprise_over_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(301)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="enterprise")
        assert_lint(ctx, "CF501")

    def test_cf501_rate_limiting_free_limit_is_1(self):
        rules = [{"ref": f"rl-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(1)]
        ctx = _lint({"rate_limiting_rules": rules}, plan_tier="free")
        assert_no_lint(ctx, "CF501")
        rules.append({"ref": "rl-1", "expression": 'http.host eq "extra.com"'})
        ctx = _lint({"rate_limiting_rules": rules}, plan_tier="free")
        assert_lint(ctx, "CF501")

    @pytest.mark.parametrize(
        ("plan", "limit"),
        [("pro", 2), ("business", 5), ("enterprise", 100)],
    )
    def test_cf501_rate_limiting_per_plan_limits(self, plan, limit):
        rules = [
            {"ref": f"rl-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(limit)
        ]
        ctx = _lint({"rate_limiting_rules": rules}, plan_tier=plan)
        assert_no_lint(ctx, "CF501")
        rules.append({"ref": "rl-extra", "expression": 'http.host eq "extra.com"'})
        ctx = _lint({"rate_limiting_rules": rules}, plan_tier=plan)
        assert_lint(ctx, "CF501")

    def test_cf501_enterprise_waf_custom_limit_is_1000(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(1000)
        ]
        ctx = _lint({"waf_custom_rules": rules}, plan_tier="enterprise")
        assert_no_lint(ctx, "CF501")
        rules.append({"ref": "rule-1000", "expression": 'http.host eq "extra.com"'})
        ctx = _lint({"waf_custom_rules": rules}, plan_tier="enterprise")
        assert_lint(ctx, "CF501")


class TestNonPhaseKeysIgnored:
    def test_custom_rulesets_skipped(self):
        ctx = _lint({"custom_rulesets": [{"ref": "x"}]}, plan_tier="free")
        assert len(ctx.results) == 0

    def test_lists_skipped(self):
        ctx = _lint({"lists": [{"ref": "x"}]}, plan_tier="free")
        assert len(ctx.results) == 0
