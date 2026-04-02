"""Tests for custom ruleset validation (Category T)."""

from __future__ import annotations

from octorules.linter.engine import LintContext

from octorules_cloudflare.linter.custom_ruleset_linter import lint_custom_rulesets


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_custom_rulesets(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestCustomRulesetStructure:
    def test_cf022_missing_id(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {"name": "My Ruleset", "phase": "http_request_firewall_custom", "rules": []}
                ]
            }
        )
        assert "CF022" in _ids(ctx)

    def test_cf022_missing_name(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "CF022" in _ids(ctx)

    def test_cf022_missing_phase(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "rules": [],
                    }
                ]
            }
        )
        assert "CF022" in _ids(ctx)

    def test_cf022_all_present_no_error(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "CF022" not in _ids(ctx)


class TestCustomRulesetIdFormat:
    def test_cf023_invalid_id_format(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "not-a-hex-id",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "CF023" in _ids(ctx)

    def test_cf023_valid_hex_id(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "CF023" not in _ids(ctx)


class TestCustomRulesetDuplicateRefs:
    def test_cf024_duplicate_ref_within_ruleset(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {"ref": "rule1", "expression": "true", "action": "block"},
                            {"ref": "rule1", "expression": "true", "action": "log"},
                        ],
                    }
                ]
            }
        )
        assert "CF024" in _ids(ctx)

    def test_cf025_duplicate_ref_across_rulesets(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "Ruleset A",
                        "phase": "http_request_firewall_custom",
                        "rules": [{"ref": "shared-ref", "expression": "true", "action": "block"}],
                    },
                    {
                        "id": "def12345abc67890def12345abc67890",
                        "name": "Ruleset B",
                        "phase": "http_request_firewall_custom",
                        "rules": [{"ref": "shared-ref", "expression": "true", "action": "log"}],
                    },
                ]
            }
        )
        assert "CF025" in _ids(ctx)


class TestCF026RuleCount:
    def test_cf026_over_limit(self):
        rules = [{"ref": f"rule-{i}", "expression": "true", "action": "block"} for i in range(1001)]
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "Big Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": rules,
                    }
                ]
            }
        )
        assert "CF026" in _ids(ctx)

    def test_cf026_at_limit(self):
        rules = [{"ref": f"rule-{i}", "expression": "true", "action": "block"} for i in range(1000)]
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "Big Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": rules,
                    }
                ]
            }
        )
        assert "CF026" not in _ids(ctx)


class TestNoCustomRulesets:
    def test_no_custom_rulesets_no_errors(self):
        ctx = _lint({"waf_custom_rules": []})
        assert _ids(ctx) == []
