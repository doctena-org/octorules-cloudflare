"""Integration tests for Cloudflare lint plugin — end-to-end lint_zone_file tests."""

from __future__ import annotations

from octorules.linter.engine import (
    Severity,
    lint_zone_file,
)


class TestLintZoneFile:
    def test_valid_rules_no_errors(self):
        ctx = lint_zone_file(
            {
                "redirect_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.host eq "example.com"',
                        "action": "redirect",
                        "action_parameters": {
                            "from_value": {
                                "target_url": {"value": "/new"},
                                "status_code": 301,
                            }
                        },
                    }
                ]
            }
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_missing_ref_caught(self):
        ctx = lint_zone_file({"redirect_rules": [{"expression": "true"}]})
        m001 = [r for r in ctx.results if r.rule_id == "CF003"]
        assert len(m001) == 1

    def test_unknown_phase_caught(self):
        ctx = lint_zone_file({"bogus_phase": []})
        m007 = [r for r in ctx.results if r.rule_id == "CF009"]
        assert len(m007) == 1

    def test_severity_filter_works(self):
        ctx = lint_zone_file(
            {"redirect_rules": [{"expression": "true"}]},
            severity_filter=Severity.ERROR,
        )
        assert all(r.severity == Severity.ERROR for r in ctx.results)

    def test_file_path_and_zone_name(self):
        ctx = lint_zone_file(
            {"redirect_rules": []},
            file_path="/tmp/test.yaml",
            zone_name="example.com",
        )
        assert ctx.file_path == "/tmp/test.yaml"
        assert ctx.zone_name == "example.com"

    def test_invalid_action_caught(self):
        ctx = lint_zone_file(
            {
                "redirect_rules": [
                    {
                        "ref": "test",
                        "expression": "true",
                        "action": "block",  # invalid for redirect_rules
                    }
                ]
            }
        )
        c001 = [r for r in ctx.results if r.rule_id == "CF200"]
        assert len(c001) == 1

    def test_response_field_in_request_phase(self):
        ctx = lint_zone_file(
            {"redirect_rules": [{"ref": "test", "expression": "http.response.code eq 200"}]}
        )
        b001 = [r for r in ctx.results if r.rule_id == "CF019"]
        assert len(b001) == 1

    def test_custom_ruleset_gets_phase_restrictions(self):
        """Custom ruleset rules should be checked for field/phase restrictions (CF019)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "bad-field",
                                "expression": "http.response.code eq 403",
                                "action": "block",
                            }
                        ],
                    }
                ]
            }
        )
        b001 = [r for r in ctx.results if r.rule_id == "CF019"]
        assert len(b001) == 1
        assert b001[0].ref == "bad-field"

    def test_custom_ruleset_gets_action_validation(self):
        """Custom ruleset rules should be checked for invalid actions (CF200)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "bad-action",
                                "expression": "true",
                                "action": "redirect",  # invalid for waf_custom_rules
                            }
                        ],
                    }
                ]
            }
        )
        c001 = [r for r in ctx.results if r.rule_id == "CF200"]
        assert len(c001) == 1

    def test_custom_ruleset_gets_expression_analysis(self):
        """Custom ruleset rules should be checked for expression issues (CF522)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "regex-anchor",
                                "expression": 'http.request.uri.path eq "^/api"',
                                "action": "block",
                            }
                        ],
                    }
                ]
            }
        )
        g003 = [r for r in ctx.results if r.rule_id == "CF522"]
        assert len(g003) == 1

    def test_page_shield_gets_phase_restrictions(self):
        """Page Shield policies with plan-gated fields should fire CF021 on free tier."""
        ctx = lint_zone_file(
            {
                "page_shield_policies": [
                    {
                        "description": "bot-check",
                        "action": "allow",
                        "expression": "cf.bot_management.score gt 30",
                        "enabled": True,
                        "value": "script-src 'self'",
                    }
                ]
            },
            plan_tier="free",
        )
        b003 = [r for r in ctx.results if r.rule_id == "CF021"]
        assert len(b003) == 1
        assert b003[0].ref == "bot-check"

    def test_regex_anchor_in_literal(self):
        ctx = lint_zone_file(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path eq "^/api"',
                        "action": "block",
                    }
                ]
            }
        )
        g003 = [r for r in ctx.results if r.rule_id == "CF522"]
        assert len(g003) == 1

    def test_lint_zone_file_with_suppressions(self):
        ctx = lint_zone_file(
            {
                "request_header_rules": [
                    {"ref": "catch-all", "expression": "(true)"},
                ]
            },
            suppressions={"catch-all": {"CF015"}},
        )
        m013 = [r for r in ctx.results if r.rule_id == "CF015"]
        assert len(m013) == 0
        assert ctx.suppressed_count >= 1
