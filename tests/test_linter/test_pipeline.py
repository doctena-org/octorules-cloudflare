"""End-to-end linter pipeline tests.

Runs the full 4-pass Cloudflare linting pipeline (YAML structure ->
per-rule checks -> plan-tier checks -> cross-rule analysis) via
:func:`cloudflare_lint` on realistic zone fixtures.
"""

from octorules.linter.engine import LintContext, Severity

from octorules_cloudflare.linter._plugin import cloudflare_lint


def _run_lint(
    rules_data: dict,
    *,
    plan_tier: str = "enterprise",
    zone_name: str = "example.com",
) -> LintContext:
    """Helper: build a LintContext and run cloudflare_lint."""
    ctx = LintContext(plan_tier=plan_tier, zone_name=zone_name)
    cloudflare_lint(rules_data, ctx)
    return ctx


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A clean zone with rules spanning multiple phases, custom rulesets,
# lists, and page shield policies.  Should produce zero findings.
_CLEAN_ZONE: dict = {
    "redirect_rules": [
        {
            "ref": "www-redirect",
            "expression": 'http.host eq "www.example.com"',
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"value": "https://example.com"},
                    "status_code": 301,
                }
            },
        },
    ],
    "waf_custom_rules": [
        {
            "ref": "block-bad-ua",
            "expression": 'http.user_agent contains "BadBot"',
            "action": "block",
        },
        {
            "ref": "challenge-suspicious",
            "expression": 'ip.src.country eq "XX"',
            "action": "managed_challenge",
        },
    ],
    "request_header_rules": [
        {
            "ref": "add-true-client-ip",
            "expression": 'http.host eq "api.example.com"',
            "action": "rewrite",
            "action_parameters": {
                "headers": {
                    "X-True-Client-IP": {
                        "operation": "set",
                        "value": "192.0.2.1",
                    }
                }
            },
        },
    ],
    "cache_rules": [
        {
            "ref": "cache-static",
            "expression": 'starts_with(http.request.uri.path, "/static/")',
            "action": "set_cache_settings",
            "action_parameters": {
                "cache": True,
                "edge_ttl": {"mode": "override_origin", "default": 86400},
                "browser_ttl": {"mode": "override_origin", "default": 3600},
            },
        },
    ],
    "custom_rulesets": [
        {
            "id": "a" * 32,
            "name": "shared-waf-rules",
            "phase": "http_request_firewall_custom",
            "rules": [
                {
                    "ref": "shared-block-scanners",
                    "expression": 'http.user_agent contains "Nmap"',
                    "action": "block",
                },
            ],
        },
    ],
    "lists": [
        {
            "name": "ip_blocklist",
            "kind": "ip",
            "description": "Blocked IPs",
            "items": [
                {"ip": "192.0.2.1/32", "comment": "test"},
            ],
        },
    ],
    "page_shield_policies": [
        {
            "description": "allow-self",
            "action": "allow",
            "expression": 'http.host eq "example.com"',
            "enabled": True,
            "value": "script-src 'self'",
        },
    ],
}
# A zone with known issues that should trigger specific findings across
# all four linter stages.
_BAD_ZONE: dict = {
    # Stage 1 (YAML structure): CF003 (missing ref), CF009 (unknown key)
    "bogus_phase": [],
    "redirect_rules": [
        # CF003: missing ref
        {"expression": 'http.host eq "old.example.com"'},
        # CF005: duplicate ref within phase
        {
            "ref": "dup-ref",
            "expression": 'http.host eq "a.example.com"',
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"value": "https://example.com/a"},
                    "status_code": 301,
                }
            },
        },
        {
            "ref": "dup-ref",
            "expression": 'http.host eq "b.example.com"',
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"value": "https://example.com/b"},
                    "status_code": 301,
                }
            },
        },
    ],
    "waf_custom_rules": [
        # Stage 2 (per-rule): CF200 (invalid action for phase)
        {
            "ref": "bad-action",
            "expression": "true",
            "action": "redirect",  # invalid for waf_custom_rules
        },
        # Stage 2 (per-rule): CF522 (regex anchor in literal)
        {
            "ref": "regex-in-literal",
            "expression": 'http.request.uri.path eq "^/api"',
            "action": "block",
        },
        # Stage 2 (per-rule): CF019 (response field in request phase)
        {
            "ref": "response-in-request",
            "expression": "http.response.code eq 403",
            "action": "block",
        },
        # Stage 4 (cross-rule): CF101 (unreachable after terminating)
        {
            "ref": "catch-all-block",
            "expression": "true",
            "action": "block",
        },
        {
            "ref": "unreachable-rule",
            "expression": 'http.request.uri.path eq "/test"',
            "action": "log",
        },
    ],
}


class TestLinterPipeline:
    """End-to-end tests for the full cloudflare_lint 4-pass pipeline."""

    def test_clean_zone_zero_findings(self):
        """A well-formed zone with valid rules produces zero lint findings."""
        ctx = _run_lint(_CLEAN_ZONE)
        if ctx.results:
            details = "\n".join(f"  {r}" for r in ctx.results)
            raise AssertionError(f"Expected zero findings, got {len(ctx.results)}:\n{details}")

    def test_bad_zone_expected_findings(self):
        """A zone with known issues produces the exact expected set of findings."""
        ctx = _run_lint(_BAD_ZONE)
        rule_ids = sorted(r.rule_id for r in ctx.results)

        # Stage 1: YAML structure
        assert "CF003" in rule_ids, "Missing ref not caught (stage 1)"
        assert "CF005" in rule_ids, "Duplicate ref not caught (stage 1)"
        assert "CF009" in rule_ids, "Unknown phase key not caught (stage 1)"

        # Stage 2: Per-rule checks
        assert "CF200" in rule_ids, "Invalid action not caught (stage 2)"
        assert "CF522" in rule_ids, "Regex anchor in literal not caught (stage 2)"
        assert "CF019" in rule_ids, "Response field in request phase not caught (stage 2)"

        # Stage 4: Cross-rule analysis
        assert "CF101" in rule_ids, "Unreachable rule not caught (stage 4)"

        # Verify specific refs are associated with the right findings
        findings_by_rule_id: dict[str, list] = {}
        for r in ctx.results:
            findings_by_rule_id.setdefault(r.rule_id, []).append(r)

        # CF003 should point to the rule missing ref
        cf003 = findings_by_rule_id["CF003"]
        assert len(cf003) == 1

        # CF005 should flag the duplicate ref
        cf005 = findings_by_rule_id["CF005"]
        assert len(cf005) == 1
        assert cf005[0].ref == "dup-ref"

        # CF200 should reference bad-action
        cf200 = findings_by_rule_id["CF200"]
        assert any(r.ref == "bad-action" for r in cf200)

        # CF522 should reference regex-in-literal
        cf522 = findings_by_rule_id["CF522"]
        assert any(r.ref == "regex-in-literal" for r in cf522)

        # CF101 should reference unreachable-rule
        cf101 = findings_by_rule_id["CF101"]
        assert any(r.ref == "unreachable-rule" for r in cf101)

    def test_plan_tier_rule_count_exceeded(self):
        """Stage 3 (plan-tier): rule count exceeding free tier limit triggers CF501."""
        rules = [
            {
                "ref": f"rule-{i}",
                "expression": f'http.host eq "r{i}.example.com"',
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": f"https://example.com/{i}"},
                        "status_code": 301,
                    }
                },
            }
            for i in range(11)  # free limit is 10
        ]
        ctx = _run_lint({"redirect_rules": rules}, plan_tier="free")
        cf501 = [r for r in ctx.results if r.rule_id == "CF501"]
        assert len(cf501) == 1
        assert "exceeding free plan limit" in cf501[0].message

    def test_plan_tier_regex_on_free(self):
        """Stage 3 (plan-tier): regex on free plan triggers CF500."""
        ctx = _run_lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "regex-rule",
                        "expression": 'http.request.uri.path matches "^/api/v[0-9]+"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="free",
        )
        cf500 = [r for r in ctx.results if r.rule_id == "CF500"]
        assert len(cf500) == 1
        assert "regex" in cf500[0].message.lower()

    def test_cross_rule_duplicate_expressions(self):
        """Stage 4 (cross-rule): duplicate expressions within a phase trigger CF100."""
        ctx = _run_lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "first",
                        "expression": 'http.request.uri.path eq "/api"',
                        "action": "block",
                    },
                    {
                        "ref": "second",
                        "expression": 'http.request.uri.path eq "/api"',
                        "action": "block",
                    },
                ]
            }
        )
        cf100 = [r for r in ctx.results if r.rule_id == "CF100"]
        assert len(cf100) == 1
        assert cf100[0].ref == "second"

    def test_list_reference_not_found(self):
        """Stage 4 (cross-rule): list reference to undefined list triggers CF102."""
        ctx = _run_lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "list-check",
                        "expression": "ip.src in $nonexistent_list",
                        "action": "block",
                    }
                ]
            }
        )
        cf102 = [r for r in ctx.results if r.rule_id == "CF102"]
        assert len(cf102) == 1
        assert "$nonexistent_list" in cf102[0].message

    def test_severity_levels_present(self):
        """Bad zone findings include both ERROR and WARNING severities."""
        ctx = _run_lint(_BAD_ZONE)
        severities = {r.severity for r in ctx.results}
        assert Severity.ERROR in severities, "Expected at least one ERROR"
        assert Severity.WARNING in severities, "Expected at least one WARNING"

    def test_phases_are_annotated(self):
        """Every finding from the bad zone should have a phase annotation."""
        ctx = _run_lint(_BAD_ZONE)
        for r in ctx.results:
            # Every finding should have a phase (either the rule's phase or
            # the top-level key that triggered the finding)
            assert r.phase, f"Finding {r.rule_id} has no phase annotation: {r}"
