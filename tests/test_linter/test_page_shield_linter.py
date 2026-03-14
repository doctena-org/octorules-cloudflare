"""Tests for Page Shield policy linter — Category S rules + expression analysis."""

from __future__ import annotations

from octorules.linter.engine import LintContext, lint_zone_file

from octorules_cloudflare.linter.page_shield_linter import lint_page_shield_policies


def _valid_policy(**overrides):
    """Return a valid page_shield_policies entry with optional overrides."""
    base = {
        "description": "Test policy",
        "action": "allow",
        "expression": '(http.host eq "example.com")',
        "enabled": True,
        "value": "script-src 'self'",
    }
    base.update(overrides)
    return base


def _lint(policies, **ctx_kwargs):
    """Lint a page_shield_policies list and return the context."""
    ctx = LintContext(**ctx_kwargs)
    rules_data = {"page_shield_policies": policies}
    lint_page_shield_policies(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


# ── CF460: Missing required fields ───────────────────────────────────────────


class TestS001MissingFields:
    def test_missing_description(self):
        policy = _valid_policy()
        del policy["description"]
        ctx = _lint([policy])
        assert "CF460" in _ids(ctx)
        assert any("description" in r.message for r in ctx.results if r.rule_id == "CF460")

    def test_missing_action(self):
        policy = _valid_policy()
        del policy["action"]
        ctx = _lint([policy])
        assert "CF460" in _ids(ctx)
        assert any("action" in r.message for r in ctx.results if r.rule_id == "CF460")

    def test_missing_expression(self):
        policy = _valid_policy()
        del policy["expression"]
        ctx = _lint([policy])
        assert "CF460" in _ids(ctx)
        assert any("expression" in r.message for r in ctx.results if r.rule_id == "CF460")

    def test_missing_enabled(self):
        policy = _valid_policy()
        del policy["enabled"]
        ctx = _lint([policy])
        assert "CF460" in _ids(ctx)
        assert any("enabled" in r.message for r in ctx.results if r.rule_id == "CF460")

    def test_missing_value(self):
        policy = _valid_policy()
        del policy["value"]
        ctx = _lint([policy])
        assert "CF460" in _ids(ctx)
        assert any("value" in r.message for r in ctx.results if r.rule_id == "CF460")


# ── CF461: Invalid action ────────────────────────────────────────────────────


class TestS002InvalidAction:
    def test_invalid_action_block(self):
        ctx = _lint([_valid_policy(action="block")])
        assert "CF461" in _ids(ctx)
        s002 = [r for r in ctx.results if r.rule_id == "CF461"]
        assert "block" in s002[0].message

    def test_valid_action_allow(self):
        ctx = _lint([_valid_policy(action="allow")])
        assert "CF461" not in _ids(ctx)

    def test_valid_action_log(self):
        ctx = _lint([_valid_policy(action="log")])
        assert "CF461" not in _ids(ctx)


# ── CF462: Invalid field types ───────────────────────────────────────────────


class TestS003InvalidTypes:
    def test_description_not_string(self):
        ctx = _lint([_valid_policy(description=123)])
        assert "CF462" in _ids(ctx)
        s003 = [r for r in ctx.results if r.rule_id == "CF462"]
        assert any("description" in r.message for r in s003)

    def test_enabled_not_bool(self):
        ctx = _lint([_valid_policy(enabled="yes")])
        assert "CF462" in _ids(ctx)
        s003 = [r for r in ctx.results if r.rule_id == "CF462"]
        assert any("enabled" in r.message for r in s003)

    def test_value_not_string(self):
        ctx = _lint([_valid_policy(value=123)])
        assert "CF462" in _ids(ctx)
        s003 = [r for r in ctx.results if r.rule_id == "CF462"]
        assert any("value" in r.message for r in s003)

    def test_entry_not_dict(self):
        ctx = _lint(["not a dict"])
        assert "CF462" in _ids(ctx)
        s003 = [r for r in ctx.results if r.rule_id == "CF462"]
        assert any("mapping" in r.message for r in s003)


# ── CF463: Duplicate description ─────────────────────────────────────────────


class TestS004DuplicateDescription:
    def test_duplicate_description(self):
        ctx = _lint(
            [
                _valid_policy(description="Same name"),
                _valid_policy(description="Same name"),
            ]
        )
        assert "CF463" in _ids(ctx)
        s004 = [r for r in ctx.results if r.rule_id == "CF463"]
        assert len(s004) == 1
        assert "Same name" in s004[0].message

    def test_unique_descriptions_ok(self):
        ctx = _lint(
            [
                _valid_policy(description="Policy A"),
                _valid_policy(description="Policy B"),
            ]
        )
        assert "CF463" not in _ids(ctx)


# ── Valid policy ────────────────────────────────────────────────────────────


class TestValidPolicy:
    def test_valid_policy_no_findings(self):
        ctx = _lint([_valid_policy()])
        # Only expression-level findings (if any) should appear, no S-category
        s_findings = [r for r in ctx.results if r.rule_id.startswith("S")]
        assert len(s_findings) == 0


# ── CF015/CF016: Always-true/always-false ─────────────────────────────────────


class TestCatchAllExpressions:
    def test_cf015_always_true(self):
        ctx = _lint([_valid_policy(expression="true")])
        assert "CF015" in _ids(ctx)
        m013 = [r for r in ctx.results if r.rule_id == "CF015"]
        assert m013[0].phase == "page_shield_policies"

    def test_cf015_always_true_parenthesized(self):
        ctx = _lint([_valid_policy(expression="(true)")])
        assert "CF015" in _ids(ctx)

    def test_cf016_always_false(self):
        ctx = _lint([_valid_policy(expression="false")])
        assert "CF016" in _ids(ctx)
        m014 = [r for r in ctx.results if r.rule_id == "CF016"]
        assert m014[0].phase == "page_shield_policies"


# ── Expression analysis delegation ──────────────────────────────────────────


class TestExpressionAnalysis:
    def test_cf522_regex_anchor_fires(self):
        ctx = _lint([_valid_policy(expression='http.request.uri.path eq "^/api"')])
        assert "CF522" in _ids(ctx)

    def test_ref_override_shows_description(self):
        ctx = _lint(
            [
                _valid_policy(
                    description="My CSP Policy",
                    expression='http.request.method eq "get"',
                )
            ]
        )
        g001 = [r for r in ctx.results if r.rule_id == "CF520"]
        assert len(g001) == 1
        assert g001[0].ref == "My CSP Policy"


# ── Phase filter ────────────────────────────────────────────────────────────


class TestPhaseFilter:
    def test_phase_filter_excludes_page_shield(self):
        ctx = _lint(
            [_valid_policy(action="block")],
            phase_filter=["waf_custom_rules"],
        )
        assert len(ctx.results) == 0

    def test_phase_filter_includes_page_shield(self):
        ctx = _lint(
            [_valid_policy(action="block")],
            phase_filter=["page_shield_policies"],
        )
        assert "CF461" in _ids(ctx)


# ── Integration with lint_zone_file ─────────────────────────────────────────


class TestIntegration:
    def test_lint_zone_file_catches_page_shield_errors(self):
        rules_data = {
            "page_shield_policies": [
                _valid_policy(action="block"),
            ],
        }
        ctx = lint_zone_file(rules_data)
        assert "CF461" in [r.rule_id for r in ctx.results]

    def test_lint_zone_file_page_shield_alongside_phases(self):
        rules_data = {
            "page_shield_policies": [
                _valid_policy(action="block"),
            ],
            "waf_custom_rules": [
                {
                    "ref": "test-rule",
                    "expression": "true",
                    "action": "block",
                },
            ],
        }
        ctx = lint_zone_file(rules_data)
        rule_ids = [r.rule_id for r in ctx.results]
        # Should have CF461 from page_shield and CF015 from waf_custom_rules
        assert "CF461" in rule_ids
        assert "CF015" in rule_ids


# ── Edge cases ──────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_no_page_shield_key(self):
        """No page_shield_policies key should produce no findings."""
        ctx = LintContext()
        lint_page_shield_policies({"waf_custom_rules": []}, ctx)
        assert len(ctx.results) == 0

    def test_page_shield_not_a_list(self):
        """Non-list value should produce no findings (early return)."""
        ctx = LintContext()
        lint_page_shield_policies({"page_shield_policies": "not a list"}, ctx)
        assert len(ctx.results) == 0

    def test_empty_policies_list(self):
        """Empty list should produce no findings."""
        ctx = _lint([])
        assert len(ctx.results) == 0
