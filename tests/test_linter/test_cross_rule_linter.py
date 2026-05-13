"""Tests for cross-rule linter (Category P)."""

from octorules.linter.engine import LintContext, Severity
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_cloudflare.linter.cross_rule_linter import lint_cross_rules


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_cross_rules(rules_data, ctx)
    return ctx


class TestDuplicateExpressions:
    def test_cf100_duplicate_expression(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ]
            }
        )
        assert_lint(ctx, "CF100")
        p001 = [r for r in ctx.results if r.rule_id == "CF100"]
        assert len(p001) == 1
        assert p001[0].severity == Severity.WARNING

    def test_cf100_whitespace_normalized(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host   eq   "example.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ]
            }
        )
        assert_lint(ctx, "CF100")

    def test_cf100_different_expressions_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"'},
                ]
            }
        )
        assert_no_lint(ctx, "CF100")

    def test_cf100_same_expr_different_action_params_id_ok(self):
        # Managed ruleset deployments with same expression but different IDs
        # are NOT duplicates
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "rule1",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "aaa"},
                    },
                    {
                        "ref": "rule2",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "bbb"},
                    },
                ]
            }
        )
        assert_no_lint(ctx, "CF100")

    def test_cf100_same_expr_same_action_params_id_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "rule1",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "same-id"},
                    },
                    {
                        "ref": "rule2",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "same-id"},
                    },
                ]
            }
        )
        assert_lint(ctx, "CF100")

    def test_cf100_across_phases_not_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                ],
                "rate_limiting_rules": [
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ],
            }
        )
        assert_no_lint(ctx, "CF100")


class TestUnreachableRules:
    def test_cf101_unreachable_after_block_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blocker", "expression": "true", "action": "block"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert_lint(ctx, "CF101")

    def test_cf101_not_triggered_with_non_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"', "action": "block"},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"', "action": "log"},
                ]
            }
        )
        assert_no_lint(ctx, "CF101")

    def test_cf101_not_triggered_with_non_terminating(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "true", "action": "log"},
                    {"ref": "rule2", "expression": 'http.host eq "a.com"', "action": "block"},
                ]
            }
        )
        assert_no_lint(ctx, "CF101")

    def test_cf101_disabled_rule_ignored(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "disabled", "expression": "true", "action": "block", "enabled": False},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert_no_lint(ctx, "CF101")

    def test_cf101_parenthesized_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blocker", "expression": "(true)", "action": "block"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert_lint(ctx, "CF101")


class TestListReferences:
    def test_cf102_unresolved_list_reference(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $unknown_list"},
                ],
                "lists": [],
            }
        )
        assert_lint(ctx, "CF102")
        p003 = [r for r in ctx.results if r.rule_id == "CF102"]
        assert "unknown_list" in p003[0].message

    def test_cf102_resolved_list_reference_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_ips"},
                ],
                "lists": [{"name": "my_ips"}],
            }
        )
        assert_no_lint(ctx, "CF102")

    def test_cf102_no_list_refs_no_findings(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                ],
            }
        )
        assert_no_lint(ctx, "CF102")

    def test_cf102_multiple_refs_partial_resolution(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $known"},
                    {"ref": "rule2", "expression": "ip.src in $unknown"},
                ],
                "lists": [{"name": "known"}],
            }
        )
        p003 = [r for r in ctx.results if r.rule_id == "CF102"]
        assert len(p003) == 1
        assert "unknown" in p003[0].message


class TestManagedLists:
    def test_cf103_invalid_managed_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.invalid_list"},
                ],
            }
        )
        assert_lint(ctx, "CF103")

    def test_cf103_valid_managed_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
            }
        )
        assert_no_lint(ctx, "CF103")

    def test_cf103_user_list_not_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_custom_list"},
                ],
                "lists": [{"name": "my_custom_list"}],
            }
        )
        assert_no_lint(ctx, "CF103")

    def test_cf102_doesnt_flag_managed_list(self):
        # Managed list names (with dots) should not trigger CF102
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
                "lists": [],
            }
        )
        assert_no_lint(ctx, "CF102")


class TestListTypeMismatch:
    def test_cf104_ip_field_with_asn_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert_lint(ctx, "CF104")

    def test_cf104_asn_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert_lint(ctx, "CF104")

    def test_cf104_correct_ip_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert_no_lint(ctx, "CF104")

    def test_cf104_correct_asn_field_with_asn_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.geoip.asnum in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert_no_lint(ctx, "CF104")

    def test_cf104_not_in_also_detected(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src not in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert_lint(ctx, "CF104")

    def test_cf104_no_lists_section(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_list"},
                ],
            }
        )
        assert_no_lint(ctx, "CF104")

    def test_cf104_unknown_list_no_error(self):
        """Unknown list reference is handled by CF102, not CF104."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $unknown"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert_no_lint(ctx, "CF104")

    def test_cf104_managed_list_wrong_field(self):
        """CF104 detects type mismatch for $cf.* managed lists (all are ip kind)."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $cf.anonymizer"},
                ],
            }
        )
        assert_lint(ctx, "CF104")
        p005 = [r for r in ctx.results if r.rule_id == "CF104"]
        assert len(p005) == 1
        assert "cf.anonymizer" in p005[0].message

    def test_cf104_managed_list_correct_field(self):
        """CF104 does not fire when managed list field matches (ip.src with ip kind)."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
            }
        )
        assert_no_lint(ctx, "CF104")

    def test_cf104_managed_list_not_in(self):
        """CF104 detects managed list type mismatch with 'not in' operator."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.geoip.asnum not in $cf.vpn"},
                ],
            }
        )
        assert_lint(ctx, "CF104")

    def test_cf104_managed_list_no_lists_section(self):
        """CF104 fires for managed lists even without a 'lists' section."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $cf.malware"},
                ],
            }
        )
        assert_lint(ctx, "CF104")


class TestCustomRulesetListReferences:
    """CF102/CF103/CF104 should also check rules inside custom_rulesets."""

    def test_cf102_inside_custom_rulesets(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "name": "my_ruleset",
                        "rules": [
                            {"ref": "rule1", "expression": "ip.src in $unknown_list"},
                        ],
                    }
                ],
                "lists": [],
            }
        )
        assert_lint(ctx, "CF102")
        findings = [r for r in ctx.results if r.rule_id == "CF102"]
        assert len(findings) == 1
        assert findings[0].phase == "custom_rulesets/my_ruleset"

    def test_cf103_inside_custom_rulesets(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "name": "my_ruleset",
                        "rules": [
                            {"ref": "rule1", "expression": "ip.src in $cf.invalid_list"},
                        ],
                    }
                ],
            }
        )
        assert_lint(ctx, "CF103")

    def test_cf104_inside_custom_rulesets(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "name": "my_ruleset",
                        "rules": [
                            {"ref": "rule1", "expression": "ip.src in $my_asns"},
                        ],
                    }
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert_lint(ctx, "CF104")


class TestRewriteNotTerminating:
    """Rewrite actions should NOT be terminating — subsequent rules still execute."""

    def test_cf101_not_triggered_for_rewrite(self):
        ctx = _lint(
            {
                "url_rewrite_rules": [
                    {"ref": "rewriter", "expression": "true", "action": "rewrite"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "rewrite"},
                ]
            }
        )
        assert_no_lint(ctx, "CF101")

    def test_cf101_stacked_rewrite_rules_all_true_no_warning(self):
        """Multiple rewrite rules with always-true expressions must NOT produce CF101.

        Rewrite is not a terminating action — Cloudflare continues evaluating
        subsequent rules even after a rewrite match.
        """
        ctx = _lint(
            {
                "url_rewrite_rules": [
                    {"ref": "rw1", "expression": "true", "action": "rewrite"},
                    {"ref": "rw2", "expression": "true", "action": "rewrite"},
                    {"ref": "rw3", "expression": "true", "action": "rewrite"},
                ]
            }
        )
        assert_no_lint(ctx, "CF101")

    def test_cf101_stacked_block_rules_all_true_produces_warnings(self):
        """Contrast: stacked block rules with always-true expressions DO produce CF101.

        Block IS a terminating action, so rules after the first are unreachable.
        This validates that the rewrite test above is meaningful.
        """
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blk1", "expression": "true", "action": "block"},
                    {"ref": "blk2", "expression": "true", "action": "block"},
                    {"ref": "blk3", "expression": "true", "action": "block"},
                ]
            }
        )
        cf101s = [r for r in ctx.results if r.rule_id == "CF101"]
        # blk2 and blk3 are unreachable after blk1
        assert len(cf101s) == 2
        refs = {r.ref for r in cf101s}
        assert refs == {"blk2", "blk3"}


class TestPhaseFilter:
    def test_filter_skips_unmatched_phase(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "a.com"'},
                ]
            },
            phase_filter=["redirect_rules"],
        )
        assert_no_lint(ctx, "CF100")


class TestDuplicateManagedRulesetExecute:
    """CF105: two or more `execute` rules targeting the same managed ruleset
    in one phase entrypoint — Cloudflare API rejects with error 20014."""

    _RULESET_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    _RULESET_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    def test_cf105_two_executes_same_ruleset_fires(self):
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {
                        "ref": "rule-A",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                    {
                        "ref": "rule-B",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": '(http.host eq "example.com")',
                    },
                ]
            }
        )
        assert_lint(ctx, "CF105")
        findings = [r for r in ctx.results if r.rule_id == "CF105"]
        # One finding per offending rule so users can suppress per-ref.
        assert len(findings) == 2
        assert {f.ref for f in findings} == {"rule-A", "rule-B"}
        assert all(f.severity == Severity.ERROR for f in findings)
        assert all(self._RULESET_A in f.message for f in findings)

    def test_cf105_single_execute_no_fire(self):
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {
                        "ref": "rule-A",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                ]
            }
        )
        assert_no_lint(ctx, "CF105")

    def test_cf105_two_executes_different_ids_no_fire(self):
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {
                        "ref": "rule-A",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                    {
                        "ref": "rule-B",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_B},
                        "expression": "true",
                    },
                ]
            }
        )
        assert_no_lint(ctx, "CF105")

    def test_cf105_execute_without_action_parameters_safe(self):
        # Missing action_parameters is a separate problem (CF202); CF105
        # must not crash on it nor produce a spurious finding.
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {"ref": "rule-A", "action": "execute", "expression": "true"},
                    {
                        "ref": "rule-B",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                ]
            }
        )
        assert_no_lint(ctx, "CF105")

    def test_cf105_other_phases_isolated(self):
        # Two execute rules sharing a managed-ruleset id but in different
        # phases are independent — each phase entrypoint is its own scope.
        # (Even though `execute` in waf_custom_rules typically isn't valid,
        # the cross-rule check should still group per-phase.)
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {
                        "ref": "rule-A",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                ],
                "waf_custom_rules": [
                    {
                        "ref": "rule-B",
                        "action": "execute",
                        "action_parameters": {"id": self._RULESET_A},
                        "expression": "true",
                    },
                ],
            }
        )
        assert_no_lint(ctx, "CF105")

    def test_cf105_two_executes_same_ruleset_with_different_overrides(self):
        # The PR-introduced pattern: same managed ruleset deployed twice
        # with different overrides (e.g. globally with one category off,
        # then re-enabled scoped to one host). Cloudflare still rejects
        # this — the constraint is on the ruleset id, not the overrides.
        ctx = _lint(
            {
                "waf_managed_rules": [
                    {
                        "ref": "rule-A",
                        "action": "execute",
                        "action_parameters": {
                            "id": self._RULESET_A,
                            "overrides": {
                                "categories": [
                                    {"category": "wordpress", "enabled": False},
                                ],
                            },
                        },
                        "expression": "true",
                    },
                    {
                        "ref": "rule-B",
                        "action": "execute",
                        "action_parameters": {
                            "id": self._RULESET_A,
                            "overrides": {
                                "enabled": False,
                                "categories": [
                                    {"category": "wordpress", "enabled": True},
                                ],
                            },
                        },
                        "expression": '(http.host eq "example.com")',
                    },
                ]
            }
        )
        findings = [r for r in ctx.results if r.rule_id == "CF105"]
        assert len(findings) == 2
        assert {f.ref for f in findings} == {"rule-A", "rule-B"}
