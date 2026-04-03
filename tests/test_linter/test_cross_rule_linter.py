"""Tests for cross-rule linter (Category P)."""

from octorules.linter.engine import LintContext, Severity

from octorules_cloudflare.linter.cross_rule_linter import lint_cross_rules


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_cross_rules(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


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
        assert "CF100" in _ids(ctx)
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
        assert "CF100" in _ids(ctx)

    def test_cf100_different_expressions_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"'},
                ]
            }
        )
        assert "CF100" not in _ids(ctx)

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
        assert "CF100" not in _ids(ctx)

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
        assert "CF100" in _ids(ctx)

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
        assert "CF100" not in _ids(ctx)


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
        assert "CF101" in _ids(ctx)

    def test_cf101_not_triggered_with_non_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"', "action": "block"},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"', "action": "log"},
                ]
            }
        )
        assert "CF101" not in _ids(ctx)

    def test_cf101_not_triggered_with_non_terminating(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "true", "action": "log"},
                    {"ref": "rule2", "expression": 'http.host eq "a.com"', "action": "block"},
                ]
            }
        )
        assert "CF101" not in _ids(ctx)

    def test_cf101_disabled_rule_ignored(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "disabled", "expression": "true", "action": "block", "enabled": False},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert "CF101" not in _ids(ctx)

    def test_cf101_parenthesized_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blocker", "expression": "(true)", "action": "block"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert "CF101" in _ids(ctx)


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
        assert "CF102" in _ids(ctx)
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
        assert "CF102" not in _ids(ctx)

    def test_cf102_no_list_refs_no_findings(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                ],
            }
        )
        assert "CF102" not in _ids(ctx)

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
        assert "CF103" in _ids(ctx)

    def test_cf103_valid_managed_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
            }
        )
        assert "CF103" not in _ids(ctx)

    def test_cf103_user_list_not_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_custom_list"},
                ],
                "lists": [{"name": "my_custom_list"}],
            }
        )
        assert "CF103" not in _ids(ctx)

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
        assert "CF102" not in _ids(ctx)


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
        assert "CF104" in _ids(ctx)

    def test_cf104_asn_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert "CF104" in _ids(ctx)

    def test_cf104_correct_ip_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert "CF104" not in _ids(ctx)

    def test_cf104_correct_asn_field_with_asn_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.geoip.asnum in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert "CF104" not in _ids(ctx)

    def test_cf104_not_in_also_detected(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src not in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert "CF104" in _ids(ctx)

    def test_cf104_no_lists_section(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_list"},
                ],
            }
        )
        assert "CF104" not in _ids(ctx)

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
        assert "CF104" not in _ids(ctx)

    def test_cf104_managed_list_wrong_field(self):
        """CF104 detects type mismatch for $cf.* managed lists (all are ip kind)."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $cf.anonymizer"},
                ],
            }
        )
        assert "CF104" in _ids(ctx)
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
        assert "CF104" not in _ids(ctx)

    def test_cf104_managed_list_not_in(self):
        """CF104 detects managed list type mismatch with 'not in' operator."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.geoip.asnum not in $cf.vpn"},
                ],
            }
        )
        assert "CF104" in _ids(ctx)

    def test_cf104_managed_list_no_lists_section(self):
        """CF104 fires for managed lists even without a 'lists' section."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $cf.malware"},
                ],
            }
        )
        assert "CF104" in _ids(ctx)


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
        assert "CF100" not in _ids(ctx)
