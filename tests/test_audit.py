"""Tests for the Cloudflare audit IP extractor."""

from octorules_cloudflare.audit import _extract_ips


class TestCloudflareAuditExtractor:
    def test_extracts_ipv4_from_expression(self):
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "block-bad-ips",
                    "action": "block",
                    "expression": "ip.src in {10.0.0.0/24 192.168.1.0/24}",
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "block-bad-ips"
        assert results[0].action == "block"
        assert "10.0.0.0/24" in results[0].ip_ranges
        assert "192.168.1.0/24" in results[0].ip_ranges

    def test_extracts_ipv6(self):
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "block-v6",
                    "action": "block",
                    "expression": "ip.src in {2001:db8::/32}",
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 1
        assert "2001:db8::/32" in results[0].ip_ranges

    def test_no_ips_returns_empty(self):
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "no-ip",
                    "action": "block",
                    "expression": 'http.host eq "example.com"',
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert results == []

    def test_ignores_non_cf_phases(self):
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "r1",
                    "action": "block",
                    "expression": "ip.src in {10.0.0.0/8}",
                },
            ],
        }
        assert _extract_ips(rules_data, "aws_waf_custom_rules") == []

    def test_missing_expression_skipped(self):
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {"ref": "no-expr", "action": "block"},
            ],
        }
        assert _extract_ips(rules_data, "cloudflare.waf_custom_rules") == []

    def test_non_list_rules_skipped(self):
        rules_data = {"cloudflare.waf_custom_rules": "not a list"}
        assert _extract_ips(rules_data, "cloudflare.waf_custom_rules") == []

    def test_multiple_rules(self):
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "r1",
                    "action": "block",
                    "expression": "ip.src in {10.0.0.0/24}",
                },
                {
                    "ref": "r2",
                    "action": "managed_challenge",
                    "expression": "ip.src in {172.16.0.0/12}",
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 2
        refs = {r.ref for r in results}
        assert refs == {"r1", "r2"}

    def test_extracts_list_refs(self):
        """$list_name references are captured in list_refs."""
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "block-listed",
                    "action": "block",
                    "expression": "(ip.src in $blocked_ips)",
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "block-listed"
        assert results[0].list_refs == ["blocked_ips"]
        assert results[0].ip_ranges == []  # No inline IPs

    def test_mixed_inline_and_list_ref(self):
        """Rule with both inline IPs and $list_name."""
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "mixed",
                    "action": "block",
                    "expression": ("(ip.src in {10.0.0.0/24}) or (ip.src in $office_ips)"),
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 1
        assert "10.0.0.0/24" in results[0].ip_ranges
        assert results[0].list_refs == ["office_ips"]

    def test_managed_list_ref(self):
        """Cloudflare managed list $cf.xxx references are captured."""
        rules_data = {
            "cloudflare.waf_custom_rules": [
                {
                    "ref": "managed",
                    "action": "block",
                    "expression": "(ip.src in $cf.open_proxies)",
                },
            ],
        }
        results = _extract_ips(rules_data, "cloudflare.waf_custom_rules")
        assert len(results) == 1
        assert "cf.open_proxies" in results[0].list_refs


class TestNegatedMatchesAreNotTargets:
    """An IP reached only through a negation is one the rule deliberately does
    NOT act on. Reporting it as a match target makes the cross-rule (ip-overlap)
    and cross-zone (zone-drift) checks compare exemptions as though they were
    blocks — nine false overlaps and three false drifts on a single carve-out."""

    @staticmethod
    def _extract(expression, action="execute"):
        return _extract_ips(
            {
                "cloudflare.waf_custom_rules": [
                    {"ref": "r", "action": action, "expression": expression}
                ]
            },
            "cloudflare.waf_custom_rules",
        )

    def test_negated_list_ref_is_dropped(self):
        # The shape that produced the false findings: a carve-out gating a
        # ruleset execute on "everyone except the pentest sources".
        results = self._extract(
            '(not (ip.src in $pentest_ips and cf.zone.name in {"a.example"}))'
            ' and (cf.zone.plan eq "ENT")'
        )
        assert results == [] or results[0].list_refs == []

    def test_negated_ip_literal_is_dropped(self):
        results = self._extract("not (ip.src in {203.0.113.4})")
        assert results == [] or results[0].ip_ranges == []

    def test_negated_clause_after_and(self):
        # `not` binds to the comparison that follows it, not the whole expression.
        results = self._extract("ip.src in {198.51.100.0/24} and not ip.src in $trusted")
        assert "198.51.100.0/24" in results[0].ip_ranges
        assert results[0].list_refs == []

    def test_positive_match_is_kept(self):
        results = self._extract("ip.src in $blocked", action="block")
        assert results[0].list_refs == ["blocked"]

    def test_double_negation_is_positive(self):
        results = self._extract("not (not (ip.src in $blocked))", action="block")
        assert results[0].list_refs == ["blocked"]

    def test_or_ends_the_negations_reach(self):
        results = self._extract("not ip.src in $trusted or ip.src in $blocked")
        assert results[0].list_refs == ["blocked"]

    def test_value_positive_somewhere_is_kept(self):
        # Same list used as an exemption in one clause and a target in another:
        # keep it. Conservative — never blind the audit to a real target.
        results = self._extract("(not ip.src in $dual) and (ip.src in $dual)")
        # One entry per occurrence is pre-existing extractor behaviour.
        assert set(results[0].list_refs) == {"dual"}

    def test_not_inside_a_string_literal_is_not_an_operator(self):
        results = self._extract('http.user_agent contains "not a robot" and ip.src in $blocked')
        assert results[0].list_refs == ["blocked"]

    def test_unparenthesised_negation_of_a_set(self):
        results = self._extract("not ip.src in {203.0.113.0/24}")
        assert results == [] or results[0].ip_ranges == []


class TestDisabledRulesAreNotAudited:
    """A disabled rule enforces nothing. Auditing its addresses reports
    overlaps and drift against traffic handling that does not happen — the
    live/disabled pair being the common shape (an old rule left in place)."""

    @staticmethod
    def _extract(rule):
        return _extract_ips({"cloudflare.waf_custom_rules": [rule]}, "cloudflare.waf_custom_rules")

    def test_disabled_rule_is_skipped(self):
        assert (
            self._extract(
                {
                    "ref": "old",
                    "action": "block",
                    "enabled": False,
                    "expression": "ip.src in {203.0.113.0/24}",
                }
            )
            == []
        )

    def test_enabled_rule_is_kept(self):
        results = self._extract(
            {
                "ref": "live",
                "action": "block",
                "enabled": True,
                "expression": "ip.src in {203.0.113.0/24}",
            }
        )
        assert results[0].ip_ranges == ["203.0.113.0/24"]

    def test_absent_enabled_defaults_to_enabled(self):
        results = self._extract(
            {"ref": "implicit", "action": "block", "expression": "ip.src in {203.0.113.0/24}"}
        )
        assert results[0].ip_ranges == ["203.0.113.0/24"]

    def test_only_false_disables_not_other_falsy(self):
        # `enabled: null` in YAML is a malformed value, not a disable.
        results = self._extract(
            {
                "ref": "null-enabled",
                "action": "block",
                "enabled": None,
                "expression": "ip.src in {203.0.113.0/24}",
            }
        )
        assert results[0].ip_ranges == ["203.0.113.0/24"]


class TestNegatedListRefsAreStillReferences:
    """A list used only to exempt traffic is not a match target, but it IS
    referenced — reporting it as an unused standalone list would be wrong."""

    def test_negated_ref_recorded_separately(self):
        results = _extract_ips(
            {
                "cloudflare.waf_custom_rules": [
                    {
                        "ref": "r",
                        "action": "execute",
                        "expression": '(not ip.src in $trusted) and (cf.zone.plan eq "ENT")',
                    }
                ]
            },
            "cloudflare.waf_custom_rules",
        )
        assert results[0].list_refs == []
        assert results[0].negated_list_refs == ["trusted"]

    def test_positive_ref_is_not_recorded_as_negated(self):
        results = _extract_ips(
            {
                "cloudflare.waf_custom_rules": [
                    {"ref": "r", "action": "block", "expression": "ip.src in $bad"}
                ]
            },
            "cloudflare.waf_custom_rules",
        )
        assert results[0].list_refs == ["bad"]
        assert results[0].negated_list_refs == []
