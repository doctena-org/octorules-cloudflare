"""Tests for the Cloudflare audit IP extractor."""

from octorules_cloudflare.audit import _extract_ips


class TestCloudflareAuditExtractor:
    def test_extracts_ipv4_from_expression(self):
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "block-bad-ips",
                    "action": "block",
                    "expression": "ip.src in {10.0.0.0/24 192.168.1.0/24}",
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "block-bad-ips"
        assert results[0].action == "block"
        assert "10.0.0.0/24" in results[0].ip_ranges
        assert "192.168.1.0/24" in results[0].ip_ranges

    def test_extracts_ipv6(self):
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "block-v6",
                    "action": "block",
                    "expression": "ip.src in {2001:db8::/32}",
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 1
        assert "2001:db8::/32" in results[0].ip_ranges

    def test_no_ips_returns_empty(self):
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "no-ip",
                    "action": "block",
                    "expression": 'http.host eq "example.com"',
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
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
            "waf_custom_rules": [
                {"ref": "no-expr", "action": "block"},
            ],
        }
        assert _extract_ips(rules_data, "waf_custom_rules") == []

    def test_non_list_rules_skipped(self):
        rules_data = {"waf_custom_rules": "not a list"}
        assert _extract_ips(rules_data, "waf_custom_rules") == []

    def test_multiple_rules(self):
        rules_data = {
            "waf_custom_rules": [
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
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 2
        refs = {r.ref for r in results}
        assert refs == {"r1", "r2"}

    def test_extracts_list_refs(self):
        """$list_name references are captured in list_refs."""
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "block-listed",
                    "action": "block",
                    "expression": "(ip.src in $blocked_ips)",
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "block-listed"
        assert results[0].list_refs == ["blocked_ips"]
        assert results[0].ip_ranges == []  # No inline IPs

    def test_mixed_inline_and_list_ref(self):
        """Rule with both inline IPs and $list_name."""
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "mixed",
                    "action": "block",
                    "expression": ("(ip.src in {10.0.0.0/24}) or (ip.src in $office_ips)"),
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 1
        assert "10.0.0.0/24" in results[0].ip_ranges
        assert results[0].list_refs == ["office_ips"]

    def test_managed_list_ref(self):
        """Cloudflare managed list $cf.xxx references are captured."""
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "managed",
                    "action": "block",
                    "expression": "(ip.src in $cf.open_proxies)",
                },
            ],
        }
        results = _extract_ips(rules_data, "waf_custom_rules")
        assert len(results) == 1
        assert "cf.open_proxies" in results[0].list_refs
