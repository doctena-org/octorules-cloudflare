"""Tests for list validation (Category Q)."""

from __future__ import annotations

from octorules.linter.engine import LintContext

from octorules_cloudflare.linter.list_linter import lint_lists


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_lists(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestListStructure:
    def test_cf470_missing_name(self):
        ctx = _lint({"lists": [{"kind": "ip", "items": []}]})
        assert "CF470" in _ids(ctx)

    def test_cf470_duplicate_name(self):
        ctx = _lint(
            {
                "lists": [
                    {"name": "mylist", "kind": "ip", "items": []},
                    {"name": "mylist", "kind": "ip", "items": []},
                ]
            }
        )
        assert "CF470" in _ids(ctx)

    def test_cf471_missing_kind(self):
        ctx = _lint({"lists": [{"name": "mylist", "items": []}]})
        assert "CF471" in _ids(ctx)

    def test_cf471_invalid_kind(self):
        ctx = _lint({"lists": [{"name": "mylist", "kind": "bogus", "items": []}]})
        assert "CF471" in _ids(ctx)

    def test_valid_list_no_errors(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.0/24"}],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestIPListItems:
    def test_cf472_missing_ip_field(self):
        ctx = _lint({"lists": [{"name": "myips", "kind": "ip", "items": [{"comment": "oops"}]}]})
        assert "CF472" in _ids(ctx)

    def test_cf473_invalid_ip(self):
        ctx = _lint({"lists": [{"name": "myips", "kind": "ip", "items": [{"ip": "not-an-ip"}]}]})
        assert "CF473" in _ids(ctx)

    def test_cf475_duplicate_ip(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.4"}],
                    }
                ]
            }
        )
        assert "CF475" in _ids(ctx)

    def test_valid_ips(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [
                            {"ip": "1.2.3.4"},
                            {"ip": "10.0.0.0/8"},
                            {"ip": "2001:db8::/32"},
                        ],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestASNListItems:
    def test_cf474_invalid_asn_type(self):
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": "not-int"}]}]})
        assert "CF474" in _ids(ctx)

    def test_cf474_asn_boolean_true_rejected(self):
        """bool is a subclass of int in Python — True should not be accepted as ASN."""
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": True}]}]})
        assert "CF474" in _ids(ctx)

    def test_cf474_asn_boolean_false_rejected(self):
        """bool is a subclass of int in Python — False should not be accepted as ASN."""
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": False}]}]})
        assert "CF474" in _ids(ctx)

    def test_cf474_asn_out_of_range(self):
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": -1}]}]})
        assert "CF474" in _ids(ctx)

    def test_cf475_duplicate_asn(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myasns",
                        "kind": "asn",
                        "items": [{"asn": 12345}, {"asn": 12345}],
                    }
                ]
            }
        )
        assert "CF475" in _ids(ctx)

    def test_valid_asns(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myasns",
                        "kind": "asn",
                        "items": [{"asn": 12345}, {"asn": 67890}],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestHostnameListItems:
    def test_cf475_duplicate_hostname(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "hosts",
                        "kind": "hostname",
                        "items": [
                            {"hostname": {"url_hostname": "evil.com"}},
                            {"hostname": {"url_hostname": "evil.com"}},
                        ],
                    }
                ]
            }
        )
        assert "CF475" in _ids(ctx)


class TestRedirectListItems:
    def test_cf472_missing_redirect_field(self):
        ctx = _lint(
            {"lists": [{"name": "redirects", "kind": "redirect", "items": [{"bogus": "val"}]}]}
        )
        assert "CF472" in _ids(ctx)

    def test_cf475_duplicate_redirect_source(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "redirects",
                        "kind": "redirect",
                        "items": [
                            {
                                "redirect": {
                                    "source_url": "example.com/old",
                                    "target_url": "https://example.com/new",
                                }
                            },
                            {
                                "redirect": {
                                    "source_url": "example.com/old",
                                    "target_url": "https://example.com/other",
                                }
                            },
                        ],
                    }
                ]
            }
        )
        assert "CF475" in _ids(ctx)


class TestNoListsSection:
    def test_no_lists_no_errors(self):
        ctx = _lint({"waf_custom_rules": []})
        assert _ids(ctx) == []
