"""Tests for list validation (Category Q)."""

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


class TestCF476ListItemCount:
    def test_cf476_over_limit(self):
        items = [{"ip": f"10.0.{i // 256}.{i % 256}"} for i in range(10001)]
        ctx = _lint({"lists": [{"name": "biglist", "kind": "ip", "items": items}]})
        assert "CF476" in _ids(ctx)

    def test_cf476_at_limit(self):
        items = [{"ip": f"10.0.{i // 256}.{i % 256}"} for i in range(10000)]
        ctx = _lint({"lists": [{"name": "biglist", "kind": "ip", "items": items}]})
        assert "CF476" not in _ids(ctx)


class TestCF477HostBitsSet:
    """CF477: CIDR with host bits set in IP list."""

    def test_cf477_host_bits_set(self):
        """10.0.0.1/24 has host bits set — should trigger CF477."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.1/24"}],
                    }
                ]
            }
        )
        assert "CF477" in _ids(ctx)
        cf477 = [r for r in ctx.results if r.rule_id == "CF477"]
        assert "host bits" in cf477[0].message
        assert "10.0.0.0/24" in cf477[0].message  # suggestion

    def test_cf477_no_host_bits(self):
        """10.0.0.0/24 has no host bits — should NOT trigger CF477."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}],
                    }
                ]
            }
        )
        assert "CF477" not in _ids(ctx)

    def test_cf477_single_host(self):
        """/32 single host should never trigger CF477."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.1/32"}],
                    }
                ]
            }
        )
        assert "CF477" not in _ids(ctx)

    def test_cf477_ipv6_host_bits(self):
        """IPv6 with host bits set should trigger CF477."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "2001:db8::1/32"}],
                    }
                ]
            }
        )
        assert "CF477" in _ids(ctx)


class TestCF478IPOverlap:
    """CF478: Overlapping IPs/CIDRs in an IP list."""

    def test_cf478_overlap_detected(self):
        """10.0.0.0/24 is a subnet of 10.0.0.0/16 — should trigger CF478."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}, {"ip": "10.0.0.0/16"}],
                    }
                ]
            }
        )
        assert "CF478" in _ids(ctx)

    def test_cf478_no_overlap(self):
        """10.0.0.0/24 and 10.0.1.0/24 don't overlap — should NOT trigger CF478."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}, {"ip": "10.0.1.0/24"}],
                    }
                ]
            }
        )
        assert "CF478" not in _ids(ctx)

    def test_cf478_exact_duplicate_not_cf478(self):
        """Exact duplicates are CF475, not CF478."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}, {"ip": "10.0.0.0/24"}],
                    }
                ]
            }
        )
        assert "CF475" in _ids(ctx)
        assert "CF478" not in _ids(ctx)

    def test_cf478_host_in_network(self):
        """A /32 host inside a broader network should trigger CF478."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.0/24"}],
                    }
                ]
            }
        )
        assert "CF478" in _ids(ctx)

    def test_cf478_ipv6_overlap(self):
        """IPv6 overlap should also be detected."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [
                            {"ip": "2001:db8::/32"},
                            {"ip": "2001:db8:1::/48"},
                        ],
                    }
                ]
            }
        )
        assert "CF478" in _ids(ctx)

    def test_cf478_ipv4_ipv6_no_cross(self):
        """IPv4 and IPv6 should not be compared for overlap."""
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "0.0.0.0/0"}, {"ip": "::/0"}],
                    }
                ]
            }
        )
        assert "CF478" not in _ids(ctx)

    def test_cf478_sweep_line_fast_on_large_input(self):
        """CF478 uses O(n log n) sweep-line (v0.7.8 rewrite). 1,000 disjoint
        /32s must lint well under a second; the pre-v0.7.8 O(n²) pairwise
        check would need hundreds of thousands of comparisons at this size.
        """
        import time

        items = [{"ip": f"203.0.{i // 256}.{i % 256}/32"} for i in range(1000)]
        start = time.monotonic()
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "big",
                        "kind": "ip",
                        "items": items,
                    }
                ]
            }
        )
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"CF478 sweep-line too slow: {elapsed:.2f}s for 1000 items"
        # Disjoint /32s → zero CF478 findings.
        assert "CF478" not in _ids(ctx)


class TestNoListsSection:
    def test_no_lists_no_errors(self):
        ctx = _lint({"waf_custom_rules": []})
        assert _ids(ctx) == []
