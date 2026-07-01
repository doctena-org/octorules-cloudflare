"""Tests for AST linter — expression-level rules (Categories A, E, F, G, O)."""

import pytest
from octorules.linter.engine import LintContext, Severity
from octorules.phases import PHASE_BY_NAME
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_cloudflare.linter.ast_linter import (
    _extract_function_call_args,
    lint_expressions,
)
from octorules_cloudflare.linter.expression_bridge import WIREFILTER_AVAILABLE


def _lint(expression, phase_name="waf_custom_rules", ref="test"):
    rule = {"ref": ref, "expression": expression}
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_expressions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestValueConstraints:
    def test_cf520_lowercase_method(self):
        ctx = _lint('http.request.method eq "get"')
        g001 = assert_lint(ctx, "CF520", count=1, severity=Severity.WARNING, ref="test")
        assert "get" in g001[0].message or "uppercase" in g001[0].message.lower()

    def test_cf520_uppercase_method_ok(self):
        ctx = _lint('http.request.method eq "GET"')
        assert_no_lint(ctx, "CF520")

    def test_cf521_no_false_positive_on_other_field_values(self):
        # Values for cf.zone.name should not trigger CF521
        ctx = _lint('cf.zone.name eq "doctena.com" and http.request.uri.path eq "/api"')
        g002 = [r for r in ctx.results if r.rule_id == "CF521"]
        assert len(g002) == 0

    def test_cf521_fires_on_bad_path_eq(self):
        ctx = _lint('http.request.uri.path eq "api"')
        assert "CF521" in _ids(ctx)

    def test_cf521_fires_on_bad_path_in_set(self):
        ctx = _lint('http.request.uri.path in {"/ok" "bad"}')
        g002 = assert_lint(ctx, "CF521", count=1, severity=Severity.WARNING, ref="test")
        assert "bad" in g002[0].message

    def test_cf522_regex_anchor_in_literal(self):
        ctx = _lint('http.request.uri.path eq "^/api"')
        assert "CF522" in _ids(ctx)

    def test_cf522_no_false_positive_on_matches(self):
        # With 'matches' operator, regex anchors are expected
        ctx = _lint('http.request.uri.path matches "^/api"')
        assert "CF522" not in _ids(ctx)

    def test_cf522_fires_when_expression_also_has_regex(self):
        # PR #83 regression: CF522 must fire for regex anchor in 'in' set
        # even when the expression also uses 'matches' elsewhere
        ctx = _lint(
            '(http.request.uri.path in {"/foo" "^/bar"}) or '
            '(http.request.uri.path matches "^/staging/.*")'
        )
        assert "CF522" in _ids(ctx)
        g003 = [r for r in ctx.results if r.rule_id == "CF522"]
        assert any("^/bar" in r.message for r in g003)

    def test_cf522_no_false_positive_dollar_in_path(self):
        # A '$' in a string literal used with 'in' should fire
        ctx = _lint('http.request.uri.path in {"/ok" "/test$"}')
        assert "CF522" in _ids(ctx)

    def test_cf528_duplicate_string_in_set(self):
        ctx = _lint('http.request.uri.path in {"/foo" "/bar" "/foo"}')
        assert "CF528" in _ids(ctx)
        g009 = [r for r in ctx.results if r.rule_id == "CF528"]
        assert any("/foo" in r.message for r in g009)

    def test_cf528_duplicate_ip_in_set(self):
        ctx = _lint("ip.src in {1.2.3.4 5.6.7.8 1.2.3.4}")
        assert "CF528" in _ids(ctx)
        g009 = [r for r in ctx.results if r.rule_id == "CF528"]
        assert any("1.2.3.4" in r.message for r in g009)

    def test_cf528_duplicate_int_in_set(self):
        ctx = _lint("ip.geoip.asnum in {123 456 123}")
        assert "CF528" in _ids(ctx)

    def test_cf528_no_false_positive_unique_values(self):
        ctx = _lint('http.request.uri.path in {"/a" "/b" "/c"}')
        assert "CF528" not in _ids(ctx)

    def test_cf528_multiple_in_sets_independent(self):
        # Duplicates within one set should fire; no cross-set false positives
        ctx = _lint(
            '(http.request.uri.path in {"/a" "/a"}) and (http.request.method in {"GET" "POST"})'
        )
        g009 = [r for r in ctx.results if r.rule_id == "CF528"]
        assert len(g009) == 1
        assert any("/a" in r.message for r in g009)

    def test_cf528_multiple_duplicates_reported(self):
        ctx = _lint("ip.src in {1.1.1.1 2.2.2.2 1.1.1.1 2.2.2.2}")
        g009 = [r for r in ctx.results if r.rule_id == "CF528"]
        assert len(g009) == 2

    def test_cf523_lowercase_country_code(self):
        ctx = _lint('ip.geoip.country eq "de"')
        assert "CF523" in _ids(ctx)

    def test_cf523_uppercase_country_code_ok(self):
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "CF523" not in _ids(ctx)

    def test_cf524_score_out_of_range(self):
        ctx = _lint("cf.threat_score gt 200")
        assert "CF524" in _ids(ctx)

    def test_cf524_score_in_range(self):
        ctx = _lint("cf.threat_score gt 50")
        assert "CF524" not in _ids(ctx)

    def test_cf524_per_field_no_false_positive(self):
        # Integer 200 belongs to http.response.code, not cf.waf.score
        ctx = _lint(
            "cf.waf.score gt 50 and http.response.code eq 200",
            "response_header_rules",
        )
        g005 = [r for r in ctx.results if r.rule_id == "CF524"]
        assert len(g005) == 0

    def test_cf524_bot_management_score_range(self):
        # cf.bot_management.score valid range is 1-99
        ctx = _lint("cf.bot_management.score gt 0")
        assert "CF524" in _ids(ctx)
        ctx2 = _lint("cf.bot_management.score gt 1")
        assert "CF524" not in _ids(ctx2)

    def test_cf525_invalid_response_code(self):
        ctx = _lint("http.response.code eq 999", "response_header_rules")
        assert "CF525" in _ids(ctx)

    def test_cf525_valid_response_code(self):
        ctx = _lint("http.response.code eq 200", "response_header_rules")
        assert "CF525" not in _ids(ctx)

    def test_cf527_extension_with_dot(self):
        ctx = _lint('http.request.uri.path.extension in {".jpg" ".png"}')
        assert "CF527" in _ids(ctx)

    def test_cf527_extension_without_dot(self):
        ctx = _lint('http.request.uri.path.extension in {"jpg" "png"}')
        assert "CF527" not in _ids(ctx)


class TestDeprecatedFields:
    def test_cf529_ip_geoip_asnum(self):
        ctx = _lint("ip.geoip.asnum eq 13335")
        assert "CF529" in _ids(ctx)
        g010 = [r for r in ctx.results if r.rule_id == "CF529"]
        assert "ip.src.asnum" in g010[0].message

    def test_cf529_ip_geoip_continent(self):
        ctx = _lint('ip.geoip.continent eq "EU"')
        assert "CF529" in _ids(ctx)

    def test_cf529_ip_geoip_country(self):
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "CF529" in _ids(ctx)

    def test_cf529_ip_geoip_subdivision_1(self):
        ctx = _lint('ip.geoip.subdivision_1_iso_code eq "BY"')
        assert "CF529" in _ids(ctx)

    def test_cf529_ip_geoip_subdivision_2(self):
        ctx = _lint('ip.geoip.subdivision_2_iso_code eq "MU"')
        assert "CF529" in _ids(ctx)

    def test_cf529_ip_geoip_eu(self):
        ctx = _lint("ip.geoip.is_in_european_union")
        assert "CF529" in _ids(ctx)

    def test_cf529_ip_src_country_ok(self):
        ctx = _lint('ip.src.country eq "DE"')
        assert "CF529" not in _ids(ctx)

    def test_cf529_unrelated_field_ok(self):
        ctx = _lint('http.host eq "example.com"')
        assert "CF529" not in _ids(ctx)

    def test_cf529_two_deprecated_fields(self):
        ctx = _lint('ip.geoip.country eq "DE" and ip.geoip.continent eq "EU"')
        g010 = assert_lint(ctx, "CF529", count=2, severity=Severity.WARNING)
        # Both deprecated fields should be mentioned
        messages = " ".join(r.message for r in g010)
        assert "ip.geoip.country" in messages
        assert "ip.geoip.continent" in messages


class TestBogonIPs:
    def test_cf530_rfc1918_10(self):
        ctx = _lint("ip.src in {10.0.0.1}")
        assert "CF530" in _ids(ctx)

    def test_cf530_rfc1918_172(self):
        ctx = _lint("ip.src == 172.16.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_rfc1918_192(self):
        ctx = _lint("ip.src == 192.168.1.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_loopback(self):
        ctx = _lint("ip.src == 127.0.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_link_local(self):
        ctx = _lint("ip.src == 169.254.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_cgnat(self):
        ctx = _lint("ip.src == 100.64.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_documentation(self):
        ctx = _lint("ip.src == 192.0.2.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_cidr_private(self):
        ctx = _lint("ip.src in {10.0.0.0/8}")
        assert "CF530" in _ids(ctx)

    def test_cf530_public_ip_ok(self):
        ctx = _lint("ip.src == 1.1.1.1")
        assert "CF530" not in _ids(ctx)

    def test_cf530_public_cidr_ok(self):
        ctx = _lint("ip.src in {8.8.8.0/24}")
        assert "CF530" not in _ids(ctx)

    def test_cf530_message_includes_description(self):
        ctx = _lint("ip.src == 10.0.0.1")
        g011 = [r for r in ctx.results if r.rule_id == "CF530"]
        assert "RFC 1918 private" in g011[0].message

    def test_cf530_multiple_bogons(self):
        ctx = _lint("ip.src in {10.0.0.1 192.168.1.1}")
        g011 = [r for r in ctx.results if r.rule_id == "CF530"]
        assert len(g011) == 2


class TestOverlappingIPs:
    def test_cf531_single_ip_within_cidr(self):
        ctx = _lint("ip.src in {10.0.0.1 10.0.0.0/8}")
        assert "CF531" in _ids(ctx)

    def test_cf531_cidr_within_cidr(self):
        ctx = _lint("ip.src in {10.0.0.0/24 10.0.0.0/8}")
        assert "CF531" in _ids(ctx)

    def test_cf531_same_base_different_prefix(self):
        ctx = _lint("ip.src in {192.168.1.0/24 192.168.0.0/16}")
        assert "CF531" in _ids(ctx)

    def test_cf531_non_overlapping_ok(self):
        ctx = _lint("ip.src in {1.1.1.0/24 8.8.8.0/24}")
        assert "CF531" not in _ids(ctx)

    def test_cf531_single_ip_ok(self):
        ctx = _lint("ip.src == 1.1.1.1")
        assert "CF531" not in _ids(ctx)

    def test_cf531_adjacent_non_overlapping_ok(self):
        ctx = _lint("ip.src in {10.0.0.0/25 10.0.0.128/25}")
        assert "CF531" not in _ids(ctx)

    def test_cf531_message_content(self):
        ctx = _lint("ip.src in {10.0.0.1 10.0.0.0/8}")
        g012 = [r for r in ctx.results if r.rule_id == "CF531"]
        assert len(g012) == 1
        assert "10.0.0.1" in g012[0].message
        assert "10.0.0.0/8" in g012[0].message


class TestHeaderNameCase:
    def test_cf526_uppercase_header_name(self):
        ctx = _lint('any(http.request.headers["X-Custom-Header"][*] eq "val")')
        assert "CF526" in _ids(ctx)

    def test_cf526_lowercase_header_ok(self):
        ctx = _lint('any(http.request.headers["x-custom-header"][*] eq "val")')
        assert "CF526" not in _ids(ctx)


class TestTypeConstraints:
    def test_cf307_numeric_op_on_string_field(self):
        ctx = _lint("http.host gt 5")
        assert "CF307" in _ids(ctx)

    def test_cf307_string_on_numeric_field(self):
        ctx = _lint('cf.threat_score eq "high"')
        assert "CF307" in _ids(ctx)

    def test_cf307_valid_string_comparison(self):
        ctx = _lint('http.host eq "example.com"')
        assert "CF307" not in _ids(ctx)

    def test_cf307_valid_numeric_comparison(self):
        ctx = _lint("cf.threat_score gt 50")
        assert "CF307" not in _ids(ctx)


class TestStyleSuggestions:
    def test_cf510_multiple_or_to_in(self):
        ctx = _lint('http.host eq "a" or http.host eq "b" or http.host eq "c"')
        assert "CF510" in _ids(ctx)

    def test_cf510_not_triggered_for_few(self):
        ctx = _lint('http.host eq "a" or http.host eq "b"')
        assert "CF510" not in _ids(ctx)

    def test_cf511_raw_field_suggestion(self):
        ctx = _lint('raw.http.request.uri.path eq "/test"')
        assert "CF511" in _ids(ctx)

    def test_cf512_double_negation(self):
        ctx = _lint('not not http.host eq "example.com"')
        assert "CF512" in _ids(ctx)

    def test_cf512_single_not_ok(self):
        ctx = _lint('not http.host eq "example.com"')
        assert "CF512" not in _ids(ctx)


class TestFunctionConstraints:
    def test_cf300_unknown_function(self):
        ctx = _lint('bogus_function(http.host, "x")')
        assert "CF300" in _ids(ctx)

    def test_cf300_known_function_ok(self):
        ctx = _lint('starts_with(http.request.uri.path, "/api/")')
        assert "CF300" not in _ids(ctx)

    def test_cf300_encode_base64_ok(self):
        ctx = _lint('encode_base64(http.request.uri.path) eq "L2Fw"')
        assert "CF300" not in _ids(ctx)

    def test_cf300_decode_base64_ok(self):
        ctx = _lint('decode_base64(http.request.uri.path) eq "/api"')
        assert "CF300" not in _ids(ctx)

    def test_cf300_cidr_ok(self):
        ctx = _lint("cidr(ip.src, 24, 0) == 10.0.0.0")
        assert "CF300" not in _ids(ctx)

    def test_cf300_cidr6_ok(self):
        ctx = _lint("cidr6(ip.src, 48) == 2001:db8::")
        assert "CF300" not in _ids(ctx)

    def test_cf300_join_ok(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"')
        assert "CF300" not in _ids(ctx)

    def test_cf300_split_ok(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "CF300" not in _ids(ctx)

    def test_cf300_has_key_ok(self):
        ctx = _lint('has_key(http.request.headers, "x-api-key")')
        assert "CF300" not in _ids(ctx)

    def test_cf300_wildcard_replace_ok(self):
        ctx = _lint('wildcard_replace(http.host, "*.example.com", "${1}.cdn.com") eq "a.cdn.com"')
        assert "CF300" not in _ids(ctx)


class TestNoExpression:
    def test_no_crash_on_missing_expression(self):
        rule = {"ref": "test"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext()
        lint_expressions(rule, phase, ctx)
        assert len(ctx.results) == 0

    def test_no_crash_on_non_string_expression(self):
        rule = {"ref": "test", "expression": 42}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext()
        lint_expressions(rule, phase, ctx)
        assert len(ctx.results) == 0


class TestBogonIPsNewRanges:
    def test_cf530_iana_special_purpose(self):
        ctx = _lint("ip.src == 192.0.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_6to4_relay(self):
        ctx = _lint("ip.src == 192.88.99.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_benchmark_testing(self):
        ctx = _lint("ip.src == 198.18.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_multicast(self):
        ctx = _lint("ip.src == 224.0.0.1")
        assert "CF530" in _ids(ctx)

    def test_cf530_reserved_future(self):
        ctx = _lint("ip.src == 240.0.0.1")
        assert "CF530" in _ids(ctx)


class TestValueDomains:
    def test_cf532_full_uri_must_start_with_http(self):
        ctx = _lint('http.request.full_uri eq "ftp://example.com"')
        assert "CF532" in _ids(ctx)

    def test_cf532_full_uri_https_ok(self):
        ctx = _lint('http.request.full_uri eq "https://example.com"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_http_version_must_start_with_http(self):
        ctx = _lint('http.request.version eq "2.0"')
        assert "CF532" in _ids(ctx)

    def test_cf532_http_version_ok(self):
        ctx = _lint('http.request.version eq "HTTP/2"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_mime_must_contain_slash(self):
        ctx = _lint('http.request.body.mime eq "texthtml"')
        assert "CF532" in _ids(ctx)

    def test_cf532_mime_ok(self):
        ctx = _lint('http.request.body.mime eq "text/html"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_mime_uppercase_flagged(self):
        ctx = _lint('http.request.body.mime eq "Text/HTML"')
        assert "CF532" in _ids(ctx)

    def test_cf532_continent_invalid(self):
        ctx = _lint('ip.src.continent eq "XX"')
        assert "CF532" in _ids(ctx)

    def test_cf532_continent_valid(self):
        ctx = _lint('ip.src.continent eq "EU"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_continent_t1_valid(self):
        ctx = _lint('ip.src.continent eq "T1"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_waf_score_class_invalid(self):
        ctx = _lint('cf.waf.score.class eq "bad"')
        assert "CF532" in _ids(ctx)

    def test_cf532_waf_score_class_valid(self):
        ctx = _lint('cf.waf.score.class eq "attack"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_error_type_invalid(self):
        ctx = _lint('cf.response.error_type eq "unknown"')
        assert "CF532" in _ids(ctx)

    def test_cf532_error_type_valid(self):
        ctx = _lint('cf.response.error_type eq "waf"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_raw_uri_path_must_start_with_slash(self):
        ctx = _lint('raw.http.request.uri.path eq "api"')
        g013 = [r for r in ctx.results if r.rule_id == "CF532"]
        assert len(g013) == 1

    def test_cf532_raw_extension_no_dots(self):
        ctx = _lint('raw.http.request.uri.path.extension eq ".js"')
        assert "CF532" in _ids(ctx)

    def test_cf532_raw_extension_ok(self):
        ctx = _lint('raw.http.request.uri.path.extension eq "js"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_timestamp_msec_out_of_range(self):
        ctx = _lint("http.request.timestamp.msec eq 1500")
        assert "CF532" in _ids(ctx)

    def test_cf532_timestamp_msec_in_range(self):
        ctx = _lint("http.request.timestamp.msec eq 500")
        assert "CF532" not in _ids(ctx)


class TestTimestampBounds:
    def test_cf533_too_old(self):
        ctx = _lint("http.request.timestamp.sec gt 1000")
        assert "CF533" in _ids(ctx)

    def test_cf533_valid(self):
        # A recent-ish timestamp (Jan 2024)
        ctx = _lint("http.request.timestamp.sec gt 1704067200")
        assert "CF533" not in _ids(ctx)

    def test_cf533_too_far_future(self):
        # Year 2099
        ctx = _lint("http.request.timestamp.sec gt 4102444800")
        assert "CF533" in _ids(ctx)

    def test_cf533_near_future_ok(self):
        # 6 months from now — should be fine
        import time

        ts = int(time.time()) + 180 * 86400
        ctx = _lint(f"http.request.timestamp.sec gt {ts}")
        assert "CF533" not in _ids(ctx)


class TestIntRangeOverlap:
    def test_cf534_value_in_range(self):
        ctx = _lint("ip.src.asnum in {100 50..200}")
        assert "CF534" in _ids(ctx)

    def test_cf534_subrange(self):
        ctx = _lint("ip.src.asnum in {60..70 50..200}")
        assert "CF534" in _ids(ctx)

    def test_cf534_no_overlap(self):
        ctx = _lint("ip.src.asnum in {10..20 50..100}")
        assert "CF534" not in _ids(ctx)

    def test_cf534_identical_not_flagged(self):
        # Exact duplicates are CF528's job
        ctx = _lint("ip.src.asnum in {100 100}")
        assert "CF534" not in _ids(ctx)

    def test_cf534_single_ok(self):
        ctx = _lint("ip.src.asnum in {100}")
        assert "CF534" not in _ids(ctx)


class TestNegatedComparison:
    def test_cf513_not_eq_to_ne(self):
        ctx = _lint('not http.host eq "example.com"')
        assert "CF513" in _ids(ctx)
        o004 = [r for r in ctx.results if r.rule_id == "CF513"]
        assert "ne" in o004[0].message

    def test_cf513_not_lt_to_ge(self):
        ctx = _lint("not cf.threat_score lt 50")
        assert "CF513" in _ids(ctx)
        o004 = [r for r in ctx.results if r.rule_id == "CF513"]
        assert "ge" in o004[0].message

    def test_cf513_ne_not_flagged(self):
        ctx = _lint('http.host ne "example.com"')
        assert "CF513" not in _ids(ctx)

    def test_cf513_suggestion_content(self):
        ctx = _lint('not http.host eq "example.com"')
        o004 = [r for r in ctx.results if r.rule_id == "CF513"]
        assert o004[0].suggestion is not None
        assert "ne" in o004[0].suggestion


class TestIllogicalCondition:
    def test_cf514_contradictory_and(self):
        ctx = _lint('http.host eq "a.com" and http.host eq "b.com"')
        assert "CF514" in _ids(ctx)

    def test_cf514_tautological_or(self):
        ctx = _lint('http.host ne "a.com" or http.host ne "b.com"')
        assert "CF514" in _ids(ctx)

    def test_cf514_valid_and_different_fields(self):
        ctx = _lint('http.host eq "a.com" and http.referer eq "b.com"')
        assert "CF514" not in _ids(ctx)

    def test_cf514_same_value_and_ok(self):
        ctx = _lint('http.host eq "a.com" and http.host eq "a.com"')
        assert "CF514" not in _ids(ctx)

    def test_cf514_mixed_connectives_skip(self):
        # Mixed and/or without parens — don't flag (ambiguous precedence)
        ctx = _lint('http.host eq "a.com" and http.host eq "b.com" or http.host eq "c.com"')
        assert "CF514" not in _ids(ctx)

    def test_cf514_parens_isolate(self):
        # Outer parens stripped, inner parens preserved
        ctx = _lint('(http.host eq "a.com") and (http.host eq "b.com")')
        assert "CF514" in _ids(ctx)


class TestRegexEscapes:
    def test_cf515_literal_with_backslash(self):
        ctx = _lint(r'http.request.uri.path matches "\\.(js|css)$"')
        assert "CF515" in _ids(ctx)

    def test_cf515_no_backslash_ok(self):
        ctx = _lint('http.request.uri.path matches "^/api/"')
        assert "CF515" not in _ids(ctx)


class TestHasValueFunction:
    def test_cf300_has_value_ok(self):
        ctx = _lint('has_value(http.request.headers.names, "x-api-key")')
        assert "CF300" not in _ids(ctx)


class TestIPv6BogonRanges:
    def test_cf530_ipv6_loopback(self):
        ctx = _lint("ip.src == ::1")
        assert "CF530" in _ids(ctx)

    def test_cf530_ipv6_documentation(self):
        ctx = _lint("ip.src in {2001:db8::1}")
        assert "CF530" in _ids(ctx)

    def test_cf530_ipv6_unique_local(self):
        ctx = _lint("ip.src == fd12:3456:789a::1")
        assert "CF530" in _ids(ctx)

    def test_cf530_ipv6_link_local(self):
        ctx = _lint("ip.src == fe80::1")
        assert "CF530" in _ids(ctx)

    def test_cf530_ipv6_multicast(self):
        ctx = _lint("ip.src == ff02::1")
        assert "CF530" in _ids(ctx)

    def test_cf530_ipv6_public_ok(self):
        ctx = _lint("ip.src == 2606:4700::1")
        assert "CF530" not in _ids(ctx)

    def test_cf530_ipv6_via_regex_fallback(self, monkeypatch):
        """Verify CF530 fires for IPv6 even without wirefilter FFI."""
        from octorules_cloudflare.linter import expression_bridge

        monkeypatch.setattr(expression_bridge, "WIREFILTER_AVAILABLE", False)
        # Force regex path — ::1 is loopback
        ctx = _lint("ip.src == ::1")
        assert "CF530" in _ids(ctx)


class TestLowerUpperMismatch:
    def test_cf535_lower_uppercase_value(self):
        ctx = _lint('lower(http.host) eq "EXAMPLE.COM"')
        assert "CF535" in _ids(ctx)

    def test_cf535_lower_lowercase_ok(self):
        ctx = _lint('lower(http.host) eq "example.com"')
        assert "CF535" not in _ids(ctx)

    def test_cf535_upper_lowercase_value(self):
        ctx = _lint('upper(http.host) eq "example.com"')
        assert "CF535" in _ids(ctx)

    def test_cf535_upper_uppercase_ok(self):
        ctx = _lint('upper(http.host) eq "EXAMPLE.COM"')
        assert "CF535" not in _ids(ctx)

    def test_cf535_lower_in_set(self):
        ctx = _lint('lower(http.host) in {"ok" "BAD"}')
        assert "CF535" in _ids(ctx)


class TestLenNegative:
    def test_cf536_negative_triggers(self):
        ctx = _lint("len(http.host) gt -1")
        assert "CF536" in _ids(ctx)

    def test_cf536_zero_ok(self):
        ctx = _lint("len(http.host) gt 0")
        assert "CF536" not in _ids(ctx)

    def test_cf536_positive_ok(self):
        ctx = _lint("len(http.host) gt 10")
        assert "CF536" not in _ids(ctx)


class TestF001FullRegistry:
    def test_cf307_ip_gt(self):
        ctx = _lint("ip.src gt 5")
        assert "CF307" in _ids(ctx)

    def test_cf307_int_contains(self):
        ctx = _lint('cf.threat_score contains "x"')
        assert "CF307" in _ids(ctx)

    def test_cf307_bool_string(self):
        ctx = _lint('cf.bot_management.verified_bot eq "true"')
        assert "CF307" in _ids(ctx)

    def test_cf307_string_numeric_ok(self):
        ctx = _lint('http.host eq "example.com"')
        assert "CF307" not in _ids(ctx)


class TestE003ReplaceLimits:
    def test_cf302_regex_replace_twice(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq regex_replace(http.host, "c", "d")',
            "url_rewrite_rules",
        )
        assert "CF302" in _ids(ctx)

    def test_cf302_wildcard_replace_twice(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*a*", "b") eq wildcard_replace(http.host, "*c*", "d")',
            "url_rewrite_rules",
        )
        assert "CF302" in _ids(ctx)

    def test_cf302_both_present(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq wildcard_replace(http.host, "*c*", "d")',
            "url_rewrite_rules",
        )
        assert "CF302" in _ids(ctx)

    def test_cf302_single_ok(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq "c"',
            "url_rewrite_rules",
        )
        assert "CF302" not in _ids(ctx)


class TestE002PhaseRestrictions:
    def test_cf301_regex_replace_in_waf(self):
        ctx = _lint('regex_replace(http.host, "a", "b") eq "c"', "waf_custom_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_regex_replace_in_transform_ok(self):
        ctx = _lint('regex_replace(http.host, "a", "b") eq "c"', "url_rewrite_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_sha256_in_waf(self):
        ctx = _lint('sha256(http.host) eq "abc"', "waf_custom_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_uuidv4_in_transform_ok(self):
        ctx = _lint('uuidv4() eq "abc"', "url_rewrite_rules")
        assert "CF301" not in _ids(ctx)


class TestG005ExtendedRanges:
    def test_cf524_port_out_of_range(self):
        ctx = _lint("cf.edge.server_port eq 0")
        assert "CF524" in _ids(ctx)

    def test_cf524_port_valid(self):
        ctx = _lint("cf.edge.server_port eq 443")
        assert "CF524" not in _ids(ctx)


class TestG018WildcardDoubleAsterisk:
    def test_cf537_double_asterisk_fires(self):
        ctx = _lint('http.host wildcard "**.example.com"')
        assert "CF537" in _ids(ctx)

    def test_cf537_single_asterisk_ok(self):
        ctx = _lint('http.host wildcard "*.example.com"')
        assert "CF537" not in _ids(ctx)

    def test_cf537_strict_wildcard_double(self):
        ctx = _lint('http.host strict wildcard "test**"')
        assert "CF537" in _ids(ctx)


class TestG006PerField:
    def test_cf525_no_false_positive_on_other_int(self):
        # cf.threat_score value 50 should NOT trigger CF525
        ctx = _lint(
            "http.response.code eq 200 and cf.threat_score gt 50",
            "response_header_rules",
        )
        g006 = [r for r in ctx.results if r.rule_id == "CF525"]
        assert len(g006) == 0


class TestG007BracketUppercase:
    def test_cf526_bracket_uppercase_no_dash(self):
        # Map bracket keys are always header names — uppercase without dash should fire
        ctx = _lint('any(http.request.headers["Authorization"][*] eq "val")')
        assert "CF526" in _ids(ctx)

    def test_cf526_bracket_lowercase_ok(self):
        ctx = _lint('any(http.request.headers["authorization"][*] eq "val")')
        assert "CF526" not in _ids(ctx)


class TestO001OrContext:
    def test_cf510_and_chain_no_trigger(self):
        # AND chain with 3 eq — should NOT trigger CF510
        ctx = _lint('http.host eq "a" and http.host eq "b" and http.host eq "c"')
        assert "CF510" not in _ids(ctx)


class TestO003Parens:
    def test_cf512_not_paren_not(self):
        ctx = _lint('not (not http.host eq "example.com")')
        assert "CF512" in _ids(ctx)


class TestG019ReversedRange:
    def test_cf538_start_gt_end(self):
        ctx = _lint("http.response.code in {500..200}", "response_header_rules")
        assert "CF538" in _ids(ctx)

    def test_cf538_valid_range_ok(self):
        ctx = _lint("http.response.code in {200..299}", "response_header_rules")
        assert "CF538" not in _ids(ctx)

    def test_cf538_equal_range_ok(self):
        ctx = _lint("http.response.code in {200..200}", "response_header_rules")
        assert "CF538" not in _ids(ctx)


class TestH003RegexCount:
    def test_cf502_too_many_regex(self):
        patterns = " or ".join(f'http.request.uri.path matches "^/p{i}/"' for i in range(65))
        ctx = _lint(patterns)
        h003 = assert_lint(ctx, "CF502", count=1, severity=Severity.WARNING)
        assert "64" in h003[0].message

    def test_cf502_exactly_64_ok(self):
        """Boundary: exactly 64 regex patterns should not fire CF502."""
        patterns = " or ".join(f'http.request.uri.path matches "^/p{i}/"' for i in range(64))
        ctx = _lint(patterns)
        assert_no_lint(ctx, "CF502")

    def test_cf502_under_limit_ok(self):
        patterns = " or ".join(f'http.request.uri.path matches "^/p{i}/"' for i in range(10))
        ctx = _lint(patterns)
        assert_no_lint(ctx, "CF502")


class TestE004EncodeBase64Flags:
    def test_cf303_invalid_flag(self):
        ctx = _lint('encode_base64(http.host, "x") eq "abc"', "url_rewrite_rules")
        assert "CF303" in _ids(ctx)

    def test_cf303_valid_flag(self):
        ctx = _lint('encode_base64(http.host, "u") eq "abc"', "url_rewrite_rules")
        assert "CF303" not in _ids(ctx)


class TestE005UrlDecodeFlags:
    def test_cf304_invalid_option(self):
        ctx = _lint('url_decode(http.host, "z") eq "abc"')
        assert "CF304" in _ids(ctx)

    def test_cf304_valid_option(self):
        ctx = _lint('url_decode(http.host, "r") eq "abc"')
        assert "CF304" not in _ids(ctx)


class TestE006WildcardReplaceFlags:
    def test_cf305_invalid_flag(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com", "x") eq "a"',
            "url_rewrite_rules",
        )
        assert "CF305" in _ids(ctx)

    def test_cf305_valid_flag(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com", "s") eq "a"',
            "url_rewrite_rules",
        )
        assert "CF305" not in _ids(ctx)


class TestG020SplitLimit:
    def test_cf539_limit_too_high(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 200)[*] eq "api")')
        assert "CF539" in _ids(ctx)

    def test_cf539_limit_zero(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 0)[*] eq "api")')
        assert "CF539" in _ids(ctx)

    def test_cf539_limit_ok(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "CF539" not in _ids(ctx)


class TestG021CidrBits:
    def test_cf540_cidr_out_of_range(self):
        ctx = _lint("cidr(ip.src, 33, 0) == 10.0.0.0")
        assert "CF540" in _ids(ctx)

    def test_cf540_cidr_valid(self):
        ctx = _lint("cidr(ip.src, 24, 0) == 10.0.0.0")
        assert "CF540" not in _ids(ctx)

    def test_cf540_cidr6_out_of_range(self):
        ctx = _lint("cidr6(ip.src, 129) == 2001:db8::")
        assert "CF540" in _ids(ctx)

    def test_cf540_cidr6_valid(self):
        ctx = _lint("cidr6(ip.src, 48) == 2001:db8::")
        assert "CF540" not in _ids(ctx)


class TestG022RemoveQueryArgs:
    def test_cf541_wrong_field(self):
        ctx = _lint(
            'remove_query_args(http.host, "key") eq "abc"',
            "url_rewrite_rules",
        )
        assert "CF541" in _ids(ctx)

    def test_cf541_correct_field(self):
        ctx = _lint(
            'remove_query_args(http.request.uri.query, "key") eq "abc"',
            "url_rewrite_rules",
        )
        assert "CF541" not in _ids(ctx)


@pytest.mark.skipif(not WIREFILTER_AVAILABLE, reason="octorules-wirefilter not installed")
class TestA001ParseErrors:
    def test_cf001_invalid_syntax(self):
        """Incomplete expression triggers CF001 when wirefilter is available."""
        ctx = _lint("http.host eq")
        assert "CF001" in _ids(ctx)

    def test_cf001_unknown_field_triggers(self):
        """Wirefilter rejects unknown field, fires CF001."""
        ctx = _lint('http.hoost eq "x"')
        assert "CF001" in _ids(ctx)

    def test_cf001_valid_expression_no_error(self):
        """Clean expression — CF001 does not fire."""
        ctx = _lint('http.host eq "example.com"')
        assert "CF001" not in _ids(ctx)

    def test_cf001_not_fired_without_wirefilter(self, monkeypatch):
        """CF001 should not fire when wirefilter is unavailable."""
        from octorules_cloudflare.linter import expression_bridge

        monkeypatch.setattr(expression_bridge, "WIREFILTER_AVAILABLE", False)
        ctx = _lint('http.hoost eq "x"')
        assert "CF001" not in _ids(ctx)

    def test_cf001_semantic_checks_still_fire(self):
        """CF300 fires alongside CF001 for unknown function in invalid expression."""
        ctx = _lint('bogus_fn(http.host) eq "x"')
        assert "CF001" in _ids(ctx)
        assert "CF300" in _ids(ctx)

    def test_cf001_suppressed_for_true_literal(self):
        """'true' is valid Cloudflare syntax; wirefilter rejects it but CF015 covers it."""
        ctx = _lint("true")
        assert "CF001" not in _ids(ctx)
        assert "CF015" not in _ids(ctx)  # CF015 fires in yaml_validator, not ast_linter

    def test_cf001_suppressed_for_false_literal(self):
        ctx = _lint("false")
        assert "CF001" not in _ids(ctx)

    def test_cf001_suppressed_for_parenthesized_true(self):
        ctx = _lint("(true)")
        assert "CF001" not in _ids(ctx)

    def test_cf001_suppressed_for_starts_with_function_call(self):
        """starts_with() function-call syntax is valid Cloudflare, wirefilter rejects it."""
        ctx = _lint('starts_with(http.request.uri.path, "/api")')
        assert "CF001" not in _ids(ctx)

    def test_cf001_suppressed_for_ends_with_function_call(self):
        ctx = _lint('ends_with(http.request.uri.path, "/")')
        assert "CF001" not in _ids(ctx)

    def test_cf001_suppressed_for_mixed_contains_and_starts_with(self):
        """Transform-phase expression mixing contains operator and starts_with() call."""
        ctx = _lint(
            '(http.host eq "dev.example.com" and '
            'not http.request.uri.path contains "." and '
            'not starts_with(http.request.uri.path, "/api"))',
            "url_rewrite_rules",
        )
        assert "CF001" not in _ids(ctx)


class TestF002UnknownField:
    def test_cf308_unknown_field_with_suggestion(self):
        """Typo in field name triggers CF308 with 'Did you mean?' suggestion."""
        ctx = _lint('http.hoost eq "x"')
        f002 = assert_lint(ctx, "CF308", count=1, severity=Severity.WARNING, ref="test")
        assert "http.hoost" in f002[0].message
        assert f002[0].suggestion
        assert "http.host" in f002[0].suggestion

    def test_cf308_known_field_ok(self):
        """Known field does not trigger CF308."""
        ctx = _lint('http.host eq "example.com"')
        assert "CF308" not in _ids(ctx)

    def test_cf308_deprecated_field_not_flagged(self):
        """Deprecated fields are in FIELDS, so CF529 fires, not CF308."""
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "CF308" not in _ids(ctx)
        assert "CF529" in _ids(ctx)

    def test_cf308_bogus_field_no_suggestion(self):
        """Very wrong name gets CF308 with no suggestion."""
        ctx = _lint('cf.zzzzzzz eq "x"')
        assert "CF308" in _ids(ctx)
        f002 = [r for r in ctx.results if r.rule_id == "CF308"]
        assert f002[0].suggestion == ""

    def test_cf308_close_typo_has_suggestion(self):
        """Near-miss field name gets a suggestion."""
        ctx = _lint("ip.scr eq 1.2.3.4")
        assert "CF308" in _ids(ctx)
        f002 = [r for r in ctx.results if r.rule_id == "CF308"]
        assert "ip.src" in (f002[0].suggestion or "")

    def test_cf308_jwt_exp_field_intentionally_absent(self):
        """JWT ``exp`` claim fields are intentionally NOT in the scheme.

        Cloudflare validates ``exp`` internally via ``is_jwt_valid()`` and
        does not expose it as a queryable field. Earlier wirefilter
        registrations of ``http.request.jwt.claims.exp.sec`` (and
        ``.sec.names``, ``.sec.values``) were speculative and have been
        removed. Re-adding any of them must be backed by current CF docs
        evidence, not symmetry with ``aud`` / ``iss`` / ``sub`` etc.
        """
        from octorules_cloudflare.linter.schemas.fields import get_field

        for name in [
            "http.request.jwt.claims.exp.sec",
            "http.request.jwt.claims.exp.sec.names",
            "http.request.jwt.claims.exp.sec.values",
        ]:
            assert get_field(name) is None, (
                f"{name!r} is intentionally absent (speculative addition); "
                "do not re-add without grep-verifying against the canonical "
                "CF fields YAML at cloudflare/cloudflare-docs/src/content/"
                "fields/index.yaml"
            )

    def test_cf308_response_headers_truncated_intentionally_absent(self):
        """``http.response.headers.truncated`` is intentionally NOT in the
        scheme. CF docs only expose the request-side
        ``http.request.headers.truncated``; the response variant was an
        earlier speculative addition.
        """
        from octorules_cloudflare.linter.schemas.fields import get_field

        assert get_field("http.response.headers.truncated") is None
        # Sanity: the request-side variant IS in the scheme.
        assert get_field("http.request.headers.truncated") is not None


class TestF001ArrayMapFields:
    def test_cf307_array_string_eq(self):
        """Scalar 'eq' on array field should fire CF307."""
        ctx = _lint('http.request.headers.names eq "x-custom"')
        assert "CF307" in _ids(ctx)
        f001 = [r for r in ctx.results if r.rule_id == "CF307"]
        assert "array" in f001[0].message.lower()

    def test_cf307_array_int_gt(self):
        """Scalar 'gt' on array<int> field should fire CF307."""
        ctx = _lint("cf.bot_management.detection_ids gt 5")
        assert "CF307" in _ids(ctx)

    def test_cf307_map_field_contains(self):
        """Scalar 'contains' on map field should fire CF307."""
        ctx = _lint('http.request.headers contains "x"')
        assert "CF307" in _ids(ctx)
        f001 = [r for r in ctx.results if r.rule_id == "CF307"]
        assert "map" in f001[0].message.lower()

    def test_cf307_array_field_any_ok(self):
        """Using any() with array field should not fire CF307 for any()."""
        ctx = _lint('any(http.request.headers.names[*] eq "x-custom")')
        assert "CF307" not in _ids(ctx)

    def test_cf307_map_field_has_key_ok(self):
        """Using has_key/indexing should not fire CF307."""
        # Expression like http.request.cookies["session"] is valid
        # Our regex-based CF307 checks for direct "field op" pattern
        ctx = _lint('http.request.uri.args["key"][0] eq "value"')
        assert "CF307" not in _ids(ctx)


class TestG005ScoreRanges:
    """Tests for CF524 score range corrections (cf.waf.score, cf.llm.prompt.injection_score)."""

    def test_cf524_waf_score_100_out_of_range(self):
        """cf.waf.score range is 1-99 per CF docs, so 100 should fire."""
        ctx = _lint("cf.waf.score eq 100")
        assert "CF524" in _ids(ctx)

    def test_cf524_waf_score_99_ok(self):
        """cf.waf.score 99 is at the boundary, should not fire."""
        ctx = _lint("cf.waf.score lt 99")
        assert "CF524" not in _ids(ctx)

    def test_cf524_llm_injection_score_100_out_of_range(self):
        """cf.llm.prompt.injection_score range is 1-99 per CF docs."""
        ctx = _lint("cf.llm.prompt.injection_score eq 100")
        assert "CF524" in _ids(ctx)

    def test_cf524_llm_injection_score_50_ok(self):
        ctx = _lint("cf.llm.prompt.injection_score gt 50")
        assert "CF524" not in _ids(ctx)


class TestG013TlsVersion:
    """Tests for CF532 cf.tls_version value domain."""

    def test_cf532_tls_version_invalid(self):
        ctx = _lint('cf.tls_version eq "SSLv3"')
        assert "CF532" in _ids(ctx)

    def test_cf532_tls_version_valid_12(self):
        ctx = _lint('cf.tls_version eq "TLSv1.2"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_tls_version_valid_13(self):
        ctx = _lint('cf.tls_version eq "TLSv1.3"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_tls_version_valid_none(self):
        ctx = _lint('cf.tls_version eq "none"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_tls_version_in_set(self):
        ctx = _lint('cf.tls_version in {"TLSv1.2" "TLSv1.3"}')
        assert "CF532" not in _ids(ctx)


class TestG013HttpHost:
    """Tests for CF532 http.host must not contain /."""

    def test_cf532_host_with_slash(self):
        ctx = _lint('http.host eq "example.com/path"')
        assert "CF532" in _ids(ctx)
        g013 = [r for r in ctx.results if r.rule_id == "CF532"]
        assert "cannot contain '/'" in g013[0].message

    def test_cf532_host_valid(self):
        ctx = _lint('http.host eq "example.com"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_host_with_port_valid(self):
        ctx = _lint('http.host eq "example.com:8080"')
        assert "CF532" not in _ids(ctx)


class TestG013HttpMethod:
    """Tests for CF532 http.request.method valid method set."""

    def test_cf532_method_invalid(self):
        ctx = _lint('http.request.method eq "GETT"')
        assert "CF532" in _ids(ctx)

    def test_cf532_method_get_valid(self):
        ctx = _lint('http.request.method eq "GET"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_method_purge_valid(self):
        ctx = _lint('http.request.method eq "PURGE"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_method_patch_valid(self):
        ctx = _lint('http.request.method eq "PATCH"')
        assert "CF532" not in _ids(ctx)


class TestG013HttpVersion:
    """Tests for CF532 http.request.version exact values."""

    def test_cf532_version_invalid(self):
        ctx = _lint('http.request.version eq "HTTP/0.9"')
        assert "CF532" in _ids(ctx)

    def test_cf532_version_http11_valid(self):
        ctx = _lint('http.request.version eq "HTTP/1.1"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_version_http2_valid(self):
        ctx = _lint('http.request.version eq "HTTP/2"')
        assert "CF532" not in _ids(ctx)

    def test_cf532_version_http3_valid(self):
        ctx = _lint('http.request.version eq "HTTP/3"')
        assert "CF532" not in _ids(ctx)


class TestG023RegexValidation:
    """Tests for CF542 — invalid regex pattern in matches operator."""

    def test_cf542_invalid_regex_unbalanced_parens(self):
        ctx = _lint('http.host matches "(unclosed"')
        g023 = [r for r in ctx.results if r.rule_id == "CF542"]
        assert len(g023) > 0
        assert "unterminated subpattern" in g023[0].message

    def test_cf542_invalid_regex_bad_quantifier(self):
        ctx = _lint('http.host matches "*invalid"')
        g023 = [r for r in ctx.results if r.rule_id == "CF542"]
        assert len(g023) > 0
        assert "Invalid regex" in g023[0].message

    def test_cf542_valid_regex_ok(self):
        ctx = _lint('http.host matches ".*example\\.com$"')
        assert "CF542" not in _ids(ctx)

    def test_cf542_invalid_regex_bad_char_class(self):
        ctx = _lint('http.host matches "[z-a]"')
        g023 = [r for r in ctx.results if r.rule_id == "CF542"]
        assert len(g023) > 0


class TestG024SubstringBounds:
    """Tests for CF543 — substring() bounds validation."""

    def test_cf543_negative_start_allowed(self):
        """CF substring() supports negative indices — no CF543."""
        ctx = _lint('substring(http.request.uri.path, -1, 5) eq "/api"')
        assert "CF543" not in _ids(ctx)

    def test_cf543_end_less_than_start(self):
        ctx = _lint('substring(http.request.uri.path, 10, 5) eq "/api"')
        assert "CF543" in _ids(ctx)
        g024 = [r for r in ctx.results if r.rule_id == "CF543"]
        assert "less than start" in g024[0].message

    def test_cf543_valid_bounds(self):
        ctx = _lint('substring(http.request.uri.path, 0, 4) eq "/api"')
        assert "CF543" not in _ids(ctx)

    def test_cf543_valid_no_end(self):
        ctx = _lint('substring(http.request.uri.path, 5) eq "test"')
        assert "CF543" not in _ids(ctx)


class TestG025LookupJsonPath:
    """Tests for CF544 — lookup_json_* path validation."""

    def test_cf544_invalid_path_no_slash(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "name") eq "test"')
        assert "CF544" in _ids(ctx)
        g025 = [r for r in ctx.results if r.rule_id == "CF544"]
        assert "should start with '/'" in g025[0].message

    def test_cf544_valid_path(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "/name") eq "test"')
        assert "CF544" not in _ids(ctx)

    def test_cf544_lookup_json_integer_invalid(self):
        ctx = _lint('lookup_json_integer(http.request.body.raw, "count") gt 5')
        assert "CF544" in _ids(ctx)

    def test_cf544_lookup_json_integer_valid(self):
        ctx = _lint('lookup_json_integer(http.request.body.raw, "/count") gt 5')
        assert "CF544" not in _ids(ctx)

    def test_cf544_nested_path(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "/data/name") eq "test"')
        assert "CF544" not in _ids(ctx)


class TestG026BitSlice:
    """Tests for CF545 — bit_slice offset/size validation."""

    def test_cf545_valid_bit_slice(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "network_firewall_rules")
        assert "CF545" not in _ids(ctx)

    def test_cf545_offset_too_large(self):
        ctx = _lint(
            "bit_slice(raw.http.request.body.raw, 2048, 16) eq 1234", "network_firewall_rules"
        )
        assert "CF545" in _ids(ctx)
        g026 = [r for r in ctx.results if r.rule_id == "CF545"]
        assert "offset" in g026[0].message

    def test_cf545_size_too_large(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 64) eq 1234", "network_firewall_rules")
        assert "CF545" in _ids(ctx)
        g026 = [r for r in ctx.results if r.rule_id == "CF545"]
        assert "size" in g026[0].message

    def test_cf545_size_zero(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 0) eq 1234", "network_firewall_rules")
        assert "CF545" in _ids(ctx)

    def test_cf545_max_valid_offset_and_size(self):
        ctx = _lint(
            "bit_slice(raw.http.request.body.raw, 2040, 32) eq 1234", "network_firewall_rules"
        )
        assert "CF545" not in _ids(ctx)


class TestE007FunctionSourceMustBeField:
    """Tests for CF306 — function source argument must be a field reference."""

    def test_cf306_decode_base64_with_literal(self):
        ctx = _lint('decode_base64("dGVzdA==") eq "test"')
        assert "CF306" in _ids(ctx)

    def test_cf306_decode_base64_with_field(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"')
        assert "CF306" not in _ids(ctx)

    def test_cf306_url_decode_with_literal(self):
        ctx = _lint('url_decode("hello%20world") eq "hello world"')
        assert "CF306" in _ids(ctx)

    def test_cf306_url_decode_with_field(self):
        ctx = _lint('url_decode(http.request.uri.path) eq "/test"')
        assert "CF306" not in _ids(ctx)

    def test_cf306_starts_with_with_literal(self):
        ctx = _lint('starts_with("hello", "he")')
        assert "CF306" in _ids(ctx)

    def test_cf306_starts_with_with_field(self):
        ctx = _lint('starts_with(http.request.uri.path, "/api")')
        assert "CF306" not in _ids(ctx)

    def test_cf306_ends_with_with_literal(self):
        ctx = _lint('ends_with("hello", "lo")')
        assert "CF306" in _ids(ctx)

    def test_cf306_ends_with_with_field(self):
        ctx = _lint('ends_with(http.request.uri.path, ".js")')
        assert "CF306" not in _ids(ctx)


class TestF003ArrayStarUnpacking:
    """Tests for CF309 — array [*] used on multiple distinct arrays."""

    def test_cf309_single_array_star_ok(self):
        ctx = _lint('any(http.request.headers.names[*] eq "x-api-key")')
        assert "CF309" not in _ids(ctx)

    def test_cf309_same_array_star_ok(self):
        ctx = _lint(
            'any(http.request.headers.names[*] eq "x-api-key")'
            ' and any(http.request.headers.names[*] eq "authorization")'
        )
        assert "CF309" not in _ids(ctx)

    def test_cf309_different_arrays_flagged(self):
        ctx = _lint(
            'any(http.request.headers.names[*] eq "x-api-key")'
            ' and any(http.request.headers.values[*] eq "secret")'
        )
        assert "CF309" in _ids(ctx)

    def test_cf309_no_star_no_flag(self):
        ctx = _lint('http.request.headers.names[0] eq "content-type"')
        assert "CF309" not in _ids(ctx)


class TestFunctionPhaseRestrictions:
    """Tests for function phase restrictions added in coverage audit."""

    def test_cf301_split_in_wrong_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "waf_custom_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_split_in_correct_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "response_header_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_split_in_custom_error_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "custom_error_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_join_in_wrong_phase(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"', "redirect_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_join_in_correct_phase(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"', "url_rewrite_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_cidr_in_wrong_phase(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "redirect_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_cidr_in_correct_phase(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "waf_custom_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_cidr_in_rate_limiting(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "rate_limiting_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_bit_slice_in_wrong_phase(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "waf_custom_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_bit_slice_in_correct_phase(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "network_firewall_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_decode_base64_in_wrong_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "redirect_rules")
        assert "CF301" in _ids(ctx)

    def test_cf301_decode_base64_in_transform_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "request_header_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_decode_base64_in_waf_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "waf_custom_rules")
        assert "CF301" not in _ids(ctx)

    def test_cf301_decode_base64_in_rate_limiting(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "rate_limiting_rules")
        assert "CF301" not in _ids(ctx)


class TestFunctionPlanRestrictions:
    """Tests for CF021 — function plan requirement checks."""

    def test_cf021_sha256_requires_enterprise(self):
        ctx = _lint(
            'sha256(http.request.body.raw) eq "abc"',
            "request_header_rules",
        )
        # Default plan_tier is 'enterprise', so should not fire
        assert "CF021" not in [r.rule_id for r in ctx.results if "sha256" in r.message]

    def test_cf021_sha256_on_free_plan(self):
        rule = {"ref": "test", "expression": 'sha256(http.request.body.raw) eq "abc"'}
        phase = PHASE_BY_NAME["request_header_rules"]
        ctx = LintContext(plan_tier="free")
        lint_expressions(rule, phase, ctx)
        b003 = [r for r in ctx.results if r.rule_id == "CF021" and "sha256" in r.message]
        assert len(b003) == 1
        assert "enterprise" in b003[0].message

    def test_cf021_is_timed_hmac_requires_pro(self):
        expr = 'is_timed_hmac_valid_v0(http.request.uri.path, "secret", 300, 0)'
        rule = {"ref": "test", "expression": expr}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_expressions(rule, phase, ctx)
        b003 = [
            r for r in ctx.results if r.rule_id == "CF021" and "is_timed_hmac_valid_v0" in r.message
        ]
        assert len(b003) == 1
        assert "pro" in b003[0].message

    def test_cf021_is_timed_hmac_on_pro_ok(self):
        expr = 'is_timed_hmac_valid_v0(http.request.uri.path, "secret", 300, 0)'
        rule = {"ref": "test", "expression": expr}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="pro")
        lint_expressions(rule, phase, ctx)
        b003 = [
            r for r in ctx.results if r.rule_id == "CF021" and "is_timed_hmac_valid_v0" in r.message
        ]
        assert len(b003) == 0


class TestA002DepthExceeded:
    def test_cf002_fires_when_depth_exceeded(self, monkeypatch):
        from octorules_cloudflare.linter import ast_linter
        from octorules_cloudflare.linter.expression_bridge import ExpressionInfo

        fake_info = ExpressionInfo(raw="deeply nested", depth_exceeded=True)
        monkeypatch.setattr(ast_linter, "parse_expression", lambda expr, phase=None: fake_info)
        ctx = _lint("deeply nested")
        assert "CF002" in _ids(ctx)

    def test_cf002_not_fired_normal_expression(self, monkeypatch):
        from octorules_cloudflare.linter import ast_linter
        from octorules_cloudflare.linter.expression_bridge import ExpressionInfo

        fake_info = ExpressionInfo(raw="simple", depth_exceeded=False)
        monkeypatch.setattr(ast_linter, "parse_expression", lambda expr, phase=None: fake_info)
        ctx = _lint("simple")
        assert "CF002" not in _ids(ctx)


class TestLargeExpressionStability:
    """Stability tests: very large expressions must not crash or hang."""

    def test_very_large_expression_does_not_crash(self):
        """10KB+ expression is handled gracefully (no crash, no exponential time)."""
        import time

        # Generate a 10KB+ expression: 500 OR clauses
        clauses = [f"ip.src eq 1.2.3.{i % 256}" for i in range(500)]
        expr = " or ".join(clauses)
        assert len(expr) > 10_000, f"Expression too short: {len(expr)} bytes"

        rule = {"ref": "big-rule", "expression": expr}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext()

        start = time.monotonic()
        lint_expressions(rule, phase, ctx)
        elapsed = time.monotonic() - start

        # Must complete in under 5 seconds (generous; typical is < 1s)
        assert elapsed < 5.0, f"lint_expressions took {elapsed:.1f}s on 10KB+ expression"
        # Should produce results (at minimum, the expression was parsed)
        # No crash is the main assertion — the function returned normally


class TestExtractFunctionCallArgs:
    """Unit tests for _extract_function_call_args depth-tracking parser."""

    def test_nested_function_args(self):
        """Nested function calls like split(lower(x), ...) are parsed correctly."""
        result = _extract_function_call_args('split(lower(http.request.uri.path), "/", 2)', "split")
        assert result == [["lower(http.request.uri.path)", '"/"', "2"]]

    def test_parens_in_string_literal(self):
        """Parentheses inside quoted strings are skipped by the depth tracker."""
        result = _extract_function_call_args('split(http.host, "(")', "split")
        assert result == [["http.host", '"("']]

    def test_escaped_quote_in_string_literal(self):
        """Escaped quotes inside strings don't terminate the string early."""
        result = _extract_function_call_args(r'split(http.host, "a\"b")', "split")
        assert result == [["http.host", r'"a\"b"']]

    def test_closing_paren_in_string_literal(self):
        """A ) inside a quoted string does not close the argument list."""
        result = _extract_function_call_args('split(http.host, ")")', "split")
        assert result == [["http.host", '")"']]


# ---------------------------------------------------------------------------
# CF027 — expression-whitespace
# ---------------------------------------------------------------------------


class TestCF027ExpressionWhitespace:
    def test_leading_whitespace_fires(self):
        ctx = _lint(' http.host eq "example.com"')
        cf027 = assert_lint(ctx, "CF027", count=1, severity=Severity.INFO, ref="test")
        assert "whitespace" in cf027[0].message.lower()

    def test_trailing_whitespace_fires(self):
        ctx = _lint('http.host eq "example.com" ')
        assert_lint(ctx, "CF027", count=1, severity=Severity.INFO)

    def test_both_sides_fires_once(self):
        ctx = _lint('  http.host eq "example.com"\t')
        # Single CF027 even when whitespace is on both sides.
        assert_lint(ctx, "CF027", count=1)

    def test_no_whitespace_no_fire(self):
        ctx = _lint('http.host eq "example.com"')
        assert_no_lint(ctx, "CF027")

    def test_whitespace_inside_expression_no_fire(self):
        # Internal whitespace is part of normal syntax — not a CF027 case.
        ctx = _lint('http.host eq "example.com" and ip.src eq 1.2.3.4')
        assert_no_lint(ctx, "CF027")


# ---------------------------------------------------------------------------
# CF516 — operator_style (mixed English / C-like notation)
# ---------------------------------------------------------------------------


class TestCF516OperatorStyle:
    def test_mixed_eq_and_double_equals_fires(self):
        ctx = _lint('http.host eq "a" and ip.src == 1.2.3.4')
        assert_lint(ctx, "CF516", count=1, severity=Severity.INFO, ref="test")

    def test_mixed_and_with_double_amp_fires(self):
        ctx = _lint('http.host eq "a" && ip.src eq 1.2.3.4')
        assert_lint(ctx, "CF516", count=1)

    def test_all_english_no_fire(self):
        ctx = _lint('http.host eq "a" and ip.src eq 1.2.3.4')
        assert_no_lint(ctx, "CF516")

    def test_all_clike_no_fire(self):
        ctx = _lint('http.host == "a" && ip.src == 1.2.3.4')
        assert_no_lint(ctx, "CF516")

    def test_clike_op_inside_string_literal_does_not_fire(self):
        # `==` inside a string literal must NOT be counted as a C-like
        # operator. _strip_literals masks string content first.
        ctx = _lint('http.host eq "a == b"')
        assert_no_lint(ctx, "CF516")


# ---------------------------------------------------------------------------
# CF517 — ambiguous-precedence (mixed and/or without parens)
# ---------------------------------------------------------------------------


class TestCF517AmbiguousPrecedence:
    def test_mixed_and_or_at_top_level_fires(self):
        ctx = _lint('http.host eq "a" and ip.src eq 1.2.3.4 or http.host eq "b"')
        assert_lint(ctx, "CF517", count=1, severity=Severity.INFO, ref="test")

    def test_explicit_parens_no_fire(self):
        ctx = _lint('(http.host eq "a" and ip.src eq 1.2.3.4) or http.host eq "b"')
        assert_no_lint(ctx, "CF517")

    def test_only_and_no_fire(self):
        ctx = _lint('http.host eq "a" and ip.src eq 1.2.3.4')
        assert_no_lint(ctx, "CF517")

    def test_only_or_no_fire(self):
        ctx = _lint('http.host eq "a" or http.host eq "b"')
        assert_no_lint(ctx, "CF517")

    def test_clike_mixed_fires(self):
        # `&&` and `||` mixed at top level — same hazard as `and`/`or`.
        ctx = _lint('http.host == "a" && ip.src == 1.2.3.4 || http.host == "b"')
        assert_lint(ctx, "CF517", count=1)

    def test_and_or_inside_string_literal_does_not_fire(self):
        # The keyword inside the literal must not trip the check.
        ctx = _lint('http.host eq "and-or-inside" and ip.src eq 1.2.3.4')
        assert_no_lint(ctx, "CF517")


# ---------------------------------------------------------------------------
# CF517 — ambiguous-precedence stress cases
#
# Closes coverage gaps identified by the 19-case stress matrix run during
# review. Each case below is a real expression shape a user could write;
# the assertion documents whether CF517 should fire.
# ---------------------------------------------------------------------------


class TestCF517StressCases:
    def test_negation_in_mix_fires(self):
        # `not A and B or C` — `not` doesn't change the and/or hazard.
        ctx = _lint('not http.host eq "a" and ip.src eq 1.2.3.4 or http.host eq "b"')
        assert_lint(ctx, "CF517", count=1)

    def test_negated_paren_then_or_no_fire(self):
        # `not (A and B) or C` — `and` is inside parens, only `or` at depth 0.
        ctx = _lint('not (http.host eq "a" and ip.src eq 1.2.3.4) or http.host eq "b"')
        assert_no_lint(ctx, "CF517")

    def test_clike_only_chain_with_mixed_fires(self):
        # `A && B && C || D` — three-way chain is C-like-only but mixed.
        ctx = _lint(
            'http.host == "a" && ip.src == 1.2.3.4 && http.referer == "x" || http.host == "b"'
        )
        assert_lint(ctx, "CF517", count=1)

    def test_clike_or_then_and_fires(self):
        # `A || B && C` — C-like or-then-and at depth 0.
        ctx = _lint('http.host == "a" || ip.src == 1.2.3.4 && http.host == "b"')
        assert_lint(ctx, "CF517", count=1)

    def test_english_and_clike_or_mixed_fires(self):
        # Mixed English `and` with C-like `||` at depth 0 — both CF516
        # and CF517 fire (different concerns).
        ctx = _lint('http.host eq "a" and ip.src == 1.2.3.4 || http.host eq "b"')
        assert_lint(ctx, "CF517", count=1)

    def test_fully_parenthesized_groups_no_fire(self):
        # `((A and B) or (C and D))` — every and/or is inside parens.
        ctx = _lint(
            '((http.host eq "a" and ip.src eq 1.2.3.4) or (http.host eq "b" and ip.src eq 5.6.7.8))'
        )
        assert_no_lint(ctx, "CF517")

    def test_nested_or_at_depth_zero_only_no_fire(self):
        # `((A or B) and C) or D` — outer paren has and+or, but only `or`
        # appears at the absolute top level (depth 0 after the outer
        # group closes). The check tracks depth strictly.
        ctx = _lint(
            '((http.host eq "a" or http.host eq "b") and ip.src eq 1.2.3.4) or http.host eq "c"'
        )
        # Only `or` at depth 0 → no fire on CF517.
        assert_no_lint(ctx, "CF517")

    def test_xor_combined_with_and_or_fires(self):
        # `A and B xor C or D` — `xor` plus `and`/`or` at depth 0 is
        # even harder to read than two-way mixing; should fire.
        ctx = _lint(
            'http.host eq "a" and ip.src eq 1.2.3.4 xor cf.threat_score gt 10 or http.host eq "b"'
        )
        assert_lint(ctx, "CF517", count=1)

    def test_function_call_parens_isolate_inner_and_or(self):
        # `foo(A and B) or C` — `and` is inside the function-call parens
        # (depth 1), only `or` at depth 0. No mix at top level → no fire.
        ctx = _lint('any(http.request.headers.names[*] eq "x") or http.host eq "a"')
        assert_no_lint(ctx, "CF517")

    def test_function_calls_with_top_level_mix_fires(self):
        # `foo(A) and bar(B) or C` — function calls produce atom-shaped
        # operands, but `and` and `or` are still at depth 0.
        ctx = _lint('len(http.host) gt 5 and len(http.request.uri.path) gt 1 or http.host eq "b"')
        assert_lint(ctx, "CF517", count=1)

    def test_parens_around_atoms_still_fires(self):
        # `(A) and (B) or (C)` — parens are around atoms, not around
        # mixed groups. Both `and` and `or` still at depth 0.
        ctx = _lint('(http.host eq "a") and (ip.src eq 1.2.3.4) or (http.host eq "b")')
        assert_lint(ctx, "CF517", count=1)

    def test_uppercase_keywords_no_fire(self):
        # `A AND B OR C` — wirefilter rejects uppercase at parse time
        # (CF001 fires); CF517 should not fire because the regex is
        # case-sensitive (matches wirefilter's behavior).
        ctx = _lint('http.host eq "a" AND ip.src eq 1.2.3.4 OR http.host eq "b"')
        assert_no_lint(ctx, "CF517")

    def test_empty_and_bare_field_no_fire(self):
        # Single field, no operators at all.
        ctx = _lint("ssl")
        assert_no_lint(ctx, "CF517")


# ---------------------------------------------------------------------------
# CF518 — long-in-list (readability)
# ---------------------------------------------------------------------------


class TestCF518LongInList:
    def test_above_threshold_fires(self):
        # Register 30 entries — comfortably above the 25-entry threshold.
        entries = " ".join(f'"v{i}"' for i in range(30))
        ctx = _lint(f"http.host in {{{entries}}}")
        cf518 = assert_lint(ctx, "CF518", count=1, severity=Severity.INFO)
        assert "30" in cf518[0].message
        assert "25" in cf518[0].message

    def test_at_threshold_no_fire(self):
        # Exactly 25 — boundary case, doesn't fire (the check is `>`, not `>=`).
        entries = " ".join(f'"v{i}"' for i in range(25))
        ctx = _lint(f"http.host in {{{entries}}}")
        assert_no_lint(ctx, "CF518")

    def test_one_above_threshold_fires(self):
        # 26 entries — first value above the threshold; off-by-one guard.
        entries = " ".join(f'"v{i}"' for i in range(26))
        ctx = _lint(f"http.host in {{{entries}}}")
        assert_lint(ctx, "CF518", count=1)

    def test_short_list_no_fire(self):
        ctx = _lint('http.host in {"a" "b" "c"}')
        assert_no_lint(ctx, "CF518")


# ---------------------------------------------------------------------------
# CF546 — suspicious_regex (unescaped `.` on dotted-context fields)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not WIREFILTER_AVAILABLE,
    reason="CF546 needs regex_field_pairs from wirefilter",
)
class TestCF546SuspiciousRegex:
    def test_unescaped_dot_in_hostname_regex_fires(self):
        ctx = _lint(r'http.host matches "api.example.com"')
        cf546 = assert_lint(ctx, "CF546", count=1, severity=Severity.WARNING)
        assert "unescaped" in cf546[0].message.lower() or "." in cf546[0].message

    def test_escaped_dot_no_fire(self):
        ctx = _lint(r'http.host matches "api\.example\.com"')
        assert_no_lint(ctx, "CF546")

    def test_dot_inside_character_class_no_fire(self):
        # `.` inside `[...]` is a literal dot already — no false positive.
        ctx = _lint(r'http.host matches "[a-z.]+"')
        assert_no_lint(ctx, "CF546")

    def test_path_field_unescaped_dot_fires(self):
        ctx = _lint(r'http.request.uri.path matches "/foo.bar/"')
        assert_lint(ctx, "CF546", count=1)

    def test_function_call_lhs_no_fire(self):
        # `lower(http.host)` — function-call LHS, no field-regex pair
        # recorded; CF546 should not fire (no false positives on
        # transformed LHS).
        ctx = _lint(r'lower(http.host) matches "api.example.com"')
        assert_no_lint(ctx, "CF546")

    def test_non_dotted_context_field_no_fire(self):
        # CF546 only fires on hostname/path-style fields. A regex on
        # cf.bot_management.ja3_hash is unrelated.
        ctx = _lint(r'cf.bot_management.ja3_hash matches "abc.def"')
        assert_no_lint(ctx, "CF546")

    def test_intentional_wildcard_dot_star_no_fire(self):
        # `.*` is an intentional any-char wildcard, not a typo for `\.`.
        # The heuristic skips `.` followed by `*`, `+`, `?`, or `{`.
        ctx = _lint(r'http.host matches ".*"')
        assert_no_lint(ctx, "CF546")

    def test_wildcard_with_unescaped_literal_dot_fires(self):
        # `.*example.com` — leading `.*` is a wildcard (skipped), but
        # `example.com` has a bare literal-context dot that's almost
        # certainly meant to be `\.`.
        ctx = _lint(r'http.host matches ".*example.com"')
        assert_lint(ctx, "CF546", count=1)

    def test_dot_followed_by_plus_no_fire(self):
        # `.+` is the same as `.*` — quantifier-following dots are
        # intentional any-char + repetition.
        ctx = _lint(r'http.host matches ".+\.example\.com"')
        assert_no_lint(ctx, "CF546")

    def test_dot_followed_by_brace_quantifier_no_fire(self):
        # `.{3}` — bounded any-char repetition. Intentional.
        ctx = _lint(r'http.host matches "x.{3}\.example\.com"')
        assert_no_lint(ctx, "CF546")

    def test_upstream_zone_field_in_dotted_context(self):
        # cf.worker.upstream_zone is a hostname; treated as dotted-context
        # alongside http.host etc.
        ctx = _lint(r'cf.worker.upstream_zone matches "tenant.example.com"')
        assert_lint(ctx, "CF546", count=1)

    def test_cert_subject_dn_unescaped_dot_fires(self):
        # X.509 Distinguished Name: the CN= portion contains hostname-style
        # content. `CN=api.example.com` has 2 unescaped dots that are
        # wildcards by accident — same bug shape as a bare hostname regex.
        ctx = _lint(r'cf.tls_client_auth.cert_subject_dn matches "CN=api.example.com"')
        assert_lint(ctx, "CF546", count=1, severity=Severity.WARNING)

    def test_cert_subject_dn_escaped_no_fire(self):
        # Properly-escaped DN regex — no false positive.
        ctx = _lint(r'cf.tls_client_auth.cert_subject_dn matches "CN=api\.example\.com,"')
        assert_no_lint(ctx, "CF546")

    def test_cert_subject_dn_wildcard_subdomain_no_fire(self):
        # `.*\.example\.com,` — `.*` is a quantifier-followed wildcard
        # (skipped by heuristic); the `\.` are escaped.
        ctx = _lint(r'cf.tls_client_auth.cert_subject_dn matches "CN=.*\.example\.com,"')
        assert_no_lint(ctx, "CF546")

    def test_cert_issuer_dn_unescaped_dot_fires(self):
        # Same logic for issuer DN — both subject and issuer are
        # in _DOTTED_CONTEXT_FIELDS.
        ctx = _lint(r'cf.tls_client_auth.cert_issuer_dn matches "O=Acme,CN=ca.acme.com"')
        assert_lint(ctx, "CF546", count=1)

    def test_cert_subject_dn_oid_escaping_required(self):
        # OIDs like `1.2.840.113549` need escaping just like hostnames —
        # bare dots match any char. Lint correctly fires on bare form.
        ctx = _lint(r'cf.tls_client_auth.cert_subject_dn matches "1.2.840.113549"')
        assert_lint(ctx, "CF546", count=1)
        # And with proper escaping, no fire.
        ctx2 = _lint(r'cf.tls_client_auth.cert_subject_dn matches "1\.2\.840\.113549"')
        assert_no_lint(ctx2, "CF546")

    def test_cert_dn_legacy_and_rfc2253_variants_fire(self):
        # All 3 forms of subject DN and 3 of issuer DN are in scope.
        for field in [
            "cf.tls_client_auth.cert_subject_dn",
            "cf.tls_client_auth.cert_subject_dn_legacy",
            "cf.tls_client_auth.cert_subject_dn_rfc2253",
            "cf.tls_client_auth.cert_issuer_dn",
            "cf.tls_client_auth.cert_issuer_dn_legacy",
            "cf.tls_client_auth.cert_issuer_dn_rfc2253",
        ]:
            ctx = _lint(rf'{field} matches "CN=foo.bar.com"')
            cf546 = [r for r in ctx.results if r.rule_id == "CF546"]
            assert len(cf546) == 1, f"{field}: expected CF546 to fire, got {ctx.results}"

    def test_cert_dn_no_dot_no_fire(self):
        # No `.` in the regex — no fire even on a DN field.
        ctx = _lint(r'cf.tls_client_auth.cert_subject_dn matches "O=Acme Corp"')
        assert_no_lint(ctx, "CF546")

    # ── Unescaped `?` in URI-context fields ────────────────────

    def test_unescaped_question_in_uri_fires(self):
        # `/foo?bar=1` — `o?` is a regex quantifier ("zero or one o");
        # almost certainly the user meant the literal `?` query separator.
        ctx = _lint(r'http.request.uri matches "/foo?bar=1"')
        cf546 = assert_lint(ctx, "CF546", count=1, severity=Severity.WARNING)
        assert "?" in cf546[0].message or "query separator" in cf546[0].message.lower()

    def test_escaped_question_in_uri_no_fire(self):
        # Properly escaped — no fire.
        ctx = _lint(r'http.request.uri matches "/foo\?bar=1"')
        assert_no_lint(ctx, "CF546")

    def test_https_optional_protocol_no_fire(self):
        # `https?` is the documented exception — `s?` is intentional
        # protocol-letter optionality, not a literal `?`.
        ctx = _lint(r'http.request.uri matches "https?://example\.com/foo"')
        assert_no_lint(ctx, "CF546")

    def test_question_in_regex_quantifier_context_no_fire(self):
        # `?` after `*`, `+`, `)`, `]` are regex quantifier contexts.
        for pattern in [
            r"foo*?",  # lazy quantifier
            r"foo+?",  # lazy quantifier
            r"(foo)?",  # optional group
            r"[abc]?",  # optional class
            r"(?i)foo",  # regex flag
        ]:
            ctx = _lint(rf'http.request.uri matches "{pattern}"')
            assert_no_lint(ctx, "CF546")

    def test_question_check_only_for_uri_context_fields(self):
        # `?` check should NOT fire on plain hostname fields — `?` in a
        # hostname regex is unusual but not the same kind of typo as in
        # a URI. Scope is intentionally narrow.
        ctx = _lint(r'http.host matches "foo?bar"')
        # No dot in the regex, so the dot check doesn't fire either.
        assert_no_lint(ctx, "CF546")

    # ── Glob `/*/` on path fields ──────────────────────────────

    def test_slash_star_slash_in_path_fires(self):
        # `/foo/*/bar` — user wrote a glob (intended to match any
        # segment) but `o*/` means "zero or more `o`s followed by /".
        ctx = _lint(r'http.request.uri.path matches "/foo/*/bar"')
        cf546 = assert_lint(ctx, "CF546", count=1, severity=Severity.WARNING)
        assert "wildcard" in cf546[0].message.lower() or "*" in cf546[0].message

    def test_trailing_slash_star_in_path_fires(self):
        # `/foo/*` at end — same shape, glob intent.
        ctx = _lint(r'http.request.uri.path matches "/foo/*"')
        assert_lint(ctx, "CF546", count=1)

    def test_star_after_letter_in_path_no_fire(self):
        # `/foo*/bar` — `*` after letter is a normal regex quantifier;
        # no glob confusion. Glob check shouldn't fire.
        ctx = _lint(r'http.request.uri.path matches "/foo*/bar"')
        cf546_glob = [
            r for r in ctx.results if r.rule_id == "CF546" and "wildcard" in r.message.lower()
        ]
        assert cf546_glob == []

    def test_glob_check_only_for_path_fields(self):
        # `/foo/*/bar` on http.host shouldn't fire the glob check
        # (paths have a glob-vs-regex confusion; hostnames don't).
        ctx = _lint(r'http.host matches "/foo/*/bar"')
        cf546_glob = [
            r for r in ctx.results if r.rule_id == "CF546" and "wildcard" in r.message.lower()
        ]
        assert cf546_glob == []

    def test_glob_check_takes_priority_over_dot_check(self):
        # When both glob AND dot would fire, the glob message wins
        # (more specific). Pattern with both: `/foo/*/api.example.com`.
        ctx = _lint(r'http.request.uri.path matches "/foo/*/api.example.com"')
        cf546 = assert_lint(ctx, "CF546", count=1)
        # Message should be about glob, not about dots.
        assert "wildcard" in cf546[0].message.lower() or "*" in cf546[0].message


# ---------------------------------------------------------------------------
# CF547 — empty-in-list (`field in {}` always false)
# ---------------------------------------------------------------------------


class TestCF547EmptyInList:
    def test_empty_in_set_fires(self):
        ctx = _lint("ip.src in {}")
        cf547 = assert_lint(ctx, "CF547", count=1, severity=Severity.WARNING)
        assert "empty" in cf547[0].message.lower() or "always" in cf547[0].message.lower()

    def test_empty_in_set_with_whitespace_fires(self):
        ctx = _lint("ip.src in {  }")
        assert_lint(ctx, "CF547", count=1)

    def test_non_empty_in_set_no_fire(self):
        ctx = _lint('http.host in {"a" "b"}')
        assert_no_lint(ctx, "CF547")

    def test_empty_braces_inside_string_literal_no_fire(self):
        # `in {}` inside a string literal must not fire.
        ctx = _lint('http.host eq "in {}"')
        assert_no_lint(ctx, "CF547")


# ---------------------------------------------------------------------------
# CF548 — overly-permissive regex (matches every value)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not WIREFILTER_AVAILABLE,
    reason="CF548 needs regex_field_pairs from wirefilter",
)
class TestCF548OverlyPermissiveRegex:
    def test_dot_alone_fires(self):
        ctx = _lint(r'http.host matches "."')
        cf548 = assert_lint(ctx, "CF548", count=1, severity=Severity.WARNING)
        msg = cf548[0].message.lower()
        assert "every value" in msg or "no condition" in msg

    def test_dot_star_fires(self):
        ctx = _lint(r'http.host matches ".*"')
        assert_lint(ctx, "CF548", count=1)

    def test_dot_plus_fires(self):
        ctx = _lint(r'http.host matches ".+"')
        assert_lint(ctx, "CF548", count=1)

    def test_anchored_dot_star_fires(self):
        ctx = _lint(r'http.host matches "^.*$"')
        assert_lint(ctx, "CF548", count=1)

    def test_caret_alone_fires(self):
        # `^` anchors to start but matches empty string — always-match.
        ctx = _lint(r'http.host matches "^"')
        assert_lint(ctx, "CF548", count=1)

    def test_dollar_alone_fires(self):
        ctx = _lint(r'http.host matches "$"')
        assert_lint(ctx, "CF548", count=1)

    def test_alternation_with_empty_fires(self):
        # `|` matches empty on either side — always-match.
        ctx = _lint(r'http.host matches "|"')
        assert_lint(ctx, "CF548", count=1)

    def test_path_only_overly_permissive(self):
        # `/` and `^/` always match for path fields (paths start with /).
        ctx = _lint(r'http.request.uri.path matches "/"')
        assert_lint(ctx, "CF548", count=1)
        ctx = _lint(r'http.request.uri.path matches "/.*"')
        assert_lint(ctx, "CF548", count=1)

    def test_path_only_overly_permissive_does_not_fire_for_other_fields(self):
        # `/` is not always-match for http.host — could fail on hosts
        # that don't contain `/`. Check that the path-specific rule
        # doesn't leak to non-path fields.
        ctx = _lint(r'http.host matches "/"')
        assert_no_lint(ctx, "CF548")

    def test_specific_pattern_no_fire(self):
        # A non-trivial pattern doesn't fire.
        ctx = _lint(r'http.host matches "^api\.example\.com$"')
        assert_no_lint(ctx, "CF548")

    def test_literal_dot_no_fire(self):
        # `\.` is escaped — not always-match.
        ctx = _lint(r'http.host matches "\."')
        assert_no_lint(ctx, "CF548")


# ---------------------------------------------------------------------------
# CF549 — unnecessary-regex (simplifies to eq)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not WIREFILTER_AVAILABLE,
    reason="CF549 needs regex_field_pairs from wirefilter",
)
class TestCF549UnnecessaryRegex:
    def test_anchored_literal_fires_with_eq_suggestion(self):
        ctx = _lint(r'http.host matches "^example$"')
        cf549 = assert_lint(ctx, "CF549", count=1, severity=Severity.INFO)
        assert "eq" in cf549[0].suggestion
        assert "example" in cf549[0].suggestion

    def test_anchored_literal_with_escaped_dot_fires(self):
        # `^api\.example\.com$` simplifies to `eq "api.example.com"`.
        ctx = _lint(r'http.host matches "^api\.example\.com$"')
        cf549 = assert_lint(ctx, "CF549", count=1)
        # Suggestion should unescape the dots back to literal form.
        assert "api.example.com" in cf549[0].suggestion

    def test_anchored_literal_with_path_chars(self):
        # Slashes and hyphens are literal-friendly in URI paths.
        ctx = _lint(r'http.request.uri.path matches "^/api/v1/health$"')
        cf549 = assert_lint(ctx, "CF549", count=1)
        assert "/api/v1/health" in cf549[0].suggestion

    def test_partial_anchor_no_fire(self):
        # Only one anchor — not a full-match-literal case.
        ctx = _lint(r'http.host matches "^example"')
        assert_no_lint(ctx, "CF549")
        ctx = _lint(r'http.host matches "example$"')
        assert_no_lint(ctx, "CF549")

    def test_no_anchors_no_fire(self):
        ctx = _lint(r'http.host matches "example"')
        assert_no_lint(ctx, "CF549")

    def test_alternation_no_fire(self):
        # `^(foo|bar)$` is not a single literal — don't fire.
        # (Could be its own simplification rule for `in {…}` but that's
        # a separate diagnostic; CF549 is scoped to single-literal case.)
        ctx = _lint(r'http.host matches "^(foo|bar)$"')
        assert_no_lint(ctx, "CF549")

    def test_character_class_no_fire(self):
        # `^[abc]$` has a character class — not a literal.
        ctx = _lint(r'http.host matches "^[abc]$"')
        assert_no_lint(ctx, "CF549")

    def test_quantifier_no_fire(self):
        # `^foo+$` has a quantifier — not a literal.
        ctx = _lint(r'http.host matches "^foo+$"')
        assert_no_lint(ctx, "CF549")

    def test_function_call_lhs_no_fire(self):
        # No regex_field_pair recorded for function-call LHS.
        ctx = _lint(r'lower(http.host) matches "^example$"')
        assert_no_lint(ctx, "CF549")


# ---------------------------------------------------------------------------
# CF550 — percent-encoded literal on decoded URI field
# ---------------------------------------------------------------------------


class TestCF550PercentEncodedLiteral:
    def test_percent_encoded_slash_on_path_fires(self):
        # Literal with %2F (encoded /) on http.request.uri.path fires.
        ctx = _lint('http.request.uri.path eq "/api%2Fv1"')
        cf550 = assert_lint(ctx, "CF550", count=1, severity=Severity.WARNING)
        assert "%2F" in cf550[0].message or "percent-encoded" in cf550[0].message.lower()

    def test_percent_encoded_dot_on_host_fires(self):
        # Literal with %2E (encoded .) on http.host fires.
        ctx = _lint('http.host eq "example%2Ecom"')
        assert_lint(ctx, "CF550", count=1)

    def test_percent_encoded_question_on_uri_fires(self):
        # Literal with %3F (encoded ?) on http.request.uri fires.
        ctx = _lint('http.request.uri eq "/api%3Fv=1"')
        assert_lint(ctx, "CF550", count=1)

    def test_percent_encoded_on_referer_fires(self):
        # Literal with %2F on http.referer fires.
        ctx = _lint('http.referer eq "https://example.com%2Fadmin"')
        assert_lint(ctx, "CF550", count=1)

    def test_percent_encoded_on_full_uri_fires(self):
        # Literal with %20 (space) on http.request.full_uri fires.
        ctx = _lint('http.request.full_uri eq "https://example.com/path%20with%20space"')
        assert_lint(ctx, "CF550", count=1)

    def test_raw_uri_field_no_fire(self):
        # Percent-encoded literal on raw.http.request.uri.path does NOT fire
        # (encoding is correct for raw fields).
        ctx = _lint('raw.http.request.uri.path eq "/api%2Fv1"')
        assert_no_lint(ctx, "CF550")

    def test_regex_operator_no_fire(self):
        # Percent-encoded sequence in a regex pattern does NOT fire
        # (%XX may be intentional in regex bodies).
        ctx = _lint('http.request.uri.path matches "/api%2Fv1"')
        assert_no_lint(ctx, "CF550")

    def test_no_percent_encoding_no_fire(self):
        # Literal on decoded URI field without percent-encoding does NOT fire.
        ctx = _lint('http.request.uri.path eq "/api/v1"')
        assert_no_lint(ctx, "CF550")

    def test_lowercase_percent_encoding_fires(self):
        # Mixed-case percent-encoding (%2f lowercase) still fires.
        ctx = _lint('http.request.uri.path eq "/api%2f"')
        assert_lint(ctx, "CF550", count=1)

    def test_invalid_percent_sequence_no_fire(self):
        # Percent not followed by 2 hex digits (e.g., `100%pure`) does NOT fire.
        ctx = _lint('http.host eq "100%pure"')
        assert_no_lint(ctx, "CF550")

    def test_in_operator_with_percent_encoded_fires(self):
        # The 'in' operator with a set containing percent-encoded values fires.
        ctx = _lint('http.request.uri.path in {"/a%2F" "/b"}')
        assert_lint(ctx, "CF550", count=1)

    def test_ne_operator_with_percent_encoded_fires(self):
        # The 'ne' operator also counts as a literal-comparison operator.
        ctx = _lint('http.request.uri.path ne "/api%2Fv1"')
        assert_lint(ctx, "CF550", count=1)

    def test_contains_operator_with_percent_encoded_fires(self):
        # The 'contains' operator with percent-encoded value fires.
        ctx = _lint('http.request.uri.path contains "%2Fadmin"')
        assert_lint(ctx, "CF550", count=1)

    def test_starts_with_operator_with_percent_encoded_fires(self):
        # The 'starts_with' operator with percent-encoded value fires.
        ctx = _lint('http.request.uri.path starts_with "/api%2F"')
        assert_lint(ctx, "CF550", count=1)

    def test_ends_with_operator_with_percent_encoded_fires(self):
        # The 'ends_with' operator with percent-encoded value fires.
        ctx = _lint('http.request.uri.path ends_with "%2Fadmin"')
        assert_lint(ctx, "CF550", count=1)

    def test_non_uri_field_no_fire(self):
        # Percent-encoded literal on a non-URI field does NOT fire
        # (the rule only targets decoded URI fields).
        ctx = _lint('http.request.method eq "GET%20POST"')
        assert_no_lint(ctx, "CF550")

    def test_mixed_expression_with_decoded_uri_fires(self):
        # If the expression uses a decoded URI field (even mixed with others),
        # and has a percent-encoded literal, it fires.
        ctx = _lint('(http.request.method eq "GET") and (http.request.uri.path eq "/api%2Fv1")')
        assert_lint(ctx, "CF550", count=1)


# ---------------------------------------------------------------------------
# Test Rule Overlap — Multiple rules fire independently on same input
# ---------------------------------------------------------------------------
class TestRuleOverlap:
    """Document intentional double-firing behavior for known overlap pairs.

    Lint rules fire independently — when two rules catch different concerns
    on the same input, both should fire to give richer signal to the user.
    """

    def test_cf548_cf549_overlap_permissive_vs_literal(self):
        """CF548 ∩ CF549: Document current behavior for overlap.

        CF548: Overly-permissive regex patterns (^.+$, ^.*$, etc.)
        CF549: Fully-anchored literals (^foo$, ^/bar$, etc.)

        A pattern like ^.+$ is permissive (CF548) but NOT a literal (not CF549).
        A pattern like ^foo$ is a literal (CF549) but NOT permissive (not CF548).

        Currently, they do NOT overlap because the permissive set excludes
        literals, and the fully-anchored literal check excludes quantifiers.
        This test documents that behavior.
        """
        # Permissive pattern: ^.+$ matches CF548 only
        ctx1 = _lint('http.host matches "^.+$"')
        rule_ids1 = {r.rule_id for r in ctx1.results}
        assert "CF548" in rule_ids1, f"CF548 not found for ^.+$; got {rule_ids1}"
        assert "CF549" not in rule_ids1, f"CF549 should NOT fire for ^.+$; got {rule_ids1}"

        # Anchored literal pattern: ^foo$ matches CF549 only
        ctx2 = _lint('http.host matches "^foo$"')
        rule_ids2 = {r.rule_id for r in ctx2.results}
        assert "CF548" not in rule_ids2, f"CF548 should NOT fire for ^foo$; got {rule_ids2}"
        assert "CF549" in rule_ids2, f"CF549 not found for ^foo$; got {rule_ids2}"
