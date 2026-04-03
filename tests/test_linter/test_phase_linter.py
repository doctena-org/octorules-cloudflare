"""Tests for phase linter (Category B)."""

from octorules.linter.engine import LintContext
from octorules.phases import PHASE_BY_NAME

from octorules_cloudflare.linter.phase_linter import lint_phase_restrictions


def _lint(expression, phase_name):
    rule = {"ref": "test", "expression": expression}
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_phase_restrictions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestResponseFieldInRequestPhase:
    def test_cf019_response_field_in_redirect(self):
        ctx = _lint("http.response.code eq 200", "redirect_rules")
        assert "CF019" in _ids(ctx)

    def test_cf019_response_field_in_waf(self):
        ctx = _lint("http.response.code eq 200", "waf_custom_rules")
        assert "CF019" in _ids(ctx)

    def test_cf019_response_field_in_response_phase_ok(self):
        ctx = _lint("http.response.code eq 200", "response_header_rules")
        assert "CF019" not in _ids(ctx)

    def test_cf019_request_field_in_request_phase_ok(self):
        ctx = _lint('http.host eq "example.com"', "redirect_rules")
        assert "CF019" not in _ids(ctx)


class TestBodyFieldRestriction:
    def test_cf020_body_field_in_redirect(self):
        ctx = _lint("http.request.body.size gt 0", "redirect_rules")
        assert "CF020" in _ids(ctx)

    def test_cf020_body_field_in_waf_ok(self):
        ctx = _lint("http.request.body.size gt 0", "waf_custom_rules")
        assert "CF020" not in _ids(ctx)

    def test_cf020_body_field_in_rate_limit_ok(self):
        ctx = _lint("http.request.body.size gt 0", "rate_limiting_rules")
        assert "CF020" not in _ids(ctx)


class TestPlanGatedField:
    def test_cf021_enterprise_field_on_free(self):
        rule = {"ref": "test", "expression": "cf.bot_management.score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "CF021" in ids

    def test_cf021_enterprise_field_on_enterprise_ok(self):
        rule = {"ref": "test", "expression": "cf.bot_management.score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="enterprise")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "CF021" not in ids

    def test_cf021_not_triggered_for_all_plan_field(self):
        rule = {"ref": "test", "expression": "cf.threat_score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "CF021" not in ids


class TestNoExpression:
    def test_no_crash_on_missing_expression(self):
        rule = {"ref": "test"}
        phase = PHASE_BY_NAME["redirect_rules"]
        ctx = LintContext()
        lint_phase_restrictions(rule, phase, ctx)
        assert len(ctx.results) == 0
