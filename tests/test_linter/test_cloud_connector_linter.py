"""Tests for the Cloud Connector rule linter - Category U rules + expression analysis."""

from octorules.linter.engine import LintContext
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_cloudflare.linter.cloud_connector_linter import lint_cloud_connector_rules

SECTION = "cloudflare.cloud_connector_rules"


def _valid_rule(**overrides):
    """Return a valid cloud_connector_rules entry with optional overrides."""
    base = {
        "description": "Serve assets from R2",
        "expression": 'starts_with(http.request.uri.path, "/assets/")',
        "provider": "cloudflare_r2",
        "parameters": {"host": "assets.account-a.r2.cloudflarestorage.com"},
    }
    base.update(overrides)
    return base


def _lint(rules, **ctx_kwargs):
    """Lint a cloud_connector_rules list and return the context."""
    ctx = LintContext(**ctx_kwargs)
    lint_cloud_connector_rules({SECTION: rules}, ctx)
    return ctx


class TestCleanRules:
    def test_valid_rule_produces_no_findings(self):
        ctx = _lint([_valid_rule()])
        assert ctx.results == []

    def test_no_section_produces_no_findings(self):
        ctx = LintContext()
        lint_cloud_connector_rules({}, ctx)
        assert ctx.results == []

    def test_non_list_section_produces_no_findings(self):
        ctx = LintContext()
        lint_cloud_connector_rules({SECTION: {"description": "x"}}, ctx)
        assert ctx.results == []

    def test_phase_filter_excluding_the_section_skips_it(self):
        rule = _valid_rule()
        del rule["description"]
        ctx = _lint([rule], phase_filter={"cloudflare.waf_custom_rules"})
        assert ctx.results == []


class TestU001MissingFields:
    def test_missing_description(self):
        rule = _valid_rule()
        del rule["description"]
        ctx = _lint([rule])
        assert_lint(ctx, "CF490")
        assert any("description" in r.message for r in ctx.results if r.rule_id == "CF490")

    def test_missing_expression(self):
        rule = _valid_rule()
        del rule["expression"]
        ctx = _lint([rule])
        assert_lint(ctx, "CF490")

    def test_missing_provider(self):
        rule = _valid_rule()
        del rule["provider"]
        ctx = _lint([rule])
        assert_lint(ctx, "CF490")


class TestU002InvalidProvider:
    def test_unknown_provider(self):
        ctx = _lint([_valid_rule(provider="digitalocean")])
        assert_lint(ctx, "CF491")

    def test_every_documented_provider_is_accepted(self):
        for provider in ("aws_s3", "cloudflare_r2", "gcp_storage", "azure_storage"):
            ctx = _lint([_valid_rule(provider=provider)])
            assert_no_lint(ctx, "CF491")


class TestU003InvalidTypes:
    def test_non_mapping_rule(self):
        ctx = _lint(["not a rule"])
        assert_lint(ctx, "CF492")

    def test_non_string_description(self):
        ctx = _lint([_valid_rule(description=123)])
        assert_lint(ctx, "CF492")

    def test_non_bool_enabled(self):
        ctx = _lint([_valid_rule(enabled="yes")])
        assert_lint(ctx, "CF492")

    def test_non_mapping_parameters(self):
        ctx = _lint([_valid_rule(parameters="host")])
        assert_lint(ctx, "CF492")

    def test_empty_host(self):
        ctx = _lint([_valid_rule(parameters={"host": ""})])
        assert_lint(ctx, "CF492")


class TestU004DuplicateDescription:
    def test_duplicate_description_warns(self):
        ctx = _lint([_valid_rule(), _valid_rule(expression="http.host eq 'a'")])
        assert_lint(ctx, "CF493")

    def test_distinct_descriptions_pass(self):
        ctx = _lint(
            [_valid_rule(), _valid_rule(description="other", expression="http.host eq 'a'")]
        )
        assert_no_lint(ctx, "CF493")


class TestU005UnknownFields:
    def test_unknown_field(self):
        ctx = _lint([_valid_rule(action="route")])
        assert_lint(ctx, "CF494")

    def test_ref_gets_the_identity_hint(self):
        ctx = _lint([_valid_rule(ref="assets")])
        assert_lint(ctx, "CF494")
        assert any(
            "identified by description" in r.message for r in ctx.results if r.rule_id == "CF494"
        )

    def test_unknown_parameters_key(self):
        ctx = _lint([_valid_rule(parameters={"host": "a.example", "bucket": "b"})])
        assert_lint(ctx, "CF494")


class TestU006DuplicateExpression:
    def test_two_enabled_rules_with_the_same_expression_warn(self):
        ctx = _lint([_valid_rule(), _valid_rule(description="copy")])
        assert_lint(ctx, "CF495")

    def test_whitespace_variants_are_the_same_expression(self):
        first = _valid_rule()
        second = _valid_rule(
            description="copy",
            expression='starts_with(http.request.uri.path,   "/assets/")',
        )
        ctx = _lint([first, second])
        assert_lint(ctx, "CF495")

    def test_disabled_side_does_not_warn(self):
        """Same expression with one side disabled is a staged swap, not a bug."""
        ctx = _lint([_valid_rule(enabled=False), _valid_rule(description="copy")])
        assert_no_lint(ctx, "CF495")

    def test_distinct_expressions_pass(self):
        ctx = _lint(
            [_valid_rule(), _valid_rule(description="other", expression="http.host eq 'a'")]
        )
        assert_no_lint(ctx, "CF495")


class TestCatchAllExpressions:
    def test_always_true_expression_fires_cf015(self):
        ctx = _lint([_valid_rule(expression="true")])
        assert_lint(ctx, "CF015")

    def test_always_false_expression_fires_cf016(self):
        ctx = _lint([_valid_rule(expression="false")])
        assert_lint(ctx, "CF016")


class TestExpressionDelegation:
    def test_response_field_fires_cf019(self):
        ctx = _lint([_valid_rule(expression="http.response.code eq 200")])
        assert_lint(ctx, "CF019")

    def test_findings_carry_the_description_as_ref(self):
        ctx = _lint([_valid_rule(expression="http.response.code eq 200")])
        finding = next(r for r in ctx.results if r.rule_id == "CF019")
        assert finding.ref == "Serve assets from R2"
