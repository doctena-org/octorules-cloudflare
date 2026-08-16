"""Cloud Connector rule linter -- Category U rules + expression analysis.

Validates cloud_connector_rules entries for structural correctness
(CF490-CF495), catch-all expressions (CF015/CF016), and delegates
expression-level analysis (E, F, G, O) to the AST linter.
"""

from typing import Any

from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    check_catch_all,
)
from octorules.phases import Phase

RULE_IDS = frozenset({"CF015", "CF016", "CF490", "CF491", "CF492", "CF493", "CF494", "CF495"})

_SECTION = "cloudflare.cloud_connector_rules"

# Synthetic phase for expression analysis. Cloud Connector matches on
# request-phase fields with the default HTTP scheme.
_CC_PHASE = Phase(_SECTION, "cloud_connector", None)

_REQUIRED_FIELDS = ("description", "expression", "provider")
_KNOWN_FIELDS = frozenset({"description", "enabled", "expression", "parameters", "provider"})
_KNOWN_PARAMETERS = frozenset({"host"})

# Cloud Provider type -- a closed enum in the Cloudflare API schema.
_VALID_PROVIDERS = frozenset({"aws_s3", "cloudflare_r2", "gcp_storage", "azure_storage"})


def lint_cloud_connector_rules(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Cloud Connector rule checks on the rules data."""
    rules = rules_data.get(_SECTION)
    if not isinstance(rules, list):
        return

    if ctx.phase_filter and _SECTION not in ctx.phase_filter:
        return

    seen_descriptions: set[str] = set()
    seen_expressions: dict[str, str] = {}
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            ctx.add(
                LintResult(
                    rule_id="CF492",
                    severity=Severity.ERROR,
                    message=f"Rule at index {i} must be a mapping, got {type(rule).__name__}",
                    phase=_SECTION,
                )
            )
            continue
        ctx.set_location(rule)

        desc = rule.get("description", "")
        desc_label = desc if isinstance(desc, str) and desc else f"index {i}"

        _check_rule_structure(rule, desc_label, seen_descriptions, seen_expressions, ctx)
        _check_rule_expressions(rule, desc_label, ctx)

        if isinstance(desc, str) and desc:
            seen_descriptions.add(desc)


def _check_rule_structure(
    rule: dict[str, Any],
    desc_label: str,
    seen_descriptions: set[str],
    seen_expressions: dict[str, str],
    ctx: LintContext,
) -> None:
    """Check structural correctness of a single rule (CF490-CF495, CF015/CF016)."""
    # CF490: Missing required fields
    for field_name in _REQUIRED_FIELDS:
        if field_name not in rule:
            ctx.add(
                LintResult(
                    rule_id="CF490",
                    severity=Severity.ERROR,
                    message=f"Rule is missing required {field_name!r} field",
                    phase=_SECTION,
                    ref=desc_label,
                )
            )

    # CF491: Invalid provider
    provider = rule.get("provider")
    if provider is not None and provider not in _VALID_PROVIDERS:
        ctx.add(
            LintResult(
                rule_id="CF491",
                severity=Severity.ERROR,
                message=(
                    f"Invalid provider {provider!r} -- must be one of"
                    f" {', '.join(sorted(_VALID_PROVIDERS))}"
                ),
                phase=_SECTION,
                ref=desc_label,
                field="provider",
            )
        )

    # CF492: Invalid field types
    for field_name in ("description", "expression"):
        value = rule.get(field_name)
        if value is not None and (not isinstance(value, str) or not value):
            ctx.add(
                LintResult(
                    rule_id="CF492",
                    severity=Severity.ERROR,
                    message=(
                        f"{field_name!r} must be a non-empty string,"
                        f" got {type(value).__name__} ({value!r})"
                    ),
                    phase=_SECTION,
                    ref=desc_label,
                    field=field_name,
                )
            )

    enabled = rule.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        ctx.add(
            LintResult(
                rule_id="CF492",
                severity=Severity.ERROR,
                message=f"'enabled' must be a boolean, got {type(enabled).__name__} ({enabled!r})",
                phase=_SECTION,
                ref=desc_label,
                field="enabled",
            )
        )

    _check_parameters(rule, desc_label, ctx)

    # CF493: Duplicate description
    desc = rule.get("description")
    if isinstance(desc, str) and desc and desc in seen_descriptions:
        ctx.add(
            LintResult(
                rule_id="CF493",
                severity=Severity.WARNING,
                message=f"Duplicate description {desc!r} -- descriptions are identity keys",
                phase=_SECTION,
                ref=desc_label,
            )
        )

    # CF494: Unknown fields
    unknown = sorted(k for k in rule if k not in _KNOWN_FIELDS)
    if unknown:
        hint = " (rules here are identified by description, not ref)" if "ref" in unknown else ""
        ctx.add(
            LintResult(
                rule_id="CF494",
                severity=Severity.ERROR,
                message=f"Unknown field(s) {unknown}{hint}",
                phase=_SECTION,
                ref=desc_label,
            )
        )

    expr = rule.get("expression")
    if isinstance(expr, str) and expr:
        # CF495: Duplicate expression across two enabled rules -- a likely
        # copy/paste error. A pair where either side is disabled is left
        # alone (a staged swap is a legitimate shape).
        from octorules.expression import normalize_expression

        if rule.get("enabled") is not False:
            normalized = normalize_expression(expr)
            earlier = seen_expressions.get(normalized)
            if earlier is not None:
                ctx.add(
                    LintResult(
                        rule_id="CF495",
                        severity=Severity.WARNING,
                        message=(
                            f"Expression duplicates enabled rule {earlier!r} --"
                            " likely a copy/paste error"
                        ),
                        phase=_SECTION,
                        ref=desc_label,
                        field="expression",
                    )
                )
            else:
                seen_expressions[normalized] = desc_label

        # CF015 / CF016: always-true / always-false expressions
        check_catch_all(
            expr,
            _SECTION,
            desc_label,
            ctx,
            entity="rule",
            always_true_id="CF015",
            always_false_id="CF016",
        )


def _check_parameters(rule: dict[str, Any], desc_label: str, ctx: LintContext) -> None:
    """Check the ``parameters`` block (CF492 types, CF494 unknown keys)."""
    parameters = rule.get("parameters")
    if parameters is None:
        return
    if not isinstance(parameters, dict):
        ctx.add(
            LintResult(
                rule_id="CF492",
                severity=Severity.ERROR,
                message=f"'parameters' must be a mapping, got {type(parameters).__name__}",
                phase=_SECTION,
                ref=desc_label,
                field="parameters",
            )
        )
        return

    unknown = sorted(k for k in parameters if k not in _KNOWN_PARAMETERS)
    if unknown:
        ctx.add(
            LintResult(
                rule_id="CF494",
                severity=Severity.ERROR,
                message=f"Unknown parameters key(s) {unknown}",
                phase=_SECTION,
                ref=desc_label,
                field="parameters",
            )
        )

    host = parameters.get("host")
    if host is not None and (not isinstance(host, str) or not host):
        ctx.add(
            LintResult(
                rule_id="CF492",
                severity=Severity.ERROR,
                message=f"parameters.host must be a non-empty string, got {host!r}",
                phase=_SECTION,
                ref=desc_label,
                field="parameters",
            )
        )


def _check_rule_expressions(rule: dict[str, Any], desc_label: str, ctx: LintContext) -> None:
    """Delegate expression and phase-restriction analysis to the AST/phase linters."""
    from octorules_cloudflare.linter.ast_linter import lint_expressions
    from octorules_cloudflare.linter.phase_linter import lint_phase_restrictions

    expr = rule.get("expression")
    if not isinstance(expr, str) or not expr:
        return

    lint_expressions(rule, _CC_PHASE, ctx, ref_override=desc_label)
    lint_phase_restrictions(rule, _CC_PHASE, ctx, ref_override=desc_label)
