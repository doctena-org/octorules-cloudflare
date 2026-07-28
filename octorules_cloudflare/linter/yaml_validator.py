"""YAML structure validation — Category M rules.

Validates the structural correctness of zone rules files:
required fields, types, duplicates, unknown phases, etc.
"""

from typing import Any

from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    check_catch_all,
)
from octorules.phases import (
    KNOWN_NON_PHASE_KEYS,
    PHASE_BY_NAME,
    PHASE_BY_PROVIDER_ID,
)

RULE_IDS = frozenset(
    {
        "CF003",
        "CF004",
        "CF005",
        "CF006",
        "CF007",
        "CF008",
        "CF010",
        "CF011",
        "CF012",
        "CF013",
        "CF014",
        "CF015",
        "CF016",
        "CF018",
    }
)

# Maximum recommended description length
_MAX_DESCRIPTION_LENGTH = 500

# Phase keys whose rename aliases have been REMOVED from the registry: the
# planner no longer resolves them, so plan/sync skip the section with only
# a log warning — for a managed-WAF section that silently unmanages it.
# Lint keeps flagging these as errors for as long as the table has entries.
_REMOVED_PHASE_ALIASES: dict[str, str] = {
    "waf_managed_exceptions": "cloudflare.waf_managed_rules",
}

# Zone files nest Cloudflare sections under this namespace; core flattens
# them to ``"cloudflare:<member>"`` for anything it cannot map, so the
# removed-alias check has to see through that scoping.
_NAMESPACE_PREFIX = "cloudflare:"


def lint_yaml_structure(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Category M structural checks on a zone rules file."""
    from octorules_cloudflare import CF_PHASE_NAMES

    _check_top_level_keys(rules_data, ctx)
    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in CF_PHASE_NAMES:
            continue  # not a Cloudflare phase
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        _check_phase_rules(phase_name, rules, ctx)


def _check_top_level_keys(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Check for deprecated or CF-identifier phase keys (CF010, CF014).

    Generic unknown sections are core's CORE011 — it sees the whole file
    and every registered namespace, whereas only the zone's own target
    plugin runs here.
    """
    from octorules_cloudflare import CF_PHASE_NAMES

    for key in sorted(rules_data.keys()):
        if key in KNOWN_NON_PHASE_KEYS:
            continue
        # A nested section core could not map arrives as "cloudflare:<member>";
        # match the removed aliases against the member so the canonical
        # nested spelling is flagged just like the flat one.
        bare = key[len(_NAMESPACE_PREFIX) :] if key.startswith(_NAMESPACE_PREFIX) else key
        if bare in _REMOVED_PHASE_ALIASES:
            new_name = _REMOVED_PHASE_ALIASES[bare]
            ctx.add(
                LintResult(
                    rule_id="CF010",
                    severity=Severity.ERROR,
                    message=(
                        f"Phase {bare!r} has been renamed to {new_name!r} and the old"
                        " name is no longer accepted — plan and sync ignore this"
                        " section until it is renamed"
                    ),
                    phase=key,
                    suggestion=f"Rename to {new_name!r}",
                )
            )
            continue
        if key in PHASE_BY_NAME and key not in CF_PHASE_NAMES:
            continue  # phase owned by another provider — not our business
        if key in PHASE_BY_PROVIDER_ID:
            friendly = PHASE_BY_PROVIDER_ID[key].friendly_name
            ctx.add(
                LintResult(
                    rule_id="CF014",
                    severity=Severity.WARNING,
                    message=(
                        f"Provider phase identifier {key!r} used instead of"
                        f" friendly name {friendly!r}"
                    ),
                    phase=key,
                    suggestion=f"Use {friendly!r} instead",
                )
            )
        # Anything else unknown falls to core's CORE011.


def _check_phase_rules(phase_name: str, rules: Any, ctx: LintContext) -> None:
    """Validate rules list structure within a phase."""
    if not isinstance(rules, list):
        ctx.add(
            LintResult(
                rule_id="CF012",
                severity=Severity.ERROR,
                message=f"Phase {phase_name!r} value must be a list, got {type(rules).__name__}",
                phase=phase_name,
            )
        )
        return

    seen_refs: set[str] = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            ctx.add(
                LintResult(
                    rule_id="CF013",
                    severity=Severity.ERROR,
                    message=f"Rule at index {i} must be a mapping, got {type(rule).__name__}",
                    phase=phase_name,
                )
            )
            continue

        ctx.set_location(rule)
        ref = rule.get("ref")
        _check_rule_fields(phase_name, rule, i, ctx)

        # Check ref uniqueness
        if ref is not None and isinstance(ref, str) and ref:
            if ref in seen_refs:
                ctx.add(
                    LintResult(
                        rule_id="CF005",
                        severity=Severity.ERROR,
                        message=f"Duplicate ref {ref!r} within phase",
                        phase=phase_name,
                        ref=ref,
                    )
                )
            seen_refs.add(ref)


def _check_rule_fields(phase_name: str, rule: dict, index: int, ctx: LintContext) -> None:
    """Check individual rule fields (CF003-CF008, CF011)."""
    ref = rule.get("ref")
    ref_label = ref if isinstance(ref, str) and ref else f"index {index}"

    # CF003: missing ref
    if "ref" not in rule:
        ctx.add(
            LintResult(
                rule_id="CF003",
                severity=Severity.ERROR,
                message=f"Rule at index {index} is missing required 'ref' field",
                phase=phase_name,
            )
        )
    elif not isinstance(ref, str) or not ref:
        # CF006: invalid ref type
        ctx.add(
            LintResult(
                rule_id="CF006",
                severity=Severity.ERROR,
                message="Invalid 'ref' (must be a non-empty string)",
                phase=phase_name,
                ref=ref_label,
            )
        )

    # CF004: missing expression
    if "expression" not in rule:
        ctx.add(
            LintResult(
                rule_id="CF004",
                severity=Severity.ERROR,
                message="Rule is missing required 'expression' field",
                phase=phase_name,
                ref=ref_label,
            )
        )
    else:
        expr = rule["expression"]
        if not isinstance(expr, str) or not expr:
            # CF007: invalid expression type
            ctx.add(
                LintResult(
                    rule_id="CF007",
                    severity=Severity.ERROR,
                    message="Invalid 'expression' (must be a non-empty string)",
                    phase=phase_name,
                    ref=ref_label,
                )
            )

    # CF008: invalid enabled type
    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        ctx.add(
            LintResult(
                rule_id="CF008",
                severity=Severity.ERROR,
                message=(
                    f"'enabled' must be a boolean, got {type(rule['enabled']).__name__}"
                    f" ({rule['enabled']!r})"
                ),
                phase=phase_name,
                ref=ref_label,
                field="enabled",
            )
        )

    # CF011: description too long
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_DESCRIPTION_LENGTH:
        ctx.add(
            LintResult(
                rule_id="CF011",
                severity=Severity.WARNING,
                message=(
                    f"Description is {len(desc)} chars (max recommended: {_MAX_DESCRIPTION_LENGTH})"
                ),
                phase=phase_name,
                ref=ref_label,
                field="description",
            )
        )

    # CF018: disabled rule
    if rule.get("enabled") is False:
        ctx.add(
            LintResult(
                rule_id="CF018",
                severity=Severity.INFO,
                message="Rule is disabled (enabled: false)",
                phase=phase_name,
                ref=ref_label,
                suggestion="Remove if no longer needed",
            )
        )

    # CF015 / CF016: always-true / always-false expressions
    expr = rule.get("expression")
    if isinstance(expr, str):
        check_catch_all(
            expr,
            phase_name,
            ref_label,
            ctx,
            always_true_id="CF015",
            always_false_id="CF016",
        )
