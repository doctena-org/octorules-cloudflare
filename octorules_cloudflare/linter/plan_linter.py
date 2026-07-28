"""Plan linter — plan-level entitlement checks (Category H).

Validates rules against Cloudflare plan tier limitations:
regex availability, rule count limits, Enterprise-only features.
"""

from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import KNOWN_NON_PHASE_KEYS, PHASE_BY_NAME

from octorules_cloudflare.linter.expression_bridge import parse_expression

RULE_IDS = frozenset({"CF500", "CF501"})

# Rule count limits per phase per plan tier
_RULE_LIMITS: dict[str, dict[str, int]] = {
    "free": {
        "cloudflare.redirect_rules": 10,
        "cloudflare.url_rewrite_rules": 10,
        "cloudflare.request_header_rules": 10,
        "cloudflare.response_header_rules": 10,
        "cloudflare.config_rules": 10,
        "cloudflare.origin_rules": 10,
        "cloudflare.cache_rules": 10,
        "cloudflare.compression_rules": 10,
        "cloudflare.waf_custom_rules": 5,
        "cloudflare.rate_limiting_rules": 1,
    },
    "pro": {
        "cloudflare.redirect_rules": 25,
        "cloudflare.url_rewrite_rules": 25,
        "cloudflare.request_header_rules": 25,
        "cloudflare.response_header_rules": 25,
        "cloudflare.config_rules": 25,
        "cloudflare.origin_rules": 25,
        "cloudflare.cache_rules": 25,
        "cloudflare.compression_rules": 25,
        "cloudflare.waf_custom_rules": 20,
        "cloudflare.rate_limiting_rules": 2,
    },
    "business": {
        "cloudflare.redirect_rules": 50,
        "cloudflare.url_rewrite_rules": 50,
        "cloudflare.request_header_rules": 50,
        "cloudflare.response_header_rules": 50,
        "cloudflare.config_rules": 50,
        "cloudflare.origin_rules": 50,
        "cloudflare.cache_rules": 50,
        "cloudflare.compression_rules": 50,
        "cloudflare.waf_custom_rules": 100,
        "cloudflare.rate_limiting_rules": 5,
    },
    # Enterprise limits per Cloudflare's product docs ("Availability" tables)
    # and the 2025-02-12 changelog that raised the rules-engine phases from
    # 125 to 300. Enterprise contracts can negotiate higher quotas; CF501 is
    # WARNING severity, so a negotiated-higher zone just suppresses or
    # ignores the finding.
    "enterprise": {
        "cloudflare.redirect_rules": 300,
        "cloudflare.url_rewrite_rules": 300,
        "cloudflare.request_header_rules": 300,
        "cloudflare.response_header_rules": 300,
        "cloudflare.config_rules": 300,
        "cloudflare.origin_rules": 300,
        "cloudflare.cache_rules": 300,
        "cloudflare.compression_rules": 300,
        "cloudflare.waf_custom_rules": 1000,
        "cloudflare.rate_limiting_rules": 100,
    },
}

# Plans where regex is available in expressions
_REGEX_PLANS = frozenset({"business", "enterprise"})


def lint_plan_tier(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Check rules against plan tier limitations."""
    plan = ctx.plan_tier

    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        # CF501: Rule count exceeds plan limit
        limits = _RULE_LIMITS.get(plan, {})
        limit = limits.get(phase_name)
        if limit is not None and len(rules) > limit:
            ctx.add(
                LintResult(
                    rule_id="CF501",
                    severity=Severity.WARNING,
                    message=(
                        f"Phase {phase_name!r} has {len(rules)} rules,"
                        f" exceeding {plan} plan limit of {limit}"
                    ),
                    phase=phase_name,
                )
            )

        # CF500: Regex usage on plans that don't support it
        if plan not in _REGEX_PLANS:
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                expr = rule.get("expression", "")
                if not isinstance(expr, str):
                    continue
                info = parse_expression(expr, phase=phase_name)
                if info.has_regex:
                    ref = rule.get("ref", "")
                    ctx.add(
                        LintResult(
                            rule_id="CF500",
                            severity=Severity.WARNING,
                            message=(
                                f"Regex operator used in expression, but {plan} plan"
                                " does not include regex support"
                                " (requires Business or Enterprise)"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
