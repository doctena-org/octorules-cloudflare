"""Cloudflare audit extension — extracts IP ranges from wirefilter expressions."""

import re

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_cloudflare import CF_PHASE_NAMES
from octorules_cloudflare.linter.expression_bridge import parse_expression

# Same pattern used by the linter (cross_rule_linter.py CF102).
_LIST_REF_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_.]*)")


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP literals and list references from Cloudflare rules."""
    if phase_name not in CF_PHASE_NAMES:
        return []
    if phase_name not in PHASE_BY_NAME:
        return []

    rules = rules_data.get(phase_name)
    if not isinstance(rules, list):
        return []

    results: list[RuleIPInfo] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))
        expression = rule.get("expression", "")
        if not isinstance(expression, str) or not expression:
            continue

        info = parse_expression(expression, phase_name)
        ip_literals = list(info.ip_literals)

        # Extract $list_name references (wirefilter can't parse these)
        list_refs = _LIST_REF_RE.findall(expression)

        if ip_literals or list_refs:
            results.append(
                RuleIPInfo(
                    zone_name="",  # Stamped by caller
                    phase_name=phase_name,
                    ref=ref,
                    action=action,
                    ip_ranges=ip_literals,
                    list_refs=list_refs,
                )
            )

    return results


def register_cloudflare_audit() -> None:
    """Register the Cloudflare audit IP extractor."""
    register_audit_extension("cloudflare", _extract_ips)
