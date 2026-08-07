"""Cloudflare audit extension — extracts IP ranges from wirefilter expressions."""

import re

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_cloudflare import CF_PHASE_NAMES
from octorules_cloudflare.linter.expression_bridge import parse_expression

# Same pattern used by the linter (cross_rule_linter.py CF102).
_LIST_REF_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_.]*)")

# Tokeniser for negation analysis: parentheses, quoted strings (skipped so a
# `not` inside a literal is not read as an operator), and bare words.
_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[()]|[^\s()]+')

# A `not` binds to the group or comparison that follows it; a boolean connective
# ends its reach (`not a and b` negates `a`, not `b`).
_CONNECTIVES = frozenset({"and", "or", "xor", "&&", "||"})
_NEGATORS = frozenset({"not", "!"})


def _negated_spans(expr: str) -> list[tuple[int, int]]:
    """Character spans of *expr* that sit under an odd number of negations.

    Cloudflare expressions exempt traffic by negating a match — `not (ip.src in
    $trusted and ...)`. An IP reached that way is one the rule deliberately does
    NOT act on, so reporting it as a match target makes the audit's cross-rule
    and cross-zone checks compare exemptions as if they were blocks.

    Returns the spans rather than a per-token verdict so callers can classify
    any occurrence by position. Parity, not a flag, so `not not x` is positive.
    """
    spans: list[tuple[int, int]] = []
    depth_parity: list[int] = [0]  # parity of each open parenthesis level
    pending = 0  # a `not` seen at this level, awaiting its operand
    for m in _TOKEN_RE.finditer(expr):
        tok = m.group(0)
        if tok.startswith('"'):
            continue
        if tok in _NEGATORS:
            pending ^= 1
            continue
        if tok == "(":
            depth_parity.append(depth_parity[-1] ^ pending)
            pending = 0
            continue
        if tok == ")":
            if len(depth_parity) > 1:
                depth_parity.pop()
            pending = 0
            continue
        lowered = tok.lower()
        if lowered in _CONNECTIVES:
            pending = 0
            continue
        if depth_parity[-1] ^ pending:
            spans.append(m.span())
    return spans


def _is_negated(expr: str, span: tuple[int, int], negated: list[tuple[int, int]]) -> bool:
    """True when *span* falls inside a negated span of *expr*."""
    return any(start <= span[0] and span[1] <= end for start, end in negated)


def _positive_occurrences(expr: str, values: list[str], *, prefix: str = "") -> list[str]:
    """Keep only *values* that appear outside every negation in *expr*.

    Conservative by construction: a value whose text cannot be located, or that
    occurs positively anywhere, is kept. Dropping a real match target would
    blind the audit silently, which is worse than the false positives this
    filters out.
    """
    if not values:
        return []
    negated = _negated_spans(expr)
    if not negated:
        return values
    kept: list[str] = []
    for value in values:
        needle = re.escape(prefix + value)
        occurrences = [m.span() for m in re.finditer(rf"(?<![\w.]){needle}(?![\w.])", expr)]
        if not occurrences or any(not _is_negated(expr, s, negated) for s in occurrences):
            kept.append(value)
    return kept


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP literals and list references from Cloudflare rules.

    Rules nested in ``custom_rulesets`` are walked by core, which resolves the
    ruleset's ``phase`` and calls back in with the matching section.
    """
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
        # A disabled rule enforces nothing, so its addresses are not match
        # targets: auditing them reports overlaps and drift against traffic
        # handling that does not happen. Absent `enabled` means enabled.
        if rule.get("enabled") is False:
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))
        expression = rule.get("expression", "")
        if not isinstance(expression, str) or not expression:
            continue

        info = parse_expression(expression, phase_name)
        # Analyse polarity against the same normalised text the parser saw, so
        # literal offsets line up. Negated matches are exemptions — the rule
        # does not act on that traffic, so they are not match targets.
        analysed = info.raw or expression
        ip_literals = _positive_occurrences(analysed, list(info.ip_literals))

        # Extract $list_name references (wirefilter can't parse these)
        all_list_refs = _LIST_REF_RE.findall(analysed)
        list_refs = _positive_occurrences(analysed, all_list_refs, prefix="$")
        # Referenced only to exempt: not a match target, but still a reference,
        # so the list must not be reported as unused.
        negated_list_refs = [r for r in dict.fromkeys(all_list_refs) if r not in list_refs]

        if ip_literals or list_refs or negated_list_refs:
            results.append(
                RuleIPInfo(
                    zone_name="",  # Stamped by caller
                    phase_name=phase_name,
                    ref=ref,
                    action=action,
                    ip_ranges=ip_literals,
                    list_refs=list_refs,
                    negated_list_refs=negated_list_refs,
                )
            )

    return results


_registered = False


def register_cloudflare_audit() -> None:
    """Register the Cloudflare audit IP extractor.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _registered
    if _registered:
        return
    _registered = True
    register_audit_extension("cloudflare", _extract_ips)
