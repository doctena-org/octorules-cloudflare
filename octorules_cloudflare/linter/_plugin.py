"""Cloudflare lint plugin — orchestrates all CF-specific linter stages.

This is the provider-side equivalent of what ``lint_zone_file()`` used to do
inline.  It is registered as a ``LintPlugin`` and called by the core engine.
"""

from __future__ import annotations

from typing import Any

from octorules.linter.engine import LintContext
from octorules.phases import KNOWN_NON_PHASE_KEYS, PHASE_BY_NAME

from octorules_cloudflare.linter.action_validator import RULE_IDS as _av
from octorules_cloudflare.linter.ast_linter import RULE_IDS as _al
from octorules_cloudflare.linter.cross_rule_linter import RULE_IDS as _cr
from octorules_cloudflare.linter.custom_ruleset_linter import RULE_IDS as _crl
from octorules_cloudflare.linter.list_linter import RULE_IDS as _ll
from octorules_cloudflare.linter.page_shield_linter import RULE_IDS as _psl
from octorules_cloudflare.linter.phase_linter import RULE_IDS as _pl
from octorules_cloudflare.linter.plan_linter import RULE_IDS as _pll
from octorules_cloudflare.linter.yaml_validator import RULE_IDS as _yv

CF_RULE_IDS: frozenset[str] = _av | _al | _cr | _crl | _ll | _psl | _pl | _pll | _yv


def cloudflare_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Cloudflare-specific lint checks on a zone rules file.

    Four stages:
    1. YAML structure validation
    2. Per-rule checks (actions, expressions, phase restrictions) + custom
       rulesets + page shield + lists
    3. Plan-tier checks
    4. Cross-rule analysis
    """
    from octorules_cloudflare.linter.action_validator import lint_actions
    from octorules_cloudflare.linter.ast_linter import lint_expressions
    from octorules_cloudflare.linter.cross_rule_linter import lint_cross_rules
    from octorules_cloudflare.linter.custom_ruleset_linter import lint_custom_rulesets
    from octorules_cloudflare.linter.list_linter import lint_lists
    from octorules_cloudflare.linter.page_shield_linter import lint_page_shield_policies
    from octorules_cloudflare.linter.phase_linter import lint_phase_restrictions
    from octorules_cloudflare.linter.plan_linter import lint_plan_tier
    from octorules_cloudflare.linter.yaml_validator import lint_yaml_structure

    # Stage 1: YAML structure validation
    lint_yaml_structure(rules_data, ctx)

    from octorules_cloudflare import CF_PHASE_NAMES

    # Stage 2: Per-phase, per-rule checks (only Cloudflare phases)
    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in CF_PHASE_NAMES:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        phase = PHASE_BY_NAME[phase_name]
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            # Action validation
            lint_actions(rule, phase, ctx)

            # Expression-level analysis
            lint_expressions(rule, phase, ctx)

            # Phase restriction checks
            lint_phase_restrictions(rule, phase, ctx)

    # Stage 2b: Custom ruleset rules (use waf_custom_rules phase for validation)
    lint_custom_rulesets(rules_data, ctx)
    custom_rulesets = rules_data.get("custom_rulesets")
    if isinstance(custom_rulesets, list):
        waf_phase = PHASE_BY_NAME.get("waf_custom_rules")
        if waf_phase and (not ctx.phase_filter or "custom_rulesets" in ctx.phase_filter):
            for entry in custom_rulesets:
                if not isinstance(entry, dict):
                    continue
                for rule in entry.get("rules", []):
                    if not isinstance(rule, dict):
                        continue
                    lint_actions(rule, waf_phase, ctx)
                    lint_expressions(rule, waf_phase, ctx)
                    lint_phase_restrictions(rule, waf_phase, ctx)

    # Stage 2c: Page Shield policy checks
    lint_page_shield_policies(rules_data, ctx)

    # Stage 2d: List validation
    lint_lists(rules_data, ctx)

    # Stage 3: Plan-tier checks
    lint_plan_tier(rules_data, ctx)

    # Stage 4: Cross-rule analysis
    lint_cross_rules(rules_data, ctx)
