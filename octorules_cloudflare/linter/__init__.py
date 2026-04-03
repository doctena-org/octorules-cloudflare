"""Cloudflare linter — registers all CF-specific lint rules and plugins."""

import logging

log = logging.getLogger(__name__)

_registered = False


def register_cloudflare_linter() -> None:
    """Register the Cloudflare lint plugin, rule definitions, and non-phase keys.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _registered
    if _registered:
        return

    from octorules.linter.plugin import LintPlugin, register_linter
    from octorules.linter.rules.registry import register_rules
    from octorules.phases import register_api_fields, register_non_phase_key, register_phase_alias

    from octorules_cloudflare.linter._plugin import CF_RULE_IDS, cloudflare_lint
    from octorules_cloudflare.linter._rules import CF_RULE_METAS
    from octorules_cloudflare.linter.expression_bridge import WIREFILTER_AVAILABLE

    if WIREFILTER_AVAILABLE:
        log.info("Expression parser: wirefilter")
    else:
        log.info(
            "Expression parser: regex fallback (install octorules-wirefilter for full parsing)"
        )

    register_linter(LintPlugin(name="cloudflare", lint_fn=cloudflare_lint, rule_ids=CF_RULE_IDS))
    register_rules(CF_RULE_METAS)
    for key in ("custom_rulesets", "lists", "page_shield_policies"):
        register_non_phase_key(key)

    # Register Cloudflare-specific API fields to strip
    register_api_fields("rule", {"id", "version", "last_updated", "categories", "logging"})
    register_api_fields("list_item", {"id", "created_on", "modified_on"})
    register_api_fields("page_shield_policy", {"id", "last_updated"})

    # Register backward-compat phase alias
    register_phase_alias("waf_managed_exceptions", "waf_managed_rules")

    _registered = True
