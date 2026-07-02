"""Cloudflare linter — registers all CF-specific lint rules and plugins."""

from octorules.registration import idempotent_registration


@idempotent_registration
def register_cloudflare_linter() -> None:
    """Register the Cloudflare lint plugin and rule definitions."""
    from octorules.linter.plugin import LintPlugin, register_linter
    from octorules.linter.rules.registry import register_rules
    from octorules.phases import register_api_fields, register_phase_alias

    from octorules_cloudflare.linter._plugin import CF_RULE_IDS, cloudflare_lint
    from octorules_cloudflare.linter._rules import CF_RULE_METAS

    register_linter(LintPlugin(name="cloudflare", lint_fn=cloudflare_lint, rule_ids=CF_RULE_IDS))
    register_rules(CF_RULE_METAS)

    # Register Cloudflare-specific API fields to strip.
    #
    # ``logging`` is intentionally **not** in this set: it's user-controllable
    # per-rule (``logging.enabled: true/false``) and Cloudflare's PUT default
    # is ``true``. Stripping it on dump and omitting it on sync silently
    # flipped previously-quiet skip rules into firewall_event emitters,
    # blowing up Logpush volume. See CHANGELOG 0.8.2 for the full story.
    register_api_fields("rule", {"id", "version", "last_updated", "categories"})
    register_api_fields("action_parameters", {"version", "disable_railgun"})
    register_api_fields("list_item", {"id", "created_on", "modified_on"})
    register_api_fields("page_shield_policy", {"id", "last_updated"})

    # Register backward-compat phase alias
    register_phase_alias("waf_managed_exceptions", "waf_managed_rules")
