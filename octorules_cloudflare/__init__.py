"""Cloudflare provider for octorules."""

from octorules.expression import normalize_expression
from octorules.phases import Phase, register_non_phase_key, register_phases

from octorules_cloudflare.linter import register_cloudflare_linter
from octorules_cloudflare.provider import CloudflareProvider


def _cf_prepare_rule(rule: dict, phase: Phase) -> dict:
    """Cloudflare-specific rule preparation.

    Called by the core planner's ``prepare_desired_rules()`` via the
    ``Phase.prepare_rule`` hook.  Handles:

    - Normalize ``expression`` (collapse whitespace).
    - Normalize ``counting_expression`` inside ``action_parameters``.
    - Default ``enabled`` to ``True``.
    - Inject ``phase.default_action`` when rule has no ``action``.

    Returns a new dict — the original *rule* is never mutated.
    """
    rule = rule.copy()
    if "expression" not in rule:
        raise ValueError(
            f"Rule {rule.get('ref', '?')!r} in phase {phase.friendly_name!r}"
            f" is missing required 'expression' field"
        )
    rule["expression"] = normalize_expression(rule["expression"])
    ap = rule.get("action_parameters")
    if isinstance(ap, dict) and isinstance(ap.get("counting_expression"), str):
        ap = ap.copy()
        ap["counting_expression"] = normalize_expression(ap["counting_expression"])
        rule["action_parameters"] = ap
    if "enabled" not in rule:
        rule["enabled"] = True
    if "action" not in rule:
        if phase.default_action is None:
            raise ValueError(
                f"Rule {rule.get('ref', '?')!r} in phase {phase.friendly_name!r} "
                f"must specify an 'action' (no default for this phase)"
            )
        rule["action"] = phase.default_action
    return rule


# ---------------------------------------------------------------------------
# Cloudflare phase definitions — registered with octorules core at import.
# ---------------------------------------------------------------------------

# (friendly_name, provider_id, default_action, zone_level, account_level)
_CF_PHASE_SPECS: list[tuple] = [
    ("redirect_rules", "http_request_dynamic_redirect", "redirect", True, False),
    ("url_rewrite_rules", "http_request_transform", "rewrite", True, False),
    ("request_header_rules", "http_request_late_transform", "rewrite", True, False),
    ("response_header_rules", "http_response_headers_transform", "rewrite", True, False),
    ("config_rules", "http_config_settings", "set_config", True, False),
    ("origin_rules", "http_request_origin", "route", True, False),
    ("cache_rules", "http_request_cache_settings", "set_cache_settings", True, False),
    ("compression_rules", "http_response_compression", "compress_response", True, False),
    ("custom_error_rules", "http_custom_errors", "serve_error", True, True),
    ("waf_custom_rules", "http_request_firewall_custom", None, True, True),
    ("waf_managed_rules", "http_request_firewall_managed", None, True, True),
    ("rate_limiting_rules", "http_ratelimit", None, True, True),
    ("bot_fight_rules", "http_request_sbfm", None, True, False),
    ("sensitive_data_detection", "http_response_firewall_managed", None, True, False),
    ("http_ddos_rules", "ddos_l7", None, True, True),
    ("bulk_redirect_rules", "http_request_redirect", "redirect", False, True),
    ("log_custom_fields", "http_log_custom_fields", "log_custom_field", True, False),
    ("network_ddos_rules", "ddos_l4", None, False, True),
    ("network_firewall_rules", "magic_transit", None, False, True),
    ("network_firewall_managed", "magic_transit_managed", None, False, True),
    ("network_firewall_ratelimit", "magic_transit_ratelimit", None, False, True),
    ("network_firewall_ids", "magic_transit_ids_managed", None, False, True),
    ("url_normalization", "http_request_sanitize", None, True, False),
]

_CF_PHASES: list[Phase] = [
    Phase(
        name,
        pid,
        action,
        zone_level=zl,
        account_level=al,
        prepare_rule=_cf_prepare_rule,
    )
    for name, pid, action, zl, al in _CF_PHASE_SPECS
]

CF_PHASE_NAMES: frozenset[str] = frozenset(p.friendly_name for p in _CF_PHASES)

# Register phases first (lint plugin and other registrations may depend on them).
register_phases(_CF_PHASES)

# Register non-phase keys (config sections that aren't phase-based rulesets).
for _key in ("custom_rulesets", "lists", "page_shield_policies"):
    register_non_phase_key(_key)

# Auto-register CF-specific lint rules and the lint plugin.
register_cloudflare_linter()

# Register Page Shield extension hooks.
from octorules_cloudflare.page_shield import register_page_shield  # noqa: E402

register_page_shield()

# Register audit IP extractor.
from octorules_cloudflare.audit import register_cloudflare_audit  # noqa: E402

register_cloudflare_audit()

# Register bot management extension hooks.
register_non_phase_key("cloudflare_bot_management")
from octorules_cloudflare._bot_management import register_bot_management  # noqa: E402

register_bot_management()

# Register URL normalization extension hooks.
register_non_phase_key("cloudflare_url_normalization")
from octorules_cloudflare._url_normalization import (  # noqa: E402
    register_url_normalization,
)

register_url_normalization()

# Register zone security settings extension hooks.
register_non_phase_key("cloudflare_zone_security")
from octorules_cloudflare._zone_security import register_zone_security  # noqa: E402

register_zone_security()

# Register leaked credential check extension hooks.
register_non_phase_key("cloudflare_leaked_credential_check")
from octorules_cloudflare._leaked_credentials import (  # noqa: E402
    register_leaked_credentials,
)

register_leaked_credentials()

# Register content scanning extension hooks.
register_non_phase_key("cloudflare_content_scanning")
from octorules_cloudflare._content_scanning import register_content_scanning  # noqa: E402

register_content_scanning()

__all__ = ["CloudflareProvider"]
