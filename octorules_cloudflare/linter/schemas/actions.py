"""Action schemas — valid actions per phase and action_parameters schemas.

Defines which actions are valid in which phases, whether action_parameters
is required, and the expected structure of action_parameters.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionSchema:
    """Schema for a single action's parameters."""

    requires_parameters: bool = False
    allowed_parameter_keys: frozenset[str] = frozenset()
    required_parameter_keys: frozenset[str] = frozenset()


# --- Action schemas ---

REDIRECT_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"from_value", "from_list"}),
)

REWRITE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"uri", "headers"}),
)

SET_CACHE_SETTINGS_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "cache",
            "edge_ttl",
            "browser_ttl",
            "serve_stale",
            "respect_strong_etags",
            "cache_key",
            "origin_error_page_passthru",
            "cache_reserve",
            "origin_cache_control",
            "additional_cacheable_ports",
            "read_timeout",
            "shared_dictionary",
            "strip_etags",
            "strip_last_modified",
            "strip_set_cookie",
            "vary",
        }
    ),
)

SET_CONFIG_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "automatic_https_rewrites",
            "autominify",
            "bic",
            "disable_apps",
            "disable_rum",
            "disable_zaraz",
            "email_obfuscation",
            "fonts",
            "hotlink_protection",
            "mirage",
            "opportunistic_encryption",
            "polish",
            "rocket_loader",
            "security_level",
            "server_side_excludes",
            "ssl",
            "sxg",
            "content_converter",
            "disable_pay_per_crawl",
            "redirects_for_ai_training",
            "request_body_buffering",
            "response_body_buffering",
        }
    ),
)

ROUTE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "host_header",
            "origin",
            "sni",
        }
    ),
)

COMPRESS_RESPONSE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"algorithms"}),
)

SERVE_ERROR_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "content",
            "content_type",
            "status_code",
            "asset_name",
        }
    ),
)

LOG_CUSTOM_FIELD_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "request_fields",
            "response_fields",
            "cookie_fields",
            "raw_response_fields",
            "transformed_request_fields",
        }
    ),
)

# WAF actions
BLOCK_SCHEMA = ActionSchema(
    requires_parameters=False,
    allowed_parameter_keys=frozenset({"response"}),
)

CHALLENGE_SCHEMAS = ActionSchema(requires_parameters=False)

SKIP_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "ruleset",
            "rulesets",
            "rules",
            "phases",
            "products",
            "phase",
        }
    ),
)

EXECUTE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "id",
            "matched_data",
            "overrides",
        }
    ),
)

SCORE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"increment"}),
)

DDOS_DYNAMIC_SCHEMA = ActionSchema(requires_parameters=False)

FORCE_CONNECTION_CLOSE_SCHEMA = ActionSchema(requires_parameters=False)

RATE_LIMIT_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "characteristics",
            "period",
            "requests_per_period",
            "mitigation_timeout",
            "counting_expression",
            "requests_to_origin",
            "score_per_period",
            "score_response_header_name",
        }
    ),
)

LOG_SCHEMA = ActionSchema(requires_parameters=False)

# --- Phase-specific parameter restrictions ---
# Narrows the action schema's allowed_parameter_keys for specific phases.
# Used by CF203 to catch rules misplaced under the wrong phase (e.g. a
# url_rewrite_rules entry with action_parameters.uri accidentally falling
# under response_header_rules after a YAML editing mistake).

PHASE_PARAMETER_OVERRIDES: dict[str, frozenset[str]] = {
    # response_header_rules only supports header transforms — URI rewrites
    # are not available in the response phase (the request URI is already gone).
    "cloudflare.response_header_rules": frozenset({"headers"}),
}

# --- Valid actions per phase ---

VALID_ACTIONS_BY_PHASE: dict[str, set[str]] = {
    "cloudflare.redirect_rules": {"redirect"},
    "cloudflare.url_rewrite_rules": {"rewrite"},
    "cloudflare.request_header_rules": {"rewrite"},
    "cloudflare.response_header_rules": {"rewrite"},
    "cloudflare.config_rules": {"set_config"},
    "cloudflare.origin_rules": {"route"},
    "cloudflare.cache_rules": {"set_cache_settings"},
    "cloudflare.compression_rules": {"compress_response"},
    "cloudflare.custom_error_rules": {"serve_error"},
    "cloudflare.waf_custom_rules": {
        "block",
        "challenge",
        "js_challenge",
        "managed_challenge",
        "skip",
        "log",
        "execute",
        "score",
    },
    "cloudflare.waf_managed_rules": {"execute", "skip", "block", "log"},
    "cloudflare.rate_limiting_rules": {
        "block",
        "challenge",
        "js_challenge",
        "managed_challenge",
        "log",
        "execute",
    },
    "cloudflare.bot_fight_rules": {"block", "challenge", "js_challenge", "managed_challenge"},
    "cloudflare.sensitive_data_detection": {"log"},
    "cloudflare.http_ddos_rules": {
        "block",
        "challenge",
        "log",
        "ddos_dynamic",
        "force_connection_close",
        # Deploying the HTTP DDoS managed ruleset with sensitivity or action
        # overrides is an `execute` rule in this phase (Cloudflare's own
        # configure-via-API guide), and live zones carry exactly that. Its
        # absence here made CF200 error on a working configuration, so a
        # dumped zone could not be adopted without editing out real state.
        "execute",
    },
    "cloudflare.bulk_redirect_rules": {"redirect"},
    "cloudflare.log_custom_fields": {"log_custom_field"},
    "cloudflare.url_normalization": {"none"},
    # Network-level phases
    "cloudflare.network_ddos_rules": {"block", "log"},
    "cloudflare.network_firewall_rules": {"block", "log"},
    "cloudflare.network_firewall_managed": {"block", "log"},
    "cloudflare.network_firewall_ratelimit": {"block", "log"},
    "cloudflare.network_firewall_ids": {"block", "log"},
}

# --- Action → schema mapping ---

ACTION_SCHEMAS: dict[str, ActionSchema] = {
    "redirect": REDIRECT_SCHEMA,
    "rewrite": REWRITE_SCHEMA,
    "set_cache_settings": SET_CACHE_SETTINGS_SCHEMA,
    "set_config": SET_CONFIG_SCHEMA,
    "route": ROUTE_SCHEMA,
    "compress_response": COMPRESS_RESPONSE_SCHEMA,
    "serve_error": SERVE_ERROR_SCHEMA,
    "log_custom_field": LOG_CUSTOM_FIELD_SCHEMA,
    "block": BLOCK_SCHEMA,
    "challenge": CHALLENGE_SCHEMAS,
    "js_challenge": CHALLENGE_SCHEMAS,
    "managed_challenge": CHALLENGE_SCHEMAS,
    "skip": SKIP_SCHEMA,
    "execute": EXECUTE_SCHEMA,
    "log": LOG_SCHEMA,
    "score": SCORE_SCHEMA,
    "ddos_dynamic": DDOS_DYNAMIC_SCHEMA,
    "force_connection_close": FORCE_CONNECTION_CLOSE_SCHEMA,
    "none": ActionSchema(requires_parameters=False),
}

# --- Specific enum values for config rules ---

# Security level (challenge aggressiveness) has two distinct valid sets:
#  * Zone-wide baseline (cloudflare_zone_security) accepts all six graduated
#    levels — see _zone_security._VALID_SECURITY_LEVELS.
#  * Configuration Rules (http_config_settings) only accept the three on/off
#    style values below. Cloudflare's API rejects the graduated levels
#    (low/medium/high) in a config rule; CF420 flags them.
VALID_CONFIG_SECURITY_LEVELS = frozenset(
    {
        "off",
        "essentially_off",
        "under_attack",
    }
)

# Graduated levels that are valid only as a zone-wide baseline, never in a
# Configuration Rule. CF420 uses this to emit a targeted diagnostic.
ZONE_ONLY_SECURITY_LEVELS = frozenset({"low", "medium", "high"})

VALID_SSL_VALUES = frozenset(
    {
        "off",
        "flexible",
        "full",
        "strict",
        "origin_pull",
    }
)

VALID_POLISH_VALUES = frozenset(
    {
        "off",
        "lossless",
        "lossy",
        "webp",
    }
)

# --- Cache rule TTL modes ---

VALID_EDGE_TTL_MODES = frozenset(
    {
        "respect_origin",
        "override_origin",
        "bypass_by_default",
    }
)

VALID_BROWSER_TTL_MODES = frozenset(
    {
        "respect_origin",
        "override_origin",
        "bypass_by_default",
    }
)

# --- Cache rule Vary actions (set_cache_settings.vary, SDK 5.6+) ---
# Mirrors the Literal on ActionParametersVaryDefault.action and
# ActionParametersVaryHeaders.action.
VALID_VARY_ACTIONS = frozenset(
    {
        "bypass",
        "passthrough",
        "normalize",
    }
)

# --- Redirect status codes ---

VALID_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

# --- Rate limiting constants ---

VALID_RATE_LIMIT_PERIODS = frozenset({10, 60, 120, 300, 600, 3600})

# Max characteristics per plan tier
MAX_CHARACTERISTICS: dict[str, int] = {
    "free": 1,
    "pro": 1,
    "business": 2,
    "enterprise": 4,
}

# --- Compression algorithms ---

VALID_COMPRESSION_ALGORITHMS = frozenset({"gzip", "brotli", "zstd", "none", "auto", "default"})

# --- Skip action valid values ---

VALID_SKIP_PHASES = frozenset(
    {
        "http_request_firewall_custom",
        "http_ratelimit",
        "http_request_firewall_managed",
        "http_request_sbfm",
        "http_request_transform",
        "http_request_origin",
        "http_request_cache_settings",
        "http_config_settings",
        "http_request_late_transform",
        "http_response_headers_transform",
        "http_response_firewall_managed",
        "http_response_compression",
        "http_log_custom_fields",
    }
)

VALID_SKIP_PRODUCTS = frozenset(
    {
        "bic",
        "hot",
        "rateLimit",
        "securityLevel",
        "uaBlock",
        "waf",
        "zoneLockdown",
    }
)

# --- Execute override sensitivity levels ---

VALID_SENSITIVITY_LEVELS = frozenset({"default", "medium", "low", "eoff"})

# --- Serve error content types ---

VALID_SERVE_ERROR_CONTENT_TYPES = frozenset(
    {"application/json", "text/xml", "text/plain", "text/html"}
)

# --- Skip action ruleset values ---

VALID_SKIP_RULESET_VALUES = frozenset({"current"})

# --- Skip action parameters valid per phase ---
#
# Which skip options exist depends on where the rule sits (the docs list them
# per context: https://developers.cloudflare.com/waf/custom-rules/skip/options/).
# A parameter
# used outside its phase is rejected at sync time with API error 20117, e.g.
# "skip action parameter 'rulesets' cannot be used in the phase
# http_request_firewall_custom".
#
# Custom rules skip *later phases and non-Ruleset-Engine products*; WAF exceptions
# skip *managed rulesets and their rules*. `ruleset: current` is the only option
# common to both.
#
# Phases absent from this map are not checked: skip is not a valid action there at
# all, and CF200 reports that first.
VALID_SKIP_PARAMS_BY_PHASE: dict[str, frozenset[str]] = {
    "cloudflare.waf_custom_rules": frozenset({"ruleset", "phase", "phases", "products"}),
    "cloudflare.waf_managed_rules": frozenset({"ruleset", "rulesets", "rules"}),
}

# Parameters Cloudflare is *known* to reject in a phase, either observed from a real
# API response or positively excluded by the docs. CF226 reports these as errors.
#
#   custom/rulesets  observed: HTTP 400 code 20117, "skip action parameter 'rulesets'
#                    cannot be used in the phase http_request_firewall_custom"
#   custom/rules     the phase's parameter set is enumerated in full at
#                    https://developers.cloudflare.com/waf/custom-rules/skip/api-examples/
#                    and `rules` is not in it
#   managed/phase    "this option is only available at the zone level for the
#                    `http_request_firewall_custom` phase"
#                    (https://developers.cloudflare.com/waf/custom-rules/skip/options/)
#
# A parameter in neither map (today: `phases` and `products` in the managed phase) is
# only *absent* from the WAF-exception docs, never observed being rejected. Absence of
# documentation is not proof of rejection, and a live corpus is accept-only so it cannot
# falsify the restrictive direction — so CF226 reports those at WARNING instead, and
# says the parameter may be silently ignored rather than claiming it is invalid.
REJECTED_SKIP_PARAMS_BY_PHASE: dict[str, frozenset[str]] = {
    "cloudflare.waf_custom_rules": frozenset({"rulesets", "rules"}),
    "cloudflare.waf_managed_rules": frozenset({"phase"}),
}

# --- Block action response status codes (400-499) ---

VALID_BLOCK_RESPONSE_STATUS_CODES = frozenset(range(400, 500))

# --- Rate limit valid characteristics ---

VALID_RATE_LIMIT_CHARACTERISTICS = frozenset(
    {
        "cf.colo.id",
        "cf.unique_visitor_id",
        "ip.src",
        "ip.geoip.country",
        "ip.geoip.asnum",
        "ip.src.country",
        "ip.src.asnum",
    }
)
