"""Action and action_parameters validation — Categories C, D, I, J, K, L, N.

Validates that actions are valid for their phase and that action_parameters
match the expected schema.

Error handling convention: structural errors (wrong type, missing required
container) early-return to skip further checks; value errors (bad enum,
missing sub-field) continue so multiple issues are reported at once.
"""

import re
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import Phase

from octorules_cloudflare.linter._constants import MAX_EXPRESSION_LENGTH
from octorules_cloudflare.linter.schemas.actions import (
    ACTION_SCHEMAS,
    MAX_CHARACTERISTICS,
    PHASE_PARAMETER_OVERRIDES,
    VALID_ACTIONS_BY_PHASE,
    VALID_BLOCK_RESPONSE_STATUS_CODES,
    VALID_BROWSER_TTL_MODES,
    VALID_COMPRESSION_ALGORITHMS,
    VALID_CONFIG_SECURITY_LEVELS,
    VALID_EDGE_TTL_MODES,
    VALID_POLISH_VALUES,
    VALID_RATE_LIMIT_CHARACTERISTICS,
    VALID_RATE_LIMIT_PERIODS,
    VALID_REDIRECT_STATUS_CODES,
    VALID_SENSITIVITY_LEVELS,
    VALID_SERVE_ERROR_CONTENT_TYPES,
    VALID_SKIP_PHASES,
    VALID_SKIP_PRODUCTS,
    VALID_SKIP_RULESET_VALUES,
    VALID_SSL_VALUES,
    ZONE_ONLY_SECURITY_LEVELS,
)

# CF409: challenge actions that cannot carry a mitigation duration on
# non-Enterprise plans, and the tiers the restriction applies to.
_CHALLENGE_ACTIONS = frozenset({"managed_challenge", "js_challenge", "challenge"})
_CHALLENGE_TIMEOUT_TIERS = frozenset({"free", "pro", "business"})

# CF448: transform-rule header names accept only these characters
# (https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/).
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# CF447: request headers Cloudflare forbids modifying in transform rules
# (https://developers.cloudflare.com/rules/transform/request-header-modification/).
# Headers commonly used to identify the visitor IP/protocol: their value
# cannot be set/modified (removal is allowed).
_IMMUTABLE_IP_HEADERS = frozenset(
    {"x-forwarded-for", "true-client-ip", "x-real-ip", "x-forwarded-proto"}
)

RULE_IDS = frozenset(
    {
        "CF200",
        "CF201",
        "CF202",
        "CF203",
        "CF204",
        "CF205",
        "CF206",
        "CF207",
        "CF208",
        "CF209",
        "CF210",
        "CF211",
        "CF212",
        "CF213",
        "CF214",
        "CF215",
        "CF216",
        "CF217",
        "CF400",
        "CF401",
        "CF402",
        "CF403",
        "CF404",
        "CF405",
        "CF406",
        "CF407",
        "CF408",
        "CF410",
        "CF411",
        "CF412",
        "CF413",
        "CF414",
        "CF420",
        "CF421",
        "CF422",
        "CF423",
        "CF424",
        "CF430",
        "CF431",
        "CF432",
        "CF440",
        "CF441",
        "CF442",
        "CF443",
        "CF444",
        "CF445",
        "CF446",
        "CF447",
        "CF448",
        "CF450",
        "CF451",
        "CF452",
        "CF218",
        "CF219",
        "CF220",
        "CF221",
        "CF222",
        "CF223",
        "CF224",
        "CF225",
        "CF409",
    }
)

_VALID_HEADER_OPERATIONS = frozenset({"set", "remove", "add"})

# CF224 measures the normalized expression length against
# MAX_EXPRESSION_LENGTH (see _constants.py for the API grounding). A
# stored-list reference (e.g. `ip.src in $my_list`) stays short, which is
# the intended remediation.

# CF223: account-scope marker. Per Cloudflare's deploy-custom-ruleset docs,
# account-level rule expressions "must use parentheses to enclose any custom
# conditions and end your expression with `and cf.zone.plan eq \"ENT\"`".
# We treat the presence of that literal as the YAML-visible signal that the
# rule is intended for account scope (kind=root), where CF rejects skip with
# API error 20016.
_ACCOUNT_SCOPE_MARKER = re.compile(r'cf\.zone\.plan\s+eq\s+"ENT"')


def _check_expression_length(
    rule: dict[str, Any], phase_name: str, ref: str, ctx: LintContext
) -> None:
    """CF224: flag rule expressions exceeding Cloudflare's 4096-char API cap."""
    from octorules.expression import normalize_expression

    expression = rule.get("expression")
    if not isinstance(expression, str):
        return
    length = len(normalize_expression(expression))
    if length > MAX_EXPRESSION_LENGTH:
        ctx.add(
            LintResult(
                rule_id="CF224",
                severity=Severity.ERROR,
                message=(
                    f"Expression is {length} characters, exceeding Cloudflare's"
                    f" {MAX_EXPRESSION_LENGTH}-character API cap (error 20127)."
                    " Move large inline value lists into a stored list and"
                    " reference it (e.g. 'ip.src in $my_list')."
                ),
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )


def lint_actions(rule: dict[str, Any], phase: Phase, ctx: LintContext) -> None:
    """Run all action-related lint checks on a single rule."""
    ref = rule.get("ref", "")
    action = rule.get("action")
    phase_name = phase.friendly_name

    # CF224: expression exceeds Cloudflare's 4096-char API cap. Checked first
    # so it fires regardless of any action-validation early-return below.
    _check_expression_length(rule, phase_name, ref, ctx)

    # CF201: Missing action in phase without default
    if action is None:
        if phase.default_action is None:
            ctx.add(
                LintResult(
                    rule_id="CF201",
                    severity=Severity.ERROR,
                    message="Missing required 'action' (no default for this phase)",
                    phase=phase_name,
                    ref=ref,
                )
            )
            return
        # Use the phase default for parameter validation
        action = phase.default_action

    if not isinstance(action, str):
        ctx.add(
            LintResult(
                rule_id="CF201",
                severity=Severity.ERROR,
                message=f"'action' must be a string (got {type(action).__name__})",
                phase=phase_name,
                ref=ref,
            )
        )
        return

    # CF200: Invalid action for phase
    valid_actions = VALID_ACTIONS_BY_PHASE.get(phase_name)
    if valid_actions and action not in valid_actions:
        ctx.add(
            LintResult(
                rule_id="CF200",
                severity=Severity.ERROR,
                message=(
                    f"Action {action!r} is not valid for phase {phase_name!r}."
                    f" Valid actions: {', '.join(sorted(valid_actions))}"
                ),
                phase=phase_name,
                ref=ref,
                field="action",
            )
        )
        return  # skip parameter validation for invalid action

    # CF223: skip in account-scoped waf_custom_rules is rejected by CF
    # with API error 20016 (kind=root rulesets don't support skip).
    if action == "skip" and phase_name == "waf_custom_rules":
        expression = rule.get("expression", "")
        if isinstance(expression, str) and _ACCOUNT_SCOPE_MARKER.search(expression):
            ctx.add(
                LintResult(
                    rule_id="CF223",
                    severity=Severity.ERROR,
                    message=(
                        "'skip' action is not valid in account-scoped"
                        " waf_custom_rules (Cloudflare API error 20016)."
                        " Use a zone-level YAML or rewrite as"
                        " 'block' / 'managed_challenge'."
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action",
                )
            )

    action_params = rule.get("action_parameters")
    schema = ACTION_SCHEMAS.get(action)

    # CF202: Missing required action_parameters
    if schema and schema.requires_parameters and action_params is None:
        ctx.add(
            LintResult(
                rule_id="CF202",
                severity=Severity.ERROR,
                message=f"Action {action!r} requires 'action_parameters'",
                phase=phase_name,
                ref=ref,
                field="action_parameters",
            )
        )
        return

    # Rate-limit validation runs against the rule-level `ratelimit:` block,
    # which is independent of action_parameters. Dispatched here (before the
    # action_params-is-None early return) so a rule with `ratelimit:` set
    # and no `action_parameters` is still linted.
    if phase_name == "rate_limiting_rules" and action not in ("execute", "skip"):
        _lint_rate_limit_params(rule.get("ratelimit"), action, phase_name, ref, ctx)

    if action_params is None:
        return

    # CF204: action_parameters type check (must be a dict/mapping)
    if not isinstance(action_params, dict):
        ctx.add(
            LintResult(
                rule_id="CF204",
                severity=Severity.ERROR,
                message=(
                    f"'action_parameters' must be a mapping, got {type(action_params).__name__}"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters",
            )
        )
        return

    # CF203: Unknown action_parameters keys
    # Use phase-specific override when available (narrows the action schema).
    if schema and schema.allowed_parameter_keys:
        allowed = PHASE_PARAMETER_OVERRIDES.get(phase_name, schema.allowed_parameter_keys)
        unknown = set(action_params.keys()) - allowed
        for key in sorted(unknown):
            ctx.add(
                LintResult(
                    rule_id="CF203",
                    severity=Severity.WARNING,
                    message=(
                        f"Unknown action_parameters key {key!r}"
                        f" for action {action!r} in phase {phase_name!r}"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field=f"action_parameters.{key}",
                )
            )

    # CF208: action_parameters on action that doesn't need them
    if schema and not schema.requires_parameters and not schema.allowed_parameter_keys:
        if action_params:
            ctx.add(
                LintResult(
                    rule_id="CF208",
                    severity=Severity.WARNING,
                    message=(f"Action {action!r} does not accept action_parameters"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters",
                )
            )

    # Phase-specific validation (rate_limiting_rules is handled earlier
    # since `ratelimit:` is a rule-level field independent of action_parameters).
    if phase_name in ("redirect_rules", "bulk_redirect_rules"):
        _lint_redirect_params(action_params, phase_name, ref, ctx)
    elif phase_name == "cache_rules":
        _lint_cache_params(action_params, phase_name, ref, ctx)
    elif phase_name == "config_rules":
        _lint_config_params(action_params, phase_name, ref, ctx)
    elif phase_name == "origin_rules":
        _lint_origin_params(action_params, phase_name, ref, ctx)
    elif phase_name in ("url_rewrite_rules", "request_header_rules", "response_header_rules"):
        _lint_transform_params(action_params, phase_name, ref, ctx)
    elif phase_name == "custom_error_rules":
        _lint_serve_error_params(action_params, phase_name, ref, ctx)
    elif phase_name == "compression_rules":
        _lint_compress_response_params(action_params, phase_name, ref, ctx)

    # Action-specific validation (cross-phase)
    if action == "execute":
        _lint_execute_params(action_params, phase_name, ref, ctx)
    elif action == "skip":
        _lint_skip_params(action_params, phase_name, ref, ctx)
    elif action == "block":
        _lint_block_response_params(action_params, phase_name, ref, ctx)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _check_enum(
    value: object,
    valid: frozenset,
    *,
    rule_id: str,
    label: str,
    field_path: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> bool:
    """Emit an error if *value* is not in *valid*. Returns True if valid."""
    if value in valid:
        return True
    display = repr(value) if isinstance(value, str) else str(value)
    valid_str = ", ".join(sorted(str(v) for v in valid))
    ctx.add(
        LintResult(
            rule_id=rule_id,
            severity=Severity.ERROR,
            message=f"Invalid {label} {display}. Must be one of: {valid_str}",
            phase=phase_name,
            ref=ref,
            field=field_path,
        )
    )
    return False


def _check_value_expression_conflict(
    d: dict,
    context_label: str,
    phase_name: str,
    ref: str,
    field_path: str,
    ctx: LintContext,
) -> None:
    """CF207: flag when both 'value' and 'expression' are specified."""
    if "value" in d and "expression" in d:
        ctx.add(
            LintResult(
                rule_id="CF207",
                severity=Severity.ERROR,
                message=(f"Cannot specify both 'value' and 'expression' in {context_label}"),
                phase=phase_name,
                ref=ref,
                field=field_path,
            )
        )


def _lint_ttl(
    ttl: dict,
    ttl_name: str,
    valid_modes: frozenset[str],
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> None:
    """Validate a TTL dict (shared for edge_ttl and browser_ttl)."""
    mode = ttl.get("mode")
    if mode is not None and not isinstance(mode, str):
        ctx.add(
            LintResult(
                rule_id="CF410",
                severity=Severity.ERROR,
                message=(f"{ttl_name} mode must be a string, got {type(mode).__name__}"),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.mode",
            )
        )
        return
    if isinstance(mode, str) and mode not in valid_modes:
        ctx.add(
            LintResult(
                rule_id="CF410",
                severity=Severity.ERROR,
                message=f"Invalid {ttl_name} mode {mode!r}",
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.mode",
                suggestion=f"Valid: {sorted(valid_modes)}",
            )
        )
    # CF411: override_origin requires default TTL
    if mode == "override_origin" and "default" not in ttl:
        ctx.add(
            LintResult(
                rule_id="CF411",
                severity=Severity.ERROR,
                message=(f"{ttl_name} mode 'override_origin' requires a 'default' TTL value"),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}",
            )
        )
    # CF412: negative TTL
    default_val = ttl.get("default")
    if isinstance(default_val, (int, float)) and default_val < 0:
        ctx.add(
            LintResult(
                rule_id="CF412",
                severity=Severity.ERROR,
                message=f"Negative {ttl_name} value: {default_val}",
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.default",
            )
        )

    # CF414: TTL exceeds maximum (1 year)
    _MAX_TTL = 31536000  # 1 year in seconds
    if isinstance(default_val, (int, float)) and default_val > _MAX_TTL:
        ctx.add(
            LintResult(
                rule_id="CF414",
                severity=Severity.WARNING,
                message=(
                    f"{ttl_name} value ({default_val}s) exceeds maximum ({_MAX_TTL}s / 1 year)"
                ),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.default",
            )
        )


# ---------------------------------------------------------------------------
# Phase-specific validators
# ---------------------------------------------------------------------------
def _lint_redirect_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate redirect action_parameters (CF430, CF431, CF206, CF207)."""
    from_value = params.get("from_value")
    if not isinstance(from_value, dict):
        return

    target_url = from_value.get("target_url")
    if target_url is None:
        # CF431
        ctx.add(
            LintResult(
                rule_id="CF431",
                severity=Severity.ERROR,
                message="Missing 'target_url' in redirect from_value",
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.target_url",
            )
        )
        return

    if isinstance(target_url, dict):
        _check_value_expression_conflict(
            target_url,
            "redirect target_url",
            phase_name,
            ref,
            "action_parameters.from_value.target_url",
            ctx,
        )

        # CF432: target_url value should be a valid URL
        url_value = target_url.get("value")
        if isinstance(url_value, str) and not (
            url_value.startswith("http://")
            or url_value.startswith("https://")
            or url_value.startswith("/")
        ):
            ctx.add(
                LintResult(
                    rule_id="CF432",
                    severity=Severity.WARNING,
                    message=(
                        f"Redirect target_url {url_value!r} does not start with"
                        " 'http://', 'https://', or '/'"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.from_value.target_url.value",
                )
            )

    status_code = from_value.get("status_code")
    if status_code is None:
        # CF206
        ctx.add(
            LintResult(
                rule_id="CF206",
                severity=Severity.ERROR,
                message="Missing required 'status_code' in redirect from_value",
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.status_code",
            )
        )
    elif isinstance(status_code, int):
        # CF430
        _check_enum(
            status_code,
            VALID_REDIRECT_STATUS_CODES,
            rule_id="CF430",
            label="redirect status code",
            field_path="action_parameters.from_value.status_code",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )
    elif not isinstance(status_code, int):
        # CF205: status_code must be an integer
        ctx.add(
            LintResult(
                rule_id="CF205",
                severity=Severity.ERROR,
                message=(f"'status_code' must be an integer, got {type(status_code).__name__}"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.status_code",
            )
        )


def _lint_cache_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate cache action_parameters (CF410-CF413)."""
    edge_ttl = params.get("edge_ttl")
    if isinstance(edge_ttl, dict):
        _lint_ttl(
            edge_ttl,
            "edge_ttl",
            VALID_EDGE_TTL_MODES,
            phase_name,
            ref,
            ctx,
        )

    browser_ttl = params.get("browser_ttl")
    if isinstance(browser_ttl, dict):
        _lint_ttl(
            browser_ttl,
            "browser_ttl",
            VALID_BROWSER_TTL_MODES,
            phase_name,
            ref,
            ctx,
        )

    # CF413: conflicting bypass and eligible
    cache_val = params.get("cache")
    if cache_val is False:
        if edge_ttl is not None or browser_ttl is not None:
            ctx.add(
                LintResult(
                    rule_id="CF413",
                    severity=Severity.WARNING,
                    message=("TTL settings have no effect when cache is disabled (cache: false)"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters",
                )
            )


def _lint_config_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate config action_parameters (CF420-CF423)."""
    security_level = params.get("security_level")
    if isinstance(security_level, str):
        if security_level in ZONE_ONLY_SECURITY_LEVELS:
            # CF420: graduated levels are a zone-wide baseline only — the
            # Configuration Rules API rejects them. Emit a targeted message
            # instead of the generic "must be one of" so the distinction is
            # clear (these are real security levels, just not valid here).
            ctx.add(
                LintResult(
                    rule_id="CF420",
                    severity=Severity.ERROR,
                    message=(
                        f"security_level {security_level!r} is not valid in a Configuration"
                        " Rule. Graduated levels (low, medium, high) can only be set"
                        " zone-wide; Configuration Rules accept only: essentially_off, off,"
                        " under_attack"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.security_level",
                )
            )
        elif not _check_enum(
            security_level,
            VALID_CONFIG_SECURITY_LEVELS,
            rule_id="CF420",
            label="security_level",
            field_path="action_parameters.security_level",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        ):
            pass
        elif security_level == "off":
            ctx.add(
                LintResult(
                    rule_id="CF423",
                    severity=Severity.WARNING,
                    message=("Security level set to 'off' — this disables all security features"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.security_level",
                )
            )

    ssl = params.get("ssl")
    if ssl is not None and not isinstance(ssl, str):
        # CF421: ssl must be a string
        ctx.add(
            LintResult(
                rule_id="CF421",
                severity=Severity.ERROR,
                message=f"'ssl' must be a string, got {type(ssl).__name__}",
                phase=phase_name,
                ref=ref,
                field="action_parameters.ssl",
            )
        )
    elif isinstance(ssl, str) and not _check_enum(
        ssl,
        VALID_SSL_VALUES,
        rule_id="CF421",
        label="ssl value",
        field_path="action_parameters.ssl",
        phase_name=phase_name,
        ref=ref,
        ctx=ctx,
    ):
        pass
    elif ssl == "off":
        # CF424: SSL off security warning
        ctx.add(
            LintResult(
                rule_id="CF424",
                severity=Severity.WARNING,
                message=(
                    "SSL set to 'off' — traffic between Cloudflare and origin will be unencrypted"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.ssl",
            )
        )

    polish = params.get("polish")
    if isinstance(polish, str):
        _check_enum(
            polish,
            VALID_POLISH_VALUES,
            rule_id="CF422",
            label="polish value",
            field_path="action_parameters.polish",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )


def _lint_rate_limit_params(
    ratelimit: object, action: object, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Validate the rule-level ``ratelimit:`` block (CF400-CF408, CF213, CF406, CF409).

    The Cloudflare API places rate-limit configuration in a top-level
    ``ratelimit`` rule field (sibling of ``action_parameters``) — see
    cloudflare-python ``BlockRule.ratelimit`` / ``Ratelimit`` typed
    params. A missing or non-dict block is treated as empty so the
    "missing threshold" / "missing characteristics" findings still fire.
    """
    params: dict = ratelimit if isinstance(ratelimit, dict) else {}

    period = params.get("period")
    if isinstance(period, int):
        _check_enum(
            period,
            VALID_RATE_LIMIT_PERIODS,
            rule_id="CF400",
            label="rate limiting period",
            field_path="ratelimit.period",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )

    # CF402: missing threshold
    if "requests_per_period" not in params and "score_per_period" not in params:
        ctx.add(
            LintResult(
                rule_id="CF402",
                severity=Severity.ERROR,
                message=(
                    "Missing rate limit threshold:"
                    " needs 'requests_per_period' or 'score_per_period'"
                ),
                phase=phase_name,
                ref=ref,
                field="ratelimit",
            )
        )

    # CF407: requests_per_period range (1-10,000,000)
    rpp = params.get("requests_per_period")
    if isinstance(rpp, int) and not isinstance(rpp, bool):
        if rpp < 1 or rpp > 10_000_000:
            ctx.add(
                LintResult(
                    rule_id="CF407",
                    severity=Severity.ERROR,
                    message=(
                        f"requests_per_period ({rpp}) is outside the valid range (1-10,000,000)"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="ratelimit.requests_per_period",
                )
            )

    # CF408: score_per_period range (1-10,000,000)
    spp = params.get("score_per_period")
    if isinstance(spp, int) and not isinstance(spp, bool):
        if spp < 1 or spp > 10_000_000:
            ctx.add(
                LintResult(
                    rule_id="CF408",
                    severity=Severity.ERROR,
                    message=(f"score_per_period ({spp}) is outside the valid range (1-10,000,000)"),
                    phase=phase_name,
                    ref=ref,
                    field="ratelimit.score_per_period",
                )
            )

    # CF401: missing characteristics
    characteristics = params.get("characteristics")
    if characteristics is None:
        ctx.add(
            LintResult(
                rule_id="CF401",
                severity=Severity.WARNING,
                message=("Missing 'characteristics' — rate limit will apply globally"),
                phase=phase_name,
                ref=ref,
                field="ratelimit.characteristics",
            )
        )

    # CF213: validate characteristics values
    if isinstance(characteristics, list):
        for char_val in characteristics:
            if not isinstance(char_val, str):
                continue
            # Header references like "http.request.headers[\"x-api-key\"]" are valid
            if char_val.startswith("http.request.headers["):
                continue
            if char_val not in VALID_RATE_LIMIT_CHARACTERISTICS:
                ctx.add(
                    LintResult(
                        rule_id="CF213",
                        severity=Severity.ERROR,
                        message=f"Unknown rate limit characteristic {char_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="ratelimit.characteristics",
                        suggestion=f"Valid: {sorted(VALID_RATE_LIMIT_CHARACTERISTICS)}",
                    )
                )

        # CF406: too many characteristics for plan tier
        max_chars = MAX_CHARACTERISTICS.get(ctx.plan_tier)
        if max_chars is not None and len(characteristics) > max_chars:
            ctx.add(
                LintResult(
                    rule_id="CF406",
                    severity=Severity.ERROR,
                    message=(
                        f"Too many rate limit characteristics ({len(characteristics)})"
                        f" for {ctx.plan_tier!r} plan (max {max_chars})"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="ratelimit.characteristics",
                )
            )

        # CF225: 'ip.src' (IP) and 'cf.unique_visitor_id' (IP with NAT support)
        # are mutually exclusive in a single rate-limiting rule; Cloudflare
        # rejects a rule that lists both.
        if "ip.src" in characteristics and "cf.unique_visitor_id" in characteristics:
            ctx.add(
                LintResult(
                    rule_id="CF225",
                    severity=Severity.ERROR,
                    message=(
                        "Rate limit characteristics 'ip.src' and 'cf.unique_visitor_id'"
                        " are mutually exclusive (IP vs IP with NAT support)"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="ratelimit.characteristics",
                )
            )

    # CF403: mitigation_timeout > period
    mitigation_timeout = params.get("mitigation_timeout")
    if (
        isinstance(mitigation_timeout, int)
        and isinstance(period, int)
        and mitigation_timeout > period
    ):
        ctx.add(
            LintResult(
                rule_id="CF403",
                severity=Severity.WARNING,
                message=(f"mitigation_timeout ({mitigation_timeout}s) exceeds period ({period}s)"),
                phase=phase_name,
                ref=ref,
                field="ratelimit.mitigation_timeout",
            )
        )

    # CF409: Free/Pro/Business plans cannot select a duration with a challenge
    # action — mitigation_timeout must be 0 when the action is managed_challenge,
    # js_challenge, or challenge. Enterprise may use any value. Only fires on a
    # known non-Enterprise tier (mirrors CF406's tier gating).
    if (
        ctx.plan_tier in _CHALLENGE_TIMEOUT_TIERS
        and action in _CHALLENGE_ACTIONS
        and isinstance(mitigation_timeout, int)
        and not isinstance(mitigation_timeout, bool)
        and mitigation_timeout != 0
    ):
        ctx.add(
            LintResult(
                rule_id="CF409",
                severity=Severity.ERROR,
                message=(
                    f"mitigation_timeout must be 0 with a challenge action ({action})"
                    f" on the {ctx.plan_tier!r} plan; only Enterprise can set a duration"
                ),
                phase=phase_name,
                ref=ref,
                field="ratelimit.mitigation_timeout",
            )
        )

    # CF404: counting_expression must be a string
    counting_expr = params.get("counting_expression")
    if counting_expr is not None and not isinstance(counting_expr, str):
        ctx.add(
            LintResult(
                rule_id="CF404",
                severity=Severity.ERROR,
                message="'counting_expression' must be a string",
                phase=phase_name,
                ref=ref,
                field="ratelimit.counting_expression",
            )
        )

    # CF405: lint counting_expression content
    if isinstance(counting_expr, str) and counting_expr.strip():
        from octorules.expression import normalize_expression

        from octorules_cloudflare.linter.expression_bridge import parse_expression

        counting_expr = normalize_expression(counting_expr)
        ce_info = parse_expression(counting_expr)
        if ce_info.parse_error:
            ctx.add(
                LintResult(
                    rule_id="CF405",
                    severity=Severity.WARNING,
                    message=(f"Invalid counting_expression: {ce_info.parse_error}"),
                    phase=phase_name,
                    ref=ref,
                    field="ratelimit.counting_expression",
                )
            )


def _lint_origin_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate origin rule action_parameters (CF450, CF451, CF452)."""
    origin = params.get("origin")
    if isinstance(origin, dict):
        port = origin.get("port")
        if port is not None and (not isinstance(port, int) or isinstance(port, bool)):
            ctx.add(
                LintResult(
                    rule_id="CF450",
                    severity=Severity.ERROR,
                    message=f"Port must be an integer, got {type(port).__name__}",
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.origin.port",
                )
            )
        elif isinstance(port, int) and (port < 1 or port > 65535):
            ctx.add(
                LintResult(
                    rule_id="CF450",
                    severity=Severity.ERROR,
                    message=f"Port number {port} out of range (1-65535)",
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.origin.port",
                )
            )

        # CF451: Origin weight must be between 0.0 and 1.0
        weight = origin.get("weight")
        if isinstance(weight, (int, float)) and not isinstance(weight, bool):
            if weight < 0.0 or weight > 1.0:
                ctx.add(
                    LintResult(
                        rule_id="CF451",
                        severity=Severity.ERROR,
                        message=(f"Origin weight {weight} is outside the valid range (0.0-1.0)"),
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.origin.weight",
                    )
                )

        # CF452: Origin route must have 'host', or both 'sni' and 'host_header'
        has_host = "host" in origin
        has_sni = "sni" in origin
        has_host_header = "host_header" in origin
        if not has_host and not (has_sni and has_host_header):
            ctx.add(
                LintResult(
                    rule_id="CF452",
                    severity=Severity.ERROR,
                    message=(
                        "Origin route requires 'host' field, or both 'sni' and 'host_header' fields"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.origin",
                )
            )


def _check_restricted_header(
    header_name: str, op: object, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """CF447: Cloudflare forbids modifying certain request headers in transforms.

    Only applies to request-header transforms. The ``cf-``/``x-cf-`` headers
    cannot be touched at all (except removing ``cf-connecting-ip``); ``cookie``
    and the visitor-IP headers cannot be set/modified but can be removed.
    """
    if (
        phase_name != "request_header_rules"
        or not isinstance(op, str)
        or not isinstance(header_name, str)
    ):
        return
    name = header_name.lower()

    if name.startswith("cf-") or name.startswith("x-cf-"):
        if name == "cf-connecting-ip" and op == "remove":
            return
        ctx.add(
            LintResult(
                rule_id="CF447",
                severity=Severity.ERROR,
                message=(
                    f"Header {header_name!r} cannot be modified or removed —"
                    " Cloudflare reserves 'cf-'/'x-cf-' request headers"
                    " (only 'cf-connecting-ip' may be removed)"
                ),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.headers.{header_name}",
            )
        )
        return

    if name == "cookie" and op in ("set", "add"):
        ctx.add(
            LintResult(
                rule_id="CF447",
                severity=Severity.ERROR,
                message=(
                    "The 'cookie' request header cannot be set or modified (it can only be removed)"
                ),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.headers.{header_name}",
            )
        )
        return

    if name in _IMMUTABLE_IP_HEADERS and op in ("set", "add"):
        ctx.add(
            LintResult(
                rule_id="CF447",
                severity=Severity.ERROR,
                message=(
                    f"Header {header_name!r} cannot be modified — Cloudflare"
                    " reserves headers that identify the visitor IP/protocol"
                    " (it can be removed, not set)"
                ),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.headers.{header_name}",
            )
        )


def _lint_transform_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate transform action_parameters (CF440-CF448, CF207)."""
    # Check URI transforms
    uri = params.get("uri")
    if isinstance(uri, dict):
        for component in ("path", "query"):
            comp_val = uri.get(component)
            if isinstance(comp_val, dict):
                _check_value_expression_conflict(
                    comp_val,
                    f"uri.{component} transform",
                    phase_name,
                    ref,
                    f"action_parameters.uri.{component}",
                    ctx,
                )
                # CF444: Lint expression inside URI transform
                _lint_transform_expression(
                    comp_val,
                    f"action_parameters.uri.{component}",
                    phase_name,
                    ref,
                    ctx,
                )

    # Check header transforms
    headers = params.get("headers")
    if isinstance(headers, dict):
        for header_name, header_val in headers.items():
            # CF440: empty or non-string header name
            if not isinstance(header_name, str) or not header_name.strip():
                ctx.add(
                    LintResult(
                        rule_id="CF440",
                        severity=Severity.ERROR,
                        message="Empty or invalid header name in transform",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.headers",
                    )
                )
            # CF448: header name charset (letters, digits, hyphen, underscore)
            elif isinstance(header_name, str) and not _HEADER_NAME_RE.match(header_name):
                ctx.add(
                    LintResult(
                        rule_id="CF448",
                        severity=Severity.ERROR,
                        message=(
                            f"Header name {header_name!r} is invalid: use only letters,"
                            " digits, hyphen, and underscore (^[A-Za-z0-9_-]+$)"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field=f"action_parameters.headers.{header_name}",
                    )
                )
            if isinstance(header_val, dict):
                # CF447: header is one Cloudflare forbids modifying (request only)
                _check_restricted_header(
                    header_name, header_val.get("operation"), phase_name, ref, ctx
                )
                # CF441: missing operation
                if "operation" not in header_val:
                    ctx.add(
                        LintResult(
                            rule_id="CF441",
                            severity=Severity.ERROR,
                            message=(f"Missing 'operation' for header {header_name!r} transform"),
                            phase=phase_name,
                            ref=ref,
                            field=f"action_parameters.headers.{header_name}",
                        )
                    )
                else:
                    # CF442: invalid header transform operation
                    op = header_val["operation"]
                    if isinstance(op, str) and op not in _VALID_HEADER_OPERATIONS:
                        ctx.add(
                            LintResult(
                                rule_id="CF442",
                                severity=Severity.ERROR,
                                message=(
                                    f"Invalid header transform operation {op!r}"
                                    f" for header {header_name!r}"
                                ),
                                phase=phase_name,
                                ref=ref,
                                field=f"action_parameters.headers.{header_name}.operation",
                                suggestion=f"Valid: {sorted(_VALID_HEADER_OPERATIONS)}",
                            )
                        )
                    # CF445: request headers don't support 'add' operation
                    elif (
                        isinstance(op, str) and op == "add" and phase_name == "request_header_rules"
                    ):
                        ctx.add(
                            LintResult(
                                rule_id="CF445",
                                severity=Severity.ERROR,
                                message=(
                                    f"Request header transforms do not support 'add' operation"
                                    f" for header {header_name!r}. Use 'set' instead."
                                ),
                                phase=phase_name,
                                ref=ref,
                                field=f"action_parameters.headers.{header_name}.operation",
                            )
                        )
                    # CF446: remove should not have value or expression
                    elif isinstance(op, str) and op == "remove":
                        if "value" in header_val or "expression" in header_val:
                            ctx.add(
                                LintResult(
                                    rule_id="CF446",
                                    severity=Severity.WARNING,
                                    message=(
                                        f"Header {header_name!r} operation 'remove'"
                                        f" ignores 'value'/'expression' (remove only"
                                        f" needs the header name)"
                                    ),
                                    phase=phase_name,
                                    ref=ref,
                                    field=f"action_parameters.headers.{header_name}",
                                )
                            )
                    # CF443: set/add missing value or expression
                    elif isinstance(op, str) and op in ("set", "add"):
                        if "value" not in header_val and "expression" not in header_val:
                            ctx.add(
                                LintResult(
                                    rule_id="CF443",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"Header {header_name!r} operation {op!r}"
                                        f" requires 'value' or 'expression'"
                                    ),
                                    phase=phase_name,
                                    ref=ref,
                                    field=f"action_parameters.headers.{header_name}",
                                )
                            )
                # CF207: conflicting value and expression
                _check_value_expression_conflict(
                    header_val,
                    f"header {header_name!r} transform",
                    phase_name,
                    ref,
                    f"action_parameters.headers.{header_name}",
                    ctx,
                )
                # CF444: Lint expression inside header transform
                _lint_transform_expression(
                    header_val,
                    f"action_parameters.headers.{header_name}",
                    phase_name,
                    ref,
                    ctx,
                )


def _lint_transform_expression(
    d: dict,
    field_path: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> None:
    """CF444: Lint an expression embedded in transform action_parameters.

    Transform expressions use function-call syntax (e.g. ``concat(...)``,
    ``regex_replace(...)``).  Wirefilter only understands operator form for
    some of these, so we suppress parse errors that are caused by known
    function-call patterns that Cloudflare actually accepts.
    """
    import re

    expr = d.get("expression")
    if not isinstance(expr, str) or not expr.strip():
        return

    from octorules_cloudflare.linter.expression_bridge import parse_expression

    info = parse_expression(expr, phase=phase_name, expect_parse_error=True)
    if info.parse_error:
        # Suppress known false positives: transform expressions routinely use
        # function-call syntax (regex_replace, wildcard_replace, concat,
        # lower, upper, starts_with, ends_with, etc.) that wirefilter rejects.
        _TRANSFORM_FUNCTIONS = (
            r"\b(?:regex_replace|wildcard_replace|concat|lower|upper|"
            r"to_string|substring|remove_bytes|remove_query_args|url_decode|len|"
            r"starts_with|ends_with|contains|sha256|sha512|hmac|"
            r"encode_base64|decode_base64|uuidv4|split|join|"
            r"http\.request\.uri\.path|http\.request\.uri)\s*\("
        )
        if re.search(_TRANSFORM_FUNCTIONS, expr):
            return

        ctx.add(
            LintResult(
                rule_id="CF444",
                severity=Severity.WARNING,
                message=(f"Expression parse error in {field_path}: {info.parse_error}"),
                phase=phase_name,
                ref=ref,
                field=f"{field_path}.expression",
            )
        )


def _lint_serve_error_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate custom error action_parameters (CF205, CF209)."""
    status_code = params.get("status_code")
    if status_code is not None and isinstance(status_code, int):
        if status_code < 400 or status_code > 599:
            ctx.add(
                LintResult(
                    rule_id="CF205",
                    severity=Severity.ERROR,
                    message=(f"Custom error status_code {status_code} must be 400-599"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.status_code",
                )
            )

    # CF221: serve_error content_type validation
    content_type = params.get("content_type")
    if isinstance(content_type, str):
        _check_enum(
            content_type,
            VALID_SERVE_ERROR_CONTENT_TYPES,
            rule_id="CF221",
            label="serve_error content_type",
            field_path="action_parameters.content_type",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )

    # CF209: content size limit (~10KB)
    content = params.get("content")
    if isinstance(content, str):
        content_size = len(content.encode("utf-8"))
        if content_size > 10240:
            ctx.add(
                LintResult(
                    rule_id="CF209",
                    severity=Severity.ERROR,
                    message=(
                        f"serve_error content is {content_size:,} bytes (exceeds 10,240 byte limit)"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.content",
                )
            )


_EXECUTE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _lint_execute_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate execute action_parameters (CF215, CF216)."""
    # CF215: Missing id
    ruleset_id = params.get("id")
    if ruleset_id is None:
        ctx.add(
            LintResult(
                rule_id="CF215",
                severity=Severity.ERROR,
                message="Action 'execute' requires 'id' in action_parameters",
                phase=phase_name,
                ref=ref,
                field="action_parameters.id",
            )
        )
        return

    # CF216: Invalid id format (must be 32-char hex)
    if isinstance(ruleset_id, str) and not _EXECUTE_ID_PATTERN.match(ruleset_id):
        ctx.add(
            LintResult(
                rule_id="CF216",
                severity=Severity.WARNING,
                message=(
                    f"Execute ruleset id {ruleset_id!r} is not a valid 32-character hex string"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.id",
            )
        )

    # CF218: Validate overrides.rules structure
    # CF220: Validate sensitivity_level in overrides
    overrides = params.get("overrides")
    if isinstance(overrides, dict):
        # CF220: top-level sensitivity_level in overrides
        sl = overrides.get("sensitivity_level")
        if isinstance(sl, str):
            _check_enum(
                sl,
                VALID_SENSITIVITY_LEVELS,
                rule_id="CF220",
                label="sensitivity_level",
                field_path="action_parameters.overrides.sensitivity_level",
                phase_name=phase_name,
                ref=ref,
                ctx=ctx,
            )

        rules = overrides.get("rules")
        if isinstance(rules, list):
            for i, entry in enumerate(rules):
                if not isinstance(entry, dict):
                    continue
                rule_id = entry.get("id")
                if not isinstance(rule_id, str) or not rule_id.strip():
                    ctx.add(
                        LintResult(
                            rule_id="CF218",
                            severity=Severity.ERROR,
                            message=(
                                f"Execute overrides rule at index {i} is missing"
                                " a valid 'id' (must be a non-empty string)"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field=f"action_parameters.overrides.rules[{i}].id",
                        )
                    )
                # CF220: per-rule sensitivity_level in overrides
                rule_sl = entry.get("sensitivity_level")
                if isinstance(rule_sl, str):
                    _check_enum(
                        rule_sl,
                        VALID_SENSITIVITY_LEVELS,
                        rule_id="CF220",
                        label="sensitivity_level",
                        field_path=f"action_parameters.overrides.rules[{i}].sensitivity_level",
                        phase_name=phase_name,
                        ref=ref,
                        ctx=ctx,
                    )


def _lint_skip_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate skip action_parameters (CF210, CF211, CF222)."""
    # CF222: validate ruleset value
    ruleset = params.get("ruleset")
    if isinstance(ruleset, str):
        _check_enum(
            ruleset,
            VALID_SKIP_RULESET_VALUES,
            rule_id="CF222",
            label="skip ruleset value",
            field_path="action_parameters.ruleset",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )

    # CF210: validate phases values
    phases = params.get("phases")
    if isinstance(phases, list):
        for phase_val in phases:
            if isinstance(phase_val, str) and phase_val not in VALID_SKIP_PHASES:
                ctx.add(
                    LintResult(
                        rule_id="CF210",
                        severity=Severity.ERROR,
                        message=f"Invalid skip phase {phase_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.phases",
                        suggestion=f"Valid: {sorted(VALID_SKIP_PHASES)}",
                    )
                )

    # CF219: validate rulesets values (each must be a non-empty string)
    rulesets = params.get("rulesets")
    if isinstance(rulesets, list):
        for ruleset_val in rulesets:
            if not isinstance(ruleset_val, str) or not ruleset_val.strip():
                ctx.add(
                    LintResult(
                        rule_id="CF219",
                        severity=Severity.WARNING,
                        message="Skip action references empty or invalid ruleset ID",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.rulesets",
                    )
                )

    # CF211: validate products values
    products = params.get("products")
    if isinstance(products, list):
        for product_val in products:
            if isinstance(product_val, str) and product_val not in VALID_SKIP_PRODUCTS:
                ctx.add(
                    LintResult(
                        rule_id="CF211",
                        severity=Severity.ERROR,
                        message=f"Invalid skip product {product_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.products",
                        suggestion=f"Valid: {sorted(VALID_SKIP_PRODUCTS)}",
                    )
                )


def _lint_compress_response_params(
    params: dict, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Validate compress_response action_parameters (CF212, CF217)."""
    algorithms = params.get("algorithms")
    if isinstance(algorithms, list):
        _TERMINAL_ALGORITHMS = frozenset({"none", "auto"})
        for i, algo in enumerate(algorithms):
            algo_name = algo.get("name") if isinstance(algo, dict) else algo
            if isinstance(algo_name, str):
                _check_enum(
                    algo_name,
                    VALID_COMPRESSION_ALGORITHMS,
                    rule_id="CF212",
                    label="compression algorithm",
                    field_path="action_parameters.algorithms",
                    phase_name=phase_name,
                    ref=ref,
                    ctx=ctx,
                )
            # CF217: Terminal algorithm must be last
            if (
                isinstance(algo_name, str)
                and algo_name in _TERMINAL_ALGORITHMS
                and i < len(algorithms) - 1
            ):
                ctx.add(
                    LintResult(
                        rule_id="CF217",
                        severity=Severity.WARNING,
                        message=(
                            f"Compression algorithm {algo_name!r} must be the last item"
                            " in the algorithms list"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.algorithms",
                    )
                )


def _lint_block_response_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate block action response parameters (CF214)."""
    response = params.get("response")
    if not isinstance(response, dict):
        return

    # CF214: Invalid block response status_code (must be 400-499)
    status_code = response.get("status_code")
    if status_code is not None and isinstance(status_code, int):
        if status_code not in VALID_BLOCK_RESPONSE_STATUS_CODES:
            ctx.add(
                LintResult(
                    rule_id="CF214",
                    severity=Severity.ERROR,
                    message=(f"Block response status_code {status_code} must be 400-499"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.response.status_code",
                )
            )

    # CF214: content_type must be a string
    content_type = response.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        ctx.add(
            LintResult(
                rule_id="CF214",
                severity=Severity.ERROR,
                message=(
                    f"Block response content_type must be a string,"
                    f" got {type(content_type).__name__}"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.response.content_type",
            )
        )

    # CF214: content must be a string
    content = response.get("content")
    if content is not None and not isinstance(content, str):
        ctx.add(
            LintResult(
                rule_id="CF214",
                severity=Severity.ERROR,
                message=(f"Block response content must be a string, got {type(content).__name__}"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.response.content",
            )
        )
