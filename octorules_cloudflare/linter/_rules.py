"""Cloudflare lint rule definitions — all CF-specific RuleMeta instances."""

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

# Category A — Parse / Syntax Errors
CF001 = RuleMeta("CF001", "parse", "Expression parse error (wirefilter)", Severity.WARNING)
CF002 = RuleMeta("CF002", "parse", "Expression nesting depth exceeds 100 levels", Severity.WARNING)

# Category M — Structural / Rule-Level Checks
CF003 = RuleMeta("CF003", "structure", "Rule is missing required 'ref' field", Severity.ERROR)
CF004 = RuleMeta(
    "CF004", "structure", "Rule is missing required 'expression' field", Severity.ERROR
)
CF005 = RuleMeta("CF005", "structure", "Duplicate ref within phase", Severity.ERROR)
CF006 = RuleMeta(
    "CF006", "structure", "Invalid 'ref' type (must be non-empty string)", Severity.ERROR
)
CF007 = RuleMeta(
    "CF007", "structure", "Invalid 'expression' type (must be non-empty string)", Severity.ERROR
)
CF008 = RuleMeta("CF008", "structure", "Invalid 'enabled' type (must be boolean)", Severity.ERROR)
CF009 = RuleMeta("CF009", "structure", "Unknown top-level phase key", Severity.WARNING)
CF010 = RuleMeta("CF010", "structure", "Deprecated phase name", Severity.WARNING)
CF011 = RuleMeta("CF011", "structure", "Description exceeds 500 characters", Severity.WARNING)
CF012 = RuleMeta("CF012", "structure", "Phase value is not a list", Severity.ERROR)
CF013 = RuleMeta("CF013", "structure", "Rule entry is not a dict", Severity.ERROR)
CF014 = RuleMeta(
    "CF014",
    "structure",
    "Cloudflare phase identifier used instead of friendly name",
    Severity.WARNING,
)
CF015 = RuleMeta(
    "CF015", "structure", "Expression is always true (catch-all rule)", Severity.WARNING
)
CF016 = RuleMeta(
    "CF016", "structure", "Expression is always false (rule never matches)", Severity.WARNING
)
CF017 = RuleMeta("CF017", "structure", "Expression exceeds 4,096 character limit", Severity.ERROR)
CF018 = RuleMeta("CF018", "structure", "Rule is disabled (enabled: false)", Severity.INFO)

# Category C — Action Validation
CF200 = RuleMeta("CF200", "action", "Invalid action for this phase", Severity.ERROR)
CF201 = RuleMeta(
    "CF201", "action", "Missing required action for phase without default", Severity.ERROR
)
CF202 = RuleMeta("CF202", "action", "Missing required action_parameters", Severity.ERROR)
CF203 = RuleMeta("CF203", "action", "Unknown action_parameters key", Severity.WARNING)
CF204 = RuleMeta(
    "CF204", "action", "Invalid action_parameters type (must be mapping)", Severity.ERROR
)
CF205 = RuleMeta("CF205", "action", "Invalid status_code type or value", Severity.ERROR)
CF206 = RuleMeta("CF206", "action", "Missing required status_code for redirect", Severity.ERROR)
CF207 = RuleMeta(
    "CF207", "action", "Conflicting static value and dynamic expression", Severity.ERROR
)
CF208 = RuleMeta(
    "CF208", "action", "Unnecessary action_parameters for this action", Severity.WARNING
)
CF209 = RuleMeta("CF209", "action", "serve_error content exceeds 10KB limit", Severity.ERROR)
CF210 = RuleMeta("CF210", "action", "Invalid skip phases value", Severity.WARNING)
CF211 = RuleMeta("CF211", "action", "Invalid skip products value", Severity.WARNING)
CF212 = RuleMeta("CF212", "action", "Invalid compress_response algorithm", Severity.ERROR)
CF213 = RuleMeta("CF213", "action", "Invalid rate limit characteristic", Severity.WARNING)
CF214 = RuleMeta("CF214", "action", "Invalid block response parameter", Severity.ERROR)
CF215 = RuleMeta("CF215", "action", "Missing execute ruleset id", Severity.ERROR)
CF216 = RuleMeta("CF216", "action", "Invalid execute ruleset id format", Severity.WARNING)
CF217 = RuleMeta("CF217", "action", "Terminal compression algorithm must be last", Severity.WARNING)
CF218 = RuleMeta("CF218", "action", "Invalid execute overrides structure", Severity.ERROR)
CF219 = RuleMeta("CF219", "action", "Skip action references empty ruleset ID", Severity.WARNING)

# Category D — Rate Limiting Specific
CF400 = RuleMeta("CF400", "rate_limit", "Invalid rate limiting period", Severity.ERROR)
CF401 = RuleMeta("CF401", "rate_limit", "Missing rate limiting characteristics", Severity.WARNING)
CF402 = RuleMeta("CF402", "rate_limit", "Missing requests_per_period threshold", Severity.ERROR)
CF403 = RuleMeta("CF403", "rate_limit", "mitigation_timeout exceeds period", Severity.WARNING)
CF404 = RuleMeta("CF404", "rate_limit", "Invalid counting_expression", Severity.ERROR)
CF405 = RuleMeta("CF405", "rate_limit", "Invalid counting_expression content", Severity.WARNING)
CF406 = RuleMeta(
    "CF406", "rate_limit", "Too many rate limit characteristics for plan tier", Severity.ERROR
)
CF407 = RuleMeta("CF407", "rate_limit", "requests_per_period outside valid range", Severity.ERROR)

# Category I — Cache Rule Specific
CF410 = RuleMeta("CF410", "cache", "Invalid TTL mode value", Severity.ERROR)
CF411 = RuleMeta("CF411", "cache", "Missing TTL with override mode", Severity.ERROR)
CF412 = RuleMeta("CF412", "cache", "Negative TTL value", Severity.ERROR)
CF413 = RuleMeta("CF413", "cache", "Conflicting bypass and eligible settings", Severity.WARNING)
CF414 = RuleMeta("CF414", "cache", "Cache TTL exceeds maximum (1 year)", Severity.WARNING)

# Category J — Config Rule Specific
CF420 = RuleMeta("CF420", "config", "Invalid security_level value", Severity.ERROR)
CF421 = RuleMeta("CF421", "config", "Invalid ssl value", Severity.ERROR)
CF422 = RuleMeta("CF422", "config", "Invalid polish value", Severity.ERROR)
CF423 = RuleMeta(
    "CF423", "config", "Security warning: security_level set to 'off'", Severity.WARNING
)
CF424 = RuleMeta("CF424", "config", "Security warning: SSL set to 'off'", Severity.WARNING)

# Category K — Redirect Rule Specific
CF430 = RuleMeta("CF430", "redirect", "Invalid redirect status code", Severity.ERROR)
CF431 = RuleMeta("CF431", "redirect", "Missing target_url in redirect", Severity.ERROR)
CF432 = RuleMeta("CF432", "redirect", "Redirect target_url is not a valid URL", Severity.WARNING)

# Category L — Transform Rule Specific
CF440 = RuleMeta("CF440", "transform", "Empty header name in transform", Severity.ERROR)
CF441 = RuleMeta("CF441", "transform", "Missing operation in header transform", Severity.ERROR)
CF442 = RuleMeta("CF442", "transform", "Invalid header transform operation", Severity.ERROR)
CF443 = RuleMeta(
    "CF443", "transform", "Header set/add operation missing value or expression", Severity.ERROR
)
CF444 = RuleMeta(
    "CF444", "transform", "Expression parse error in transform action_parameters", Severity.WARNING
)
CF445 = RuleMeta(
    "CF445", "transform", "Request header transforms do not support 'add' operation", Severity.ERROR
)

# Category N — Origin Rule Specific
CF450 = RuleMeta("CF450", "origin", "Port number out of range (1-65535)", Severity.ERROR)
CF451 = RuleMeta("CF451", "action", "Origin weight outside valid range (0.0-1.0)", Severity.ERROR)
CF452 = RuleMeta("CF452", "action", "Origin route missing required fields", Severity.ERROR)

# Category B — Phase Restrictions
CF019 = RuleMeta(
    "CF019", "phase", "Response field used in request phase expression", Severity.WARNING
)
CF020 = RuleMeta(
    "CF020", "phase", "Request body field used in phase without body access", Severity.WARNING
)
CF021 = RuleMeta(
    "CF021", "phase", "Field requires a plan tier not currently configured", Severity.WARNING
)

# Category H — Plan/Entitlement Checks
CF500 = RuleMeta("CF500", "plan", "Regex operator not available on Free plan", Severity.WARNING)
CF501 = RuleMeta("CF501", "plan", "Rule count exceeds plan limit for phase", Severity.WARNING)
CF502 = RuleMeta("CF502", "plan", "Expression exceeds 64 regex pattern limit", Severity.WARNING)

# Category E — Function Constraint Violations
CF300 = RuleMeta("CF300", "function", "Unknown function in expression", Severity.WARNING)
CF301 = RuleMeta("CF301", "function", "Function not available in this phase", Severity.WARNING)
CF302 = RuleMeta(
    "CF302", "function", "regex_replace/wildcard_replace usage limit exceeded", Severity.ERROR
)
CF303 = RuleMeta("CF303", "function", "Invalid encode_base64 flags", Severity.WARNING)
CF304 = RuleMeta("CF304", "function", "Invalid url_decode options", Severity.WARNING)
CF305 = RuleMeta("CF305", "function", "Invalid wildcard_replace flags", Severity.WARNING)
CF306 = RuleMeta(
    "CF306", "function", "Function source argument must be a field, not literal", Severity.WARNING
)

# Category F — Type System / Semantic Checks
CF307 = RuleMeta("CF307", "type", "Operator-type incompatibility", Severity.ERROR)
CF308 = RuleMeta("CF308", "type", "Unknown field name in expression", Severity.WARNING)
CF309 = RuleMeta(
    "CF309", "type", "Array [*] unpacking used on multiple distinct arrays", Severity.WARNING
)

# Category G — Value Constraint Warnings
CF520 = RuleMeta("CF520", "value", "HTTP method should be uppercase", Severity.WARNING)
CF521 = RuleMeta("CF521", "value", "URI path should start with /", Severity.WARNING)
CF522 = RuleMeta(
    "CF522", "value", "Regex anchor in literal value (use 'matches' operator?)", Severity.WARNING
)
CF523 = RuleMeta("CF523", "value", "Invalid country code format", Severity.WARNING)
CF524 = RuleMeta("CF524", "value", "Score value out of typical range", Severity.WARNING)
CF525 = RuleMeta("CF525", "value", "Response code out of valid range (100-599)", Severity.WARNING)
CF526 = RuleMeta("CF526", "value", "Header name should be lowercase", Severity.INFO)
CF527 = RuleMeta("CF527", "value", "File extension should not start with a dot", Severity.WARNING)
CF528 = RuleMeta("CF528", "value", "Duplicate value in 'in' set", Severity.WARNING)
CF529 = RuleMeta("CF529", "value", "Deprecated field — use replacement", Severity.WARNING)
CF530 = RuleMeta("CF530", "value", "Reserved/bogon IP address", Severity.WARNING)
CF531 = RuleMeta("CF531", "value", "Overlapping IP ranges", Severity.WARNING)
CF532 = RuleMeta("CF532", "value", "Invalid value for field domain", Severity.WARNING)
CF533 = RuleMeta("CF533", "value", "Timestamp value out of reasonable bounds", Severity.WARNING)
CF534 = RuleMeta("CF534", "value", "Integer range overlap in 'in' set", Severity.WARNING)
CF535 = RuleMeta(
    "CF535", "value", "Value incompatible with lower()/upper() transformation", Severity.WARNING
)
CF536 = RuleMeta("CF536", "value", "len() compared to negative value", Severity.WARNING)
CF537 = RuleMeta("CF537", "value", "Invalid double-asterisk in wildcard pattern", Severity.WARNING)
CF538 = RuleMeta("CF538", "value", "Integer range has start greater than end", Severity.ERROR)
CF539 = RuleMeta("CF539", "value", "split() limit outside valid range (1-128)", Severity.WARNING)
CF540 = RuleMeta("CF540", "value", "cidr/cidr6 bit value out of range", Severity.WARNING)
CF541 = RuleMeta(
    "CF541", "value", "remove_query_args() first argument is not a query field", Severity.WARNING
)
CF542 = RuleMeta("CF542", "value", "Invalid regex pattern in matches operator", Severity.WARNING)
CF543 = RuleMeta("CF543", "value", "substring() index out of bounds or inverted", Severity.WARNING)
CF544 = RuleMeta("CF544", "value", "lookup_json path should start with /", Severity.WARNING)
CF545 = RuleMeta("CF545", "value", "bit_slice offset or size out of range", Severity.WARNING)

# Category O — Best Practice / Style
CF510 = RuleMeta(
    "CF510", "style", "Consider using 'in' operator for multiple OR values", Severity.INFO
)
CF511 = RuleMeta("CF511", "style", "Use normalized field instead of raw field", Severity.INFO)
CF512 = RuleMeta("CF512", "style", "Redundant 'not not' double negation", Severity.INFO)
CF513 = RuleMeta("CF513", "style", "Negated comparison can be simplified", Severity.INFO)
CF514 = RuleMeta(
    "CF514", "style", "Illogical condition (contradictory AND or tautological OR)", Severity.WARNING
)
CF515 = RuleMeta(
    "CF515", "style", "Regex pattern uses literal escapes instead of raw string", Severity.INFO
)

# Category S — Page Shield Structure
CF460 = RuleMeta("CF460", "page_shield", "Missing required Page Shield field", Severity.ERROR)
CF461 = RuleMeta("CF461", "page_shield", "Invalid Page Shield action", Severity.ERROR)
CF462 = RuleMeta("CF462", "page_shield", "Invalid Page Shield field type", Severity.ERROR)
CF463 = RuleMeta("CF463", "page_shield", "Duplicate Page Shield description", Severity.WARNING)

# Category P — Cross-Rule / Ruleset-Level
CF100 = RuleMeta("CF100", "cross_rule", "Duplicate expression across rules", Severity.WARNING)
CF101 = RuleMeta(
    "CF101", "cross_rule", "Unreachable rule after terminating action", Severity.WARNING
)
CF102 = RuleMeta("CF102", "cross_rule", "Unresolved list reference", Severity.WARNING)
CF103 = RuleMeta("CF103", "cross_rule", "Invalid managed list name", Severity.WARNING)
CF104 = RuleMeta("CF104", "cross_rule", "Field type incompatible with list kind", Severity.WARNING)

# Category T — Custom Rulesets
CF022 = RuleMeta("CF022", "custom_ruleset", "Missing required custom ruleset field", Severity.ERROR)
CF023 = RuleMeta("CF023", "custom_ruleset", "Invalid custom ruleset ID format", Severity.WARNING)
CF024 = RuleMeta("CF024", "custom_ruleset", "Duplicate ref within custom ruleset", Severity.ERROR)
CF025 = RuleMeta(
    "CF025", "custom_ruleset", "Duplicate ref across custom rulesets", Severity.WARNING
)
CF026 = RuleMeta(
    "CF026", "custom_ruleset", "Custom ruleset exceeds maximum rule count (1,000)", Severity.WARNING
)

# Category Q — List Validation
CF470 = RuleMeta("CF470", "list", "Missing or invalid list name", Severity.ERROR)
CF471 = RuleMeta("CF471", "list", "Missing or invalid list kind", Severity.ERROR)
CF472 = RuleMeta("CF472", "list", "Missing required item field for list kind", Severity.ERROR)
CF473 = RuleMeta("CF473", "list", "Invalid IP address in list", Severity.ERROR)
CF474 = RuleMeta("CF474", "list", "Invalid ASN value in list", Severity.ERROR)
CF475 = RuleMeta("CF475", "list", "Duplicate item in list", Severity.WARNING)
CF476 = RuleMeta("CF476", "list", "List exceeds maximum item count (10,000)", Severity.WARNING)

# Collect all rule metas for registration
CF_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
