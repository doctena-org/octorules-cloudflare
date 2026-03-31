# Lint Rule Reference

`octorules lint` performs offline static analysis of your rules files. **127 rules** across **19 categories**, organized into a 4-stage pipeline.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

**Per-rule suppression** — suppresses the rule for a single ref:

```yaml
request_header_rules:
  # octorules:disable=CF015
  - ref: add-security-headers
    expression: (true)
    action_parameters:
      headers:
        Strict-Transport-Security:
          operation: set
          value: max-age=31536000
```

**Page Shield policy suppression** — works with `- description:` lines (since policies use description as identity):

```yaml
page_shield_policies:
  # octorules:disable=CF015
  - description: "Allow all scripts"
    expression: (true)
    action: allow
    value: "script-src 'self'"
    enabled: true
```

**File-level suppression** — place the directive before any rules to suppress across the entire file:

```yaml
# octorules:disable=CF511
---
origin_rules:
  - ref: route-api
    expression: 'raw.http.request.uri.path eq "/api"'
```

**Multiple rules:**

```yaml
  # octorules:disable=CF015,CF510
  - ref: catch-all
    expression: (true)
```

Suppressed findings are excluded from the report but counted in the summary line (e.g., `Total: 0 error(s), 0 warning(s), 0 info (2 suppressed)`).

### Severity levels

| Level | Meaning |
|-------|---------|
| **ERROR** | Invalid config that will fail at Cloudflare |
| **WARNING** | Likely mistake or suboptimal pattern |
| **INFO** | Style suggestion |

## Pipeline

| Stage | What it checks | CF Range | Rules | Details |
|-------|---------------|----------|-------|---------|
| 1. YAML structure | Required fields, types, duplicates, unknown keys | CF003–CF018 | 16 | [stage1-yaml-structure.md](stage1-yaml-structure.md) |
| 2. Per-rule checks | Actions, expressions, phase restrictions, values, style | CF001–CF002, CF019–CF021, CF200–CF545 | 89 | [stage2-per-rule.md](stage2-per-rule.md) |
| 2b. Custom rulesets | Custom ruleset structure, duplicate refs + full per-rule checks (actions, expressions, phase restrictions) | CF022–CF025 | 4 | [stage2b-custom-rulesets.md](stage2b-custom-rulesets.md) |
| 2c. Page Shield | Policy structure, catch-all detection + expression analysis and phase restrictions | CF460–CF463 | 4 | [stage2b-page-shield.md](stage2b-page-shield.md) |
| 2d. List validation | List structure, item validity, duplicates | CF470–CF475 | 6 | [stage2d-lists.md](stage2d-lists.md) |
| 3. Plan-tier limits | Regex availability, rule count limits | CF500–CF502 | 3 | [stage3-plan-tier.md](stage3-plan-tier.md) |
| 4. Cross-rule analysis | Duplicates, unreachable rules, list references | CF100–CF104 | 5 | [stage4-cross-rule.md](stage4-cross-rule.md) |

## Categories

| CF Range | Category | Rules |
|----------|----------|-------|
| CF001–CF002 | Parse / syntax errors | 2 |
| CF003–CF018 | Structure | 16 |
| CF019–CF021 | Phase restrictions | 3 |
| CF022–CF025 | Custom ruleset validation | 4 |
| CF100–CF104 | Cross-rule | 5 |
| CF200–CF217 | Action validation | 18 |
| CF300–CF306 | Function constraints | 7 |
| CF307–CF309 | Type system | 3 |
| CF400–CF405 | Rate limiting | 6 |
| CF410–CF413 | Cache rules | 4 |
| CF420–CF424 | Config rules | 5 |
| CF430–CF431 | Redirect rules | 2 |
| CF440–CF445 | Transform rules | 6 |
| CF450 | Origin rules | 1 |
| CF460–CF463 | Page Shield structure | 4 |
| CF470–CF475 | List validation | 6 |
| CF500–CF502 | Plan/entitlement | 3 |
| CF510–CF515 | Best practice / style | 6 |
| CF520–CF545 | Value constraints | 26 |

---

## Cloudflare Phases Reference

Cloudflare processes every HTTP request through a fixed sequence of **phases**. Each phase has its own ruleset, and rules within a phase execute top-to-bottom. Understanding phase order is critical — it determines which fields are available, which actions are valid, and when a terminating action (like `block`) stops further processing.

### Execution order

```
Request arrives at Cloudflare edge
  │
  ├─  1. url_normalization          Normalize URL encoding
  ├─  2. bulk_redirect_rules        Account-level bulk redirects
  ├─  3. redirect_rules             Dynamic redirects
  ├─  4. url_rewrite_rules          Rewrite URI path/query
  ├─  5. request_header_rules       Modify request headers
  ├─  6. origin_rules               Override origin host/port/SNI
  ├─  7. config_rules               Set zone config (SSL, security level, polish, etc.)
  ├─  8. cache_rules                Cache settings (TTL, bypass, etc.)
  ├─  9. waf_custom_rules           Custom WAF rules (block, challenge, skip, log)
  ├─ 10. waf_managed_rules          Managed WAF rulesets (OWASP, CF Managed, etc.)
  ├─ 11. rate_limiting_rules        Rate limiting
  ├─ 12. bot_fight_rules            Super Bot Fight Mode
  ├─ 13. http_ddos_rules            L7 DDoS protection overrides
  │
  ├─── Origin fetch ────────────────── request leaves CF, response returns
  │
  ├─ 14. custom_error_rules         Custom error pages (serve_error)
  ├─ 15. response_header_rules      Modify response headers
  ├─ 16. compression_rules          Response compression algorithms
  ├─ 17. sensitive_data_detection    Detect sensitive data in responses
  ├─ 18. log_custom_fields          Custom log fields
  │
  └─ Response delivered to client
```

Network-level phases (Magic Transit) run before HTTP processing and are not shown above:

```
Network packet arrives
  │
  ├─ network_ddos_rules             L3/L4 DDoS protection (ddos_l4)
  ├─ network_firewall_rules         Magic Transit firewall (magic_transit)
  ├─ network_firewall_managed       Magic Transit managed rules
  ├─ network_firewall_ratelimit     Magic Transit rate limiting
  └─ network_firewall_ids           Magic Transit IDS
```

### Phase details

| # | YAML Key | CF Phase ID | Default Action | Valid Actions | Scope |
|---|----------|-------------|----------------|---------------|-------|
| 1 | `url_normalization` | `http_request_sanitize` | *(must specify)* | `none` | Zone |
| 2 | `bulk_redirect_rules` | `http_request_redirect` | `redirect` | `redirect` | Account |
| 3 | `redirect_rules` | `http_request_dynamic_redirect` | `redirect` | `redirect` | Zone |
| 4 | `url_rewrite_rules` | `http_request_transform` | `rewrite` | `rewrite` | Zone |
| 5 | `request_header_rules` | `http_request_late_transform` | `rewrite` | `rewrite` | Zone |
| 6 | `origin_rules` | `http_request_origin` | `route` | `route` | Zone |
| 7 | `config_rules` | `http_config_settings` | `set_config` | `set_config` | Zone |
| 8 | `cache_rules` | `http_request_cache_settings` | `set_cache_settings` | `set_cache_settings` | Zone |
| 9 | `waf_custom_rules` | `http_request_firewall_custom` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge`, `skip`, `log`, `execute` | Zone + Account |
| 10 | `waf_managed_rules` | `http_request_firewall_managed` | *(must specify)* | `execute`, `skip`, `block`, `log` | Zone + Account |
| 11 | `rate_limiting_rules` | `http_ratelimit` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge`, `log`, `execute` | Zone + Account |
| 12 | `bot_fight_rules` | `http_request_sbfm` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge` | Zone |
| 13 | `http_ddos_rules` | `ddos_l7` | *(must specify)* | `block`, `challenge`, `log` | Zone + Account |
| 14 | `custom_error_rules` | `http_custom_errors` | `serve_error` | `serve_error` | Zone + Account |
| 15 | `response_header_rules` | `http_response_headers_transform` | `rewrite` | `rewrite` | Zone |
| 16 | `compression_rules` | `http_response_compression` | `compress_response` | `compress_response` | Zone |
| 17 | `sensitive_data_detection` | `http_response_firewall_managed` | *(must specify)* | `log` | Zone |
| 18 | `log_custom_fields` | `http_log_custom_fields` | `log_custom_field` | `log_custom_field` | Zone |

### Field availability by phase

Not all fields are available in all phases. The linter checks these restrictions automatically (rules CF019, CF020, CF021).

| Field group | Available in | Linter rule |
|-------------|-------------|-------------|
| **Request fields** (`http.request.*`, `http.host`, `ip.src.*`, `cf.*`, `ssl`) | All phases | — |
| **Response fields** (`http.response.*`, `cf.response.*`) | Phases 14–18 (after origin fetch): `custom_error_rules`, `response_header_rules`, `compression_rules`, `sensitive_data_detection`, `log_custom_fields` | [CF019](stage2-per-rule.md#cf019--response-field-used-in-request-phase) |
| **Request body fields** (`http.request.body.*`) | `waf_custom_rules`, `waf_managed_rules`, `rate_limiting_rules`, `custom_error_rules` | [CF020](stage2-per-rule.md#cf020--request-body-field-in-phase-without-body-access) |
| **Plan-gated fields** (`cf.bot_management.*`, `cf.waf.*`, etc.) | Depend on plan tier (Free/Pro/Business/Enterprise) | [CF021](stage2-per-rule.md#cf021--fieldfunction-requires-higher-plan-tier) |
| **Plan-gated functions** (`sha256` Enterprise, `is_timed_hmac_valid_v0` Pro) | Depend on plan tier | [CF021](stage2-per-rule.md#cf021--fieldfunction-requires-higher-plan-tier) |

### Function availability by phase

Some functions are restricted to specific phases. The linter checks this via rule [CF301](stage2-per-rule.md#cf301--function-not-available-in-this-phase).

| Functions | Available in |
|-----------|-------------|
| `regex_replace`, `wildcard_replace`, `to_string` | Transform + redirect phases: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `redirect_rules` |
| `uuidv4`, `sha256`, `encode_base64`, `remove_query_args` | Transform phases only: `url_rewrite_rules`, `request_header_rules`, `response_header_rules` |
| `decode_base64` | Transform + WAF + rate limiting: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `waf_custom_rules`, `rate_limiting_rules` |
| `split` | Response transform + custom error phases: `response_header_rules`, `custom_error_rules` |
| `join` | Transform + WAF + custom error phases: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `waf_custom_rules`, `custom_error_rules` |
| `cidr`, `cidr6` | WAF + rate limiting phases: `waf_custom_rules`, `rate_limiting_rules` |
| `bit_slice` | Network phases only: `network_firewall_rules`, `network_ddos_rules`, `network_firewall_managed`, `network_firewall_ratelimit`, `network_firewall_ids` |
| All other functions (`lower`, `upper`, `len`, `contains`, `starts_with`, `ends_with`, `any`, `all`, etc.) | All phases |

### Key behaviors

**Terminating actions** — `block`, `redirect`, `challenge`, `js_challenge`, and `managed_challenge` stop the request from proceeding to later phases. A `block` in `waf_custom_rules` (phase 9) means `rate_limiting_rules` (phase 11) never runs. The linter detects unreachable rules *within* a phase via [CF101](stage4-cross-rule.md#cf101--unreachable-rule-after-terminating-action), but cross-phase ordering is the user's responsibility.

**`skip` action** — Only available in `waf_custom_rules` and `waf_managed_rules`. Can skip specific phases (`action_parameters.phases`) or legacy products (`action_parameters.products`). The linter validates these values via [CF210](stage2-per-rule.md#cf210--invalid-skip-phases-value) and [CF211](stage2-per-rule.md#cf211--invalid-skip-products-value).

**Transform expressions** — In transform phases (`url_rewrite_rules`, `request_header_rules`, `response_header_rules`), `action_parameters` can contain `expression` fields that use function-call syntax (e.g., `concat(...)`, `regex_replace(...)`). These are *different* from the rule's match `expression` — they define how values are computed, not whether the rule fires. The linter validates these via [CF444](stage2-per-rule.md#cf444--expression-parse-error-in-transform-action_parameters).

**Expression language** — All phases use the same [Cloudflare Rules Language](https://developers.cloudflare.com/ruleset-engine/rules-language/) (wirefilter syntax). Expressions have a 4,096 character limit ([CF017](stage1-yaml-structure.md#cf017--expression-exceeds-4096-character-limit)) and a 64 regex pattern limit per rule ([CF502](stage3-plan-tier.md#cf502--expression-exceeds-64-regex-pattern-limit)). The `matches` operator (regex) is not available on the Free plan ([CF500](stage3-plan-tier.md#cf500--regex-operator-not-available-on-free-plan)).

**Rule count limits** — Each phase has per-plan rule count limits. The linter checks these via [CF501](stage3-plan-tier.md#cf501--rule-count-exceeds-plan-limit-for-phase).

---

## Rule ID Quick Reference

| ID | Description | Severity |
|----|-------------|----------|
| [CF001](stage2-per-rule.md#cf001--expression-parse-error-wirefilter) | Expression parse error (wirefilter) | WARNING |
| [CF002](stage2-per-rule.md#cf002--expression-nesting-depth-exceeded) | Expression nesting depth exceeded | WARNING |
| [CF003](stage1-yaml-structure.md#cf003--missing-ref-field) | Missing ref field | ERROR |
| [CF004](stage1-yaml-structure.md#cf004--missing-expression-field) | Missing expression field | ERROR |
| [CF005](stage1-yaml-structure.md#cf005--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [CF006](stage1-yaml-structure.md#cf006--invalid-ref-type) | Invalid ref type | ERROR |
| [CF007](stage1-yaml-structure.md#cf007--invalid-expression-type) | Invalid expression type | ERROR |
| [CF008](stage1-yaml-structure.md#cf008--invalid-enabled-type) | Invalid enabled type | ERROR |
| [CF009](stage1-yaml-structure.md#cf009--unknown-top-level-phase-key) | Unknown top-level phase key | WARNING |
| [CF010](stage1-yaml-structure.md#cf010--deprecated-phase-name) | Deprecated phase name | WARNING |
| [CF011](stage1-yaml-structure.md#cf011--description-exceeds-500-characters) | Description exceeds 500 characters | WARNING |
| [CF012](stage1-yaml-structure.md#cf012--phase-value-is-not-a-list) | Phase value is not a list | ERROR |
| [CF013](stage1-yaml-structure.md#cf013--rule-entry-is-not-a-dict) | Rule entry is not a dict | ERROR |
| [CF014](stage1-yaml-structure.md#cf014--cloudflare-phase-identifier-used-instead-of-friendly-name) | CF phase identifier used instead of friendly name | WARNING |
| [CF015](stage1-yaml-structure.md#cf015--expression-is-always-true-catch-all) | Expression is always true (catch-all) | WARNING |
| [CF016](stage1-yaml-structure.md#cf016--expression-is-always-false-dead-rule) | Expression is always false (dead rule) | WARNING |
| [CF017](stage1-yaml-structure.md#cf017--expression-exceeds-4096-character-limit) | Expression exceeds 4,096 character limit | ERROR |
| [CF018](stage1-yaml-structure.md#cf018--rule-is-disabled) | Rule is disabled (enabled: false) | INFO |
| [CF200](stage2-per-rule.md#cf200--invalid-action-for-phase) | Invalid action for phase | ERROR |
| [CF201](stage2-per-rule.md#cf201--missing-required-action) | Missing required action | ERROR |
| [CF202](stage2-per-rule.md#cf202--missing-required-action_parameters) | Missing required action_parameters | ERROR |
| [CF203](stage2-per-rule.md#cf203--unknown-action_parameters-key) | Unknown action_parameters key | WARNING |
| [CF204](stage2-per-rule.md#cf204--invalid-action_parameters-type) | Invalid action_parameters type | ERROR |
| [CF205](stage2-per-rule.md#cf205--invalid-status_code-type-or-value) | Invalid status_code type or value | ERROR |
| [CF206](stage2-per-rule.md#cf206--missing-required-status_code-for-redirect) | Missing required status_code for redirect | ERROR |
| [CF207](stage2-per-rule.md#cf207--conflicting-static-value-and-dynamic-expression) | Conflicting static value and dynamic expression | ERROR |
| [CF208](stage2-per-rule.md#cf208--unnecessary-action_parameters) | Unnecessary action_parameters | WARNING |
| [CF209](stage2-per-rule.md#cf209--serve_error-content-exceeds-10kb-limit) | serve_error content exceeds 10KB limit | ERROR |
| [CF210](stage2-per-rule.md#cf210--invalid-skip-phases-value) | Invalid skip phases value | ERROR |
| [CF211](stage2-per-rule.md#cf211--invalid-skip-products-value) | Invalid skip products value | ERROR |
| [CF212](stage2-per-rule.md#cf212--invalid-compress_response-algorithm) | Invalid compress_response algorithm | ERROR |
| [CF213](stage2-per-rule.md#cf213--invalid-rate-limit-characteristic) | Invalid rate limit characteristic | ERROR |
| [CF214](stage2-per-rule.md#cf214--invalid-block-response-parameter) | Invalid block response parameter | ERROR |
| [CF215](stage2-per-rule.md#cf215--missing-id-in-execute-action_parameters) | Missing id in execute action_parameters | ERROR |
| [CF216](stage2-per-rule.md#cf216--invalid-execute-id-format) | Invalid execute id format | WARNING |
| [CF217](stage2-per-rule.md#cf217--compression-terminal-algorithm-must-be-last) | Compression terminal algorithm must be last | WARNING |
| [CF400](stage2-per-rule.md#cf400--invalid-rate-limiting-period) | Invalid rate limiting period | ERROR |
| [CF401](stage2-per-rule.md#cf401--missing-rate-limiting-characteristics) | Missing rate limiting characteristics | WARNING |
| [CF402](stage2-per-rule.md#cf402--missing-requests_per_period-threshold) | Missing requests_per_period threshold | ERROR |
| [CF403](stage2-per-rule.md#cf403--mitigation-timeout-exceeds-period) | Mitigation timeout exceeds period | WARNING |
| [CF404](stage2-per-rule.md#cf404--invalid-counting_expression) | Invalid counting_expression | ERROR |
| [CF405](stage2-per-rule.md#cf405--invalid-counting_expression-content) | Invalid counting_expression content | WARNING |
| [CF410](stage2-per-rule.md#cf410--invalid-ttl-mode-value) | Invalid TTL mode value | ERROR |
| [CF411](stage2-per-rule.md#cf411--missing-ttl-with-override-mode) | Missing TTL with override mode | ERROR |
| [CF412](stage2-per-rule.md#cf412--negative-ttl-value) | Negative TTL value | ERROR |
| [CF413](stage2-per-rule.md#cf413--conflicting-bypass-and-eligible-settings) | Conflicting bypass and eligible settings | WARNING |
| [CF420](stage2-per-rule.md#cf420--invalid-security_level-value) | Invalid security_level value | ERROR |
| [CF421](stage2-per-rule.md#cf421--invalid-ssl-value) | Invalid ssl value | ERROR |
| [CF422](stage2-per-rule.md#cf422--invalid-polish-value) | Invalid polish value | ERROR |
| [CF423](stage2-per-rule.md#cf423--security-warning-security_level-set-to-off) | Security warning: security_level off | WARNING |
| [CF424](stage2-per-rule.md#cf424--security-warning-ssl-set-to-off) | Security warning: ssl set to off | WARNING |
| [CF430](stage2-per-rule.md#cf430--invalid-redirect-status-code) | Invalid redirect status code | ERROR |
| [CF431](stage2-per-rule.md#cf431--missing-target_url-in-redirect) | Missing target_url in redirect | ERROR |
| [CF440](stage2-per-rule.md#cf440--empty-header-name-in-transform) | Empty header name in transform | ERROR |
| [CF441](stage2-per-rule.md#cf441--missing-operation-in-header-transform) | Missing operation in header transform | ERROR |
| [CF442](stage2-per-rule.md#cf442--invalid-header-transform-operation) | Invalid header transform operation | ERROR |
| [CF443](stage2-per-rule.md#cf443--header-setadd-missing-value-or-expression) | Header set/add missing value or expression | ERROR |
| [CF444](stage2-per-rule.md#cf444--expression-parse-error-in-transform-action_parameters) | Expression parse error in transform action_parameters | WARNING |
| [CF445](stage2-per-rule.md#cf445--request-headers-do-not-support-add-operation) | Request headers do not support add operation | ERROR |
| [CF450](stage2-per-rule.md#cf450--port-number-out-of-range) | Port number out of range (1-65535) | ERROR |
| [CF019](stage2-per-rule.md#cf019--response-field-used-in-request-phase) | Response field used in request phase | WARNING |
| [CF020](stage2-per-rule.md#cf020--request-body-field-in-phase-without-body-access) | Request body field in phase without body access | WARNING |
| [CF021](stage2-per-rule.md#cf021--fieldfunction-requires-higher-plan-tier) | Field/function requires higher plan tier | WARNING |
| [CF300](stage2-per-rule.md#cf300--unknown-function-in-expression) | Unknown function in expression | WARNING |
| [CF301](stage2-per-rule.md#cf301--function-not-available-in-this-phase) | Function not available in this phase | WARNING |
| [CF302](stage2-per-rule.md#cf302--regex_replacewildcard_replace-usage-limit) | regex_replace/wildcard_replace usage limit | ERROR |
| [CF303](stage2-per-rule.md#cf303--invalid-encode_base64-flags) | Invalid encode_base64 flags | WARNING |
| [CF304](stage2-per-rule.md#cf304--invalid-url_decode-options) | Invalid url_decode options | WARNING |
| [CF305](stage2-per-rule.md#cf305--invalid-wildcard_replace-flags) | Invalid wildcard_replace flags | WARNING |
| [CF306](stage2-per-rule.md#cf306--function-source-argument-must-be-field) | Function source argument must be field | WARNING |
| [CF307](stage2-per-rule.md#cf307--operator-type-incompatibility) | Operator-type incompatibility | ERROR |
| [CF308](stage2-per-rule.md#cf308--unknown-field-name-in-expression) | Unknown field name in expression | WARNING |
| [CF309](stage2-per-rule.md#cf309--array-star-unpacking-on-multiple-arrays) | Array [*] unpacking on multiple arrays | WARNING |
| [CF520](stage2-per-rule.md#cf520--http-method-should-be-uppercase) | HTTP method should be uppercase | WARNING |
| [CF521](stage2-per-rule.md#cf521--uri-path-should-start-with-) | URI path should start with / | WARNING |
| [CF522](stage2-per-rule.md#cf522--regex-anchor-in-literal-value) | Regex anchor in literal value | WARNING |
| [CF523](stage2-per-rule.md#cf523--invalid-country-code-format) | Invalid country code format | WARNING |
| [CF524](stage2-per-rule.md#cf524--score-value-out-of-typical-range) | Score value out of typical range | WARNING |
| [CF525](stage2-per-rule.md#cf525--response-code-out-of-valid-range) | Response code out of valid range | WARNING |
| [CF526](stage2-per-rule.md#cf526--header-name-should-be-lowercase) | Header name should be lowercase | INFO |
| [CF527](stage2-per-rule.md#cf527--file-extension-should-not-start-with-a-dot) | File extension should not start with dot | WARNING |
| [CF528](stage2-per-rule.md#cf528--duplicate-value-in-in-set) | Duplicate value in `in` set | WARNING |
| [CF529](stage2-per-rule.md#cf529--deprecated-field) | Deprecated field — use replacement | WARNING |
| [CF530](stage2-per-rule.md#cf530--reservedbogon-ip-address) | Reserved/bogon IP address | WARNING |
| [CF531](stage2-per-rule.md#cf531--overlapping-ip-ranges) | Overlapping IP ranges | WARNING |
| [CF532](stage2-per-rule.md#cf532--invalid-value-for-field-domain) | Invalid value for field domain | WARNING |
| [CF533](stage2-per-rule.md#cf533--timestamp-value-out-of-reasonable-bounds) | Timestamp value out of reasonable bounds | WARNING |
| [CF534](stage2-per-rule.md#cf534--integer-range-overlap-in-in-set) | Integer range overlap in `in` set | WARNING |
| [CF535](stage2-per-rule.md#cf535--value-incompatible-with-lowerupper) | Value incompatible with lower()/upper() | WARNING |
| [CF536](stage2-per-rule.md#cf536--len-compared-to-negative-value) | len() compared to negative value | WARNING |
| [CF537](stage2-per-rule.md#cf537--invalid-double-asterisk-in-wildcard) | Invalid double-asterisk in wildcard | WARNING |
| [CF538](stage2-per-rule.md#cf538--integer-range-start-greater-than-end) | Integer range start > end | ERROR |
| [CF539](stage2-per-rule.md#cf539--split-limit-outside-valid-range) | split() limit outside 1-128 | WARNING |
| [CF540](stage2-per-rule.md#cf540--cidrcidr6-bit-value-out-of-range) | cidr/cidr6 bit value out of range | WARNING |
| [CF541](stage2-per-rule.md#cf541--remove_query_args-wrong-first-argument) | remove_query_args() wrong first argument | WARNING |
| [CF542](stage2-per-rule.md#cf542--invalid-regex-pattern-in-matches-operator) | Invalid regex pattern in matches operator | WARNING |
| [CF543](stage2-per-rule.md#cf543--substring-index-out-of-bounds-or-inverted) | substring() index out of bounds or inverted | WARNING |
| [CF544](stage2-per-rule.md#cf544--lookup_json-path-should-start-with-) | lookup_json path should start with / | WARNING |
| [CF545](stage2-per-rule.md#cf545--bit_slice-offset-or-size-out-of-range) | bit_slice offset or size out of range | WARNING |
| [CF500](stage3-plan-tier.md#cf500--regex-operator-not-available-on-free-plan) | Regex not available on Free plan | WARNING |
| [CF501](stage3-plan-tier.md#cf501--rule-count-exceeds-plan-limit-for-phase) | Rule count exceeds plan limit | WARNING |
| [CF502](stage3-plan-tier.md#cf502--expression-exceeds-64-regex-pattern-limit) | Expression exceeds 64 regex limit | WARNING |
| [CF510](stage2-per-rule.md#cf510--consider-using-in-operator-for-multiple-or-values) | Consider using in operator | INFO |
| [CF511](stage2-per-rule.md#cf511--use-normalized-field-instead-of-raw-field) | Use normalized field instead of raw | INFO |
| [CF512](stage2-per-rule.md#cf512--redundant-double-negation) | Redundant double negation | INFO |
| [CF513](stage2-per-rule.md#cf513--negated-comparison-can-be-simplified) | Negated comparison can be simplified | INFO |
| [CF514](stage2-per-rule.md#cf514--illogical-condition) | Illogical condition | WARNING |
| [CF515](stage2-per-rule.md#cf515--regex-pattern-uses-literal-escapes) | Regex literal escapes | INFO |
| [CF460](stage2b-page-shield.md#cf460--missing-required-field) | Missing required Page Shield field | ERROR |
| [CF461](stage2b-page-shield.md#cf461--invalid-action) | Invalid Page Shield action | ERROR |
| [CF462](stage2b-page-shield.md#cf462--invalid-field-type) | Invalid Page Shield field type | ERROR |
| [CF463](stage2b-page-shield.md#cf463--duplicate-description) | Duplicate Page Shield description | WARNING |
| [CF100](stage4-cross-rule.md#cf100--duplicate-expression-across-rules) | Duplicate expression across rules | WARNING |
| [CF101](stage4-cross-rule.md#cf101--unreachable-rule-after-terminating-action) | Unreachable rule after terminating action | WARNING |
| [CF102](stage4-cross-rule.md#cf102--unresolved-list-reference) | Unresolved list reference | WARNING |
| [CF103](stage4-cross-rule.md#cf103--unknown-managed-list-name) | Unknown managed list name | WARNING |
| [CF104](stage4-cross-rule.md#cf104--list-type--field-type-mismatch) | List type / field type mismatch | WARNING |
| [CF470](stage2d-lists.md#cf470--missing-or-duplicate-list-name) | Missing or duplicate list name | ERROR |
| [CF471](stage2d-lists.md#cf471--missing-or-invalid-list-kind) | Missing or invalid list kind | ERROR |
| [CF472](stage2d-lists.md#cf472--list-item-missing-required-field) | List item missing required field | ERROR |
| [CF473](stage2d-lists.md#cf473--invalid-ip-address-in-ip-list) | Invalid IP address in IP list | ERROR |
| [CF474](stage2d-lists.md#cf474--invalid-asn-value-in-asn-list) | Invalid ASN value in ASN list | ERROR |
| [CF475](stage2d-lists.md#cf475--duplicate-items-within-list) | Duplicate items within list | WARNING |
| [CF022](stage2b-custom-rulesets.md#cf022--missing-required-field) | Missing required custom ruleset field | ERROR |
| [CF023](stage2b-custom-rulesets.md#cf023--invalid-id-format) | Invalid custom ruleset id format | WARNING |
| [CF024](stage2b-custom-rulesets.md#cf024--duplicate-ref-within-custom-ruleset) | Duplicate ref within custom ruleset | ERROR |
| [CF025](stage2b-custom-rulesets.md#cf025--duplicate-ref-across-custom-rulesets) | Duplicate ref across custom rulesets | WARNING |
