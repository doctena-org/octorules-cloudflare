# octorules-cloudflare

Cloudflare provider for [octorules](https://github.com/doctena-org/octorules) — manages 23 Cloudflare rule phases, custom rulesets, lists, and Page Shield policies as YAML.

## Installation

```bash
pip install octorules-cloudflare
```

Or via the octorules extra:

```bash
pip install octorules[cloudflare]
```

This installs octorules (core), octorules-cloudflare, and
[octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter)
(Rust FFI bridge to Cloudflare's wirefilter engine for authoritative expression
parsing and full linter coverage).

Prebuilt wirefilter wheels are available for Linux (x86_64, aarch64; glibc and
musl/Alpine), macOS (x86_64, ARM64), and Windows (x86_64).

## Configuration

```yaml
providers:
  cloudflare:
    token: env/CLOUDFLARE_API_TOKEN
  rules:
    directory: ./rules

zones:
  example.com:
    sources:
      - rules
```

The `env/` prefix resolves values from environment variables at runtime.
All keys under the provider section are forwarded to the provider constructor
as keyword arguments (octodns-style passthrough).

### Authentication

A [Cloudflare API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
is required. The token needs the following permissions:

- **Zone > Firewall Services > Edit** — for ruleset phase operations
- **Account > Account Rulesets > Edit** — for account-level rules and custom rulesets
- **Account > Account Filter Lists > Edit** — for list management
- **Zone > Page Shield > Edit** — for Page Shield policy management

### Provider settings

All settings below go under the provider section (e.g. `providers.cloudflare`).

| Key | Default | Description |
|-----|---------|-------------|
| `token` | *(required)* | Cloudflare API token (`env/` prefix supported) |
| `max_retries` | `2` | API retry count (0-10) |
| `timeout` | `30` | API timeout in seconds (max 300) |

Safety thresholds are configured under `safety:` (framework-owned, not
forwarded to the provider):

| Key | Default | Description |
|-----|---------|-------------|
| `safety.delete_threshold` | `30.0` | Max % of rules that can be deleted |
| `safety.update_threshold` | `30.0` | Max % of rules that can be updated |
| `safety.min_existing` | `3` | Min rules before thresholds apply |

## Supported features

| Feature | Status |
|---------|--------|
| Phase rules (23 phases) | Supported |
| Custom rulesets (account-level) | Supported |
| Lists (IP, ASN, hostname, redirect) | Supported |
| Page Shield policies (zone-level) | Supported |
| Zone discovery (`list_zones`) | Supported |
| Account-level scopes | Supported |

## Supported phases

23 Cloudflare phases — 18 HTTP request/response phases and 5 network-level (Magic Transit) phases. Phases execute in a fixed order:

```
Request  -> url_normalization -> redirect_rules -> url_rewrite_rules -> request_header_rules
         -> origin_rules -> config_rules -> cache_rules
         -> waf_custom_rules -> waf_managed_rules -> rate_limiting_rules
         -> bot_fight_rules -> http_ddos_rules
         ->  Origin fetch  <-
         -> custom_error_rules -> response_header_rules -> compression_rules
         -> sensitive_data_detection -> log_custom_fields -> Response
```

Phases with a default action (e.g., `redirect_rules` -> `redirect`) don't need `action` in the YAML — it's injected automatically. For phases without a default (e.g., `waf_custom_rules`), you must specify `action` explicitly.

Phases marked as both Zone and Account work at either scope. Account-only phases are skipped for zone scopes and vice versa, eliminating wasted API calls.

For the full phase reference — execution order diagram, valid actions per phase, field/function availability, and key behaviors — see [docs/lint-rules/README.md](docs/lint-rules/README.md).

> **Note:** `waf_managed_exceptions` was renamed to `waf_managed_rules`. The old name still works as an alias but is deprecated — update your YAML files to use the new name.

## Expression syntax

Rule expressions use [Cloudflare's ruleset expression language](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/). When [octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter) is installed (included automatically with `octorules-cloudflare`), expressions are parsed by Cloudflare's actual wirefilter engine, providing authoritative type checking, field validation, and syntax verification. Without it, a regex-based fallback parser extracts fields, functions, operators, and literals but cannot perform type checking.

The linter logs which parser is active at startup (`Expression parser: wirefilter` or `Expression parser: regex fallback`).

> **Rule-level metadata:** All Cloudflare rules support the `octorules:` key for per-rule metadata — `ignored: true` to skip a rule during plan/sync, and `included`/`excluded` to restrict rules to specific providers. See [octorules core docs](https://github.com/doctena-org/octorules#rule-level-metadata) for syntax and examples.

## Custom rulesets (account-level)

At the account level, WAF custom rules and rate limiting rules use a two-tier structure: the phase entrypoint contains **deploy rules** (`action: execute`) that reference child **custom rulesets** by ID. The individual blocking/logging rules live inside those child rulesets.

octorules manages both tiers. Deploy rules are managed via the normal phase sections (`waf_custom_rules`, `rate_limiting_rules`). The individual rules inside each custom ruleset are managed via a separate `custom_rulesets` section:

```yaml
# Account rules file (e.g. rules/my-account.yaml)

# Deploy rules (phase entrypoint — references child rulesets by ID)
waf_custom_rules:
  - ref: deploy-known-attackers
    description: Deploy known attackers ruleset
    action: execute
    action_parameters:
      id: abc12345def67890abc12345def67890
      version: latest
    enabled: true
    expression: (http.host eq "api.example.com")

# Individual rules inside each custom ruleset
custom_rulesets:
  - id: abc12345def67890abc12345def67890
    name: Known attackers
    phase: http_request_firewall_custom
    rules:
      - ref: block-bad-asn
        description: Block by AS number
        action: block
        expression: (ip.geoip.asnum in {12345 67890})
      - ref: block-bad-ua
        description: Block by user-agent
        action: block
        expression: (http.user_agent contains "BadBot")
```

The `id` field in each `custom_rulesets` entry links it to the deploy rule's `action_parameters.id`. Rules inside use `ref` for identification (same pattern as phase rules). Every rule must specify an `action` explicitly.

Use `octorules dump --scope account` to export existing custom rulesets to YAML.

> **Note:** octorules manages rules *within* existing custom rulesets. Creating or deleting rulesets themselves must be done via the Cloudflare dashboard. Zone-level rulesets do not have `kind=custom` children — this is account-level only.

## Lists (account-level)

Cloudflare account-level [Lists](https://developers.cloudflare.com/waf/tools/lists/) (IP lists, ASN lists, hostname lists, redirect lists) can be referenced in rule expressions via `$list_name` syntax. octorules manages full lifecycle of lists declaratively: create, delete, update metadata, and manage items.

Add a top-level `lists` key to your account rules file:

```yaml
# rules/my-account.yaml
lists:
  - name: blocked_ips
    kind: ip
    description: "Known bad IPs"
    items:
      - ip: "1.2.3.4"
        comment: "Scanner"
      - ip: "5.6.7.0/24"
        comment: "Botnet range"

  - name: partner_asns
    kind: asn
    description: "Partner AS numbers"
    items:
      - asn: 12345
        comment: "Partner A"
      - asn: 67890
        comment: "Partner B"
```

Each list entry requires:

| Field | Description |
|-------|-------------|
| `name` | List name — matches CF list name and `$list_name` in expressions |
| `kind` | One of `ip`, `asn`, `hostname`, `redirect` |
| `description` | Optional — updated if changed |
| `items` | List of items (can be empty `[]` to clear all items) |

**How it works:**

- The presence of a `lists:` key means ALL lists are managed — lists in Cloudflare not in YAML are planned for deletion (subject to safety thresholds).
- If the `lists:` key is absent, lists are ignored entirely.
- Item updates are asynchronous — octorules polls the bulk operation until completion.
- During sync, lists are applied **before** rulesets and phases, so newly created lists are available for rule expressions that reference them.
- Use `octorules dump --scope account` to export existing lists to YAML. The dump externalizes list items into separate files (referenced via `!include` tags) under `providers.lists.directory` (default: `{rules_dir}/custom_lists`).

Reference lists in rule expressions:

```yaml
waf_custom_rules:
  - ref: block-bad-ips
    description: Block IPs from blocklist
    action: block
    expression: (ip.src in $blocked_ips)
```

## Page Shield policies (zone-level)

Cloudflare [Page Shield](https://developers.cloudflare.com/page-shield/) manages Content Security Policies (CSP) at the zone level. octorules manages full lifecycle of Page Shield policies declaratively: create, update, and delete.

Add a top-level `page_shield_policies` key to your zone rules file:

```yaml
# rules/example.com.yaml
page_shield_policies:
  - description: "CSP on all example.com"
    action: allow
    expression: "true"
    enabled: true
    value: >-
      script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;
      worker-src 'self' blob:

  - description: "Log CSP on staging"
    action: log
    expression: '(http.host eq "staging.example.com")'
    enabled: true
    value: "default-src 'self'"
```

Each policy entry requires:

| Field | Description |
|-------|-------------|
| `description` | Policy description — used as the identity key for matching |
| `action` | `allow` or `log` |
| `expression` | Cloudflare filter expression |
| `enabled` | Boolean |
| `value` | CSP directive string |

**How it works:**

- The `description` field is the identity key (like `ref` for rules and `name` for lists). Policies are matched between YAML and Cloudflare by description.
- The presence of a `page_shield_policies:` key means ALL policies are managed — policies in Cloudflare not in YAML are planned for deletion.
- If the `page_shield_policies:` key is absent, policies are ignored entirely.
- During sync, policies are applied **after** lists and **before** custom rulesets and phases.
- Use `octorules dump` to export existing Page Shield policies to YAML.

## Linting

127 Cloudflare-specific lint rules (CF prefix) across 6 ranges:

| Range | Category | Rules |
|-------|----------|-------|
| CF001–CF025 | Structure & parse | 25 |
| CF100–CF104 | Cross-rule ordering | 5 |
| CF200–CF217 | Action validation | 18 |
| CF300–CF309 | Expression, function & type | 10 |
| CF400–CF475 | Domain-specific (rate limit, cache, config, redirect, transform, origin, page shield, list) | 34 |
| CF500–CF545 | Plan limits, style & value constraints | 35 |

See [docs/lint-rules/README.md](docs/lint-rules/README.md) for the full rule reference.

## Development

```bash
git clone git@github.com:doctena-org/octorules-cloudflare.git
cd octorules-cloudflare
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

The pre-commit hook auto-regenerates `schemas.json` (the frozen schema fallback
for users without wirefilter) whenever `overlay.toml` or `pyproject.toml`
changes. See [docs/schemas.md](docs/schemas.md) for the full schema
architecture.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
