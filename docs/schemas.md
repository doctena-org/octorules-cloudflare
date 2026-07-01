# Schema Architecture

The linter needs to know every valid Cloudflare field and function, along with
metadata that determines where and how each can be used. This page documents
how that data is sourced, merged, and consumed.

## Two data sources

### 1. wirefilter (Rust FFI)

[octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter) is a
**required dependency**. It provides the authoritative list of **field names**,
**field types**, and **function names** — the same data Cloudflare's own engine
uses to validate expressions — via `get_schema_info()`.

wirefilter ships **two field schemes**, selected per ruleset phase:

| Scheme | `get_schema_info(scheme=…)` | Phases |
|---|---|---|
| HTTP (default) | `get_schema_info()` | All HTTP / L7 phases (the large majority) |
| Magic Firewall (L4) | `get_schema_info("magic_firewall")` | The 5 account-level Magic Transit phases — packet fields (`ip.proto`, `tcp.*`, `udp.*`, …) |

Each scheme's field list is produced by **iterating the built scheme** — there is
no parallel name list to keep in sync. The `register_common_fields` (HTTP) and
`register_magic_firewall_fields` (L4) functions in
`octorules-wirefilter/src/scheme.rs` are the single source of truth for field
names and types.

wirefilter has no concept of billing plans, response-only fields, or per-phase
availability. It validates pure expression grammar and types.

### 2. overlay.toml (Python-only metadata)

[`overlay.toml`](../octorules_cloudflare/linter/schemas/overlay.toml) adds Cloudflare
product-level properties that wirefilter doesn't track:

| Property | Meaning | Example |
|---|---|---|
| `requires_plan` | Billing plan that gates the field/function | `cf.waf.score` → `"enterprise"` |
| `is_response` | Field only available in response phases | `http.response.code` → `true` |
| `restricted_phases` | Function only allowed in specific phases | `sha256` → transform phases only |

Only entries that differ from defaults are listed. Defaults: `requires_plan = ""`,
`is_response = false`, `restricted_phases = []`.

The Magic Transit phase availability for L4 fields is applied in code
(`_registry.MAGIC_FIREWALL_PHASES`) rather than per-field in overlay.toml, since
every L4 field shares the same five-phase availability.

## Data flow

```
octorules-wirefilter (Rust, required)        overlay.toml
  HTTP scheme + Magic Firewall scheme          plan, response, phase metadata
  (field names + types, function names)
        │                                              │
        └──────────────────┬───────────────────────────┘
                           ↓
                     _registry.py
                merges at import time
                           ↓
        fields.py FIELDS dict    functions.py FUNCTIONS dict
                           ↓
        ast_linter.py          phase_linter.py
        (field/function         (phase availability
         validation)             checks)
```

There is **no frozen fallback**: wirefilter is a required dependency, so
`get_schema_info()` is always available.

## Key files

| File | Role |
|---|---|
| [`_registry.py`](../octorules_cloudflare/linter/schemas/_registry.py) | Import-time loader: wirefilter (HTTP + L4) + overlay → dicts |
| [`overlay.toml`](../octorules_cloudflare/linter/schemas/overlay.toml) | Python-only metadata (plan, response, phase restrictions) |
| [`fields.py`](../octorules_cloudflare/linter/schemas/fields.py) | `FIELDS` registry, `FieldDef` dataclass, manual entries |
| [`functions.py`](../octorules_cloudflare/linter/schemas/functions.py) | `FUNCTIONS` registry, `FunctionDef` dataclass |

## Manual entries

A few fields are registered directly in `fields.py` as Python code, outside the
wirefilter-loaded data. These are the entries **not** exposed by
`get_schema_info()` (the `COMMON_FIELD_EXCLUSIONS` set in wirefilter):

- **Deprecated `ip.geoip.*` fields** — kept so the linter emits a "use
  `ip.src.*` instead" finding rather than "unknown field"
- **Account-level fields** (`cf.zone.name`, `cf.zone.plan`)
- **`http.request.uri.path`** — wirefilter registers it as a field, but in
  transform phases Cloudflare also treats it as a callable function

## Adding a field

Field names and types live in **one place** — `register_common_fields` (HTTP) or
`register_magic_firewall_fields` (L4) in `octorules-wirefilter/src/scheme.rs`.
Add the field there, rebuild wirefilter (`maturin develop`), and it flows
automatically through `get_schema_info()` → `_registry.py` → the `FIELDS`
registry. Only **metadata** (plan tier, response, phase restriction) is edited on
the Python side, in `overlay.toml`.

## Editing overlay.toml

When adding or changing metadata:

1. Edit `overlay.toml` with the new entry.
2. If adding a field/function that wirefilter doesn't report at all, add it to
   the `[fields]` or `[functions]` section — `_registry.py` includes
   overlay-only entries automatically.

Source of truth for plan requirements and phase restrictions: Cloudflare
dashboard and [API docs](https://developers.cloudflare.com/ruleset-engine/rules-language/).
