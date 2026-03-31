# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.1] - 2026-03-31

### Changed
- CF203 (`unknown action_parameters key`) severity corrected from ERROR to WARNING, matching its rule definition.
- `ExpressionInfo` is now a frozen dataclass for cache safety.
- `parse_expression()` results are cached per expression, eliminating redundant wirefilter FFI calls across linter passes.
- `_load_overlay()` is now cached with `lru_cache`, avoiding repeated disk reads of `overlay.toml`.
- `sync_schemas.py` reuses `merge_wirefilter_overlay()` from the registry module instead of duplicating schema merge logic.

### Fixed
- CF421 now fires when `ssl` is a non-string type (e.g., YAML `off` parsed as boolean `False`).

### Added
- Tests for `create_custom_ruleset` and `delete_custom_ruleset` (account/zone scope, error wrapping).

### Removed
- Dead `py.typed` marker file.
- Empty `linter/rules/` directory.

## [0.5.0] - 2026-03-30

### Changed
- `_to_dict()` now raises `ProviderError` on conversion failure instead of
  silently returning an empty dict. Removed lenient/strict split
  (`_ruleset_to_dict` / `_rule_to_dict` helpers deleted).
- Page Shield apply replaced local sequential `_apply_parallel()` stub with
  the shared core `_apply_parallel()` import.
- API field filtering uses shared `strip_api_fields()` from core instead of
  inline `get_api_fields()` + dict comprehension.

### Fixed
- Bulk operation polling logs status at DEBUG level for diagnosability.

## [0.4.2] - 2026-03-30

### Fixed
- `_fetch_parallel()`: catch `concurrent.futures.TimeoutError` explicitly
  instead of `builtins.TimeoutError`, which did not match on Python 3.10.

### Changed
- `_normalize_plan_name()` now logs a warning when encountering an
  unrecognized Cloudflare plan name instead of silently returning the
  lowercased value.

## [0.4.1] - 2026-03-30

### Changed
- `_fetch_parallel()`: add `_PARALLEL_FETCH_TIMEOUT` (300 s) to
  `future.result()` to prevent indefinite hangs; `TimeoutError` is now
  caught and treated as a transient failure.
- Page Shield prefetch timeout extracted to `_PREFETCH_TIMEOUT` constant.
- Document `ThreadPoolExecutor` lifecycle in `_prefetch_page_shield`.
- `get_list_items()`: `JSONDecodeError` is now retried (may be caused by
  truncated HTTP responses) alongside `APIError` / `APIConnectionError`.
- `get_list_items()`: retry backoff now uses the shared `_POLL_BACKOFF`
  schedule instead of a linear `(attempt + 1) * 1.0` calculation.

### Added
- Ruff `B` (bugbear) and `RUF` lint rule categories to `pyproject.toml`.
- Per-file ruff ignores for test files (intentional unicode, regex patterns).
- Tests for `JSONDecodeError` retry-then-succeed path.

## [0.4.0] - 2026-03-25

### Added
- Audit IP extractor: extracts IP literals from wirefilter expressions and
  `$list_name` references for use by `octorules audit`.
- Export `CF_PHASE_NAMES` frozenset from package root.

## [0.3.1] - 2026-03-24

### Changed
- Default `timeout` from `None` to `30.0` seconds in `CloudflareProvider`.
  Prevents silent hangs if the Cloudflare API becomes unresponsive.
  Pass `timeout=None` explicitly to restore the previous behavior (SDK default).
- Extract `_LIST_ITEMS_PER_PAGE` and `_POLL_BACKOFF` module-level constants
  from inline magic numbers in `provider.py`.
- Add `timeout=120` to `future.result()` in Page Shield prefetch to prevent
  indefinite hangs during plan operations.

### Added
- `TestFetchParallelConcurrency` tests: partial failure, auth error
  propagation, worker capping, and mixed success under real concurrency.
- `TestErrorMapping` tests: verify each Cloudflare SDK exception type maps
  to the correct octorules exception, with message and chain preservation.
- `TestGetListItemsRetryExhaustion` tests: all retries fail, partial page
  success, zero-retries mode, and retry warning logging.

## [0.3.0] - 2026-03-23

### Added
- `create_custom_ruleset` and `delete_custom_ruleset` provider methods.
  Required by the updated `BaseProvider` protocol for custom ruleset
  lifecycle management. Cloudflare implementation calls the rulesets API
  directly (`rulesets.create` / `rulesets.delete`).

### Changed
- Requires `octorules>=0.18.0`.
- Consolidated `_ruleset_to_dict` and `_rule_to_dict` into shared `_to_dict`
  helper with strict/lenient modes.
- Moved `get_api_fields("list_item")` call outside pagination loop in
  `get_list_items` for better performance.

## [0.2.0] - 2026-03-19

### Added
- **Lint result locations.** YAML source locations (e.g. `doctena.com.yaml:106`)
  now appear in lint output for all CF rules.
- **Page Shield support** (`octorules_cloudflare.page_shield`). All Page Shield
  planning, applying, formatting, validation, and dumping code extracted from
  octorules core. Registered via the new extension hook system at import time.
  - `PageShieldPolicyPlan` dataclass
  - `diff_page_shield_policies()` — full diff using description as identity key
  - `validate_page_shield_policy()` — offline validation
  - `format_csp_value()` — readable multi-line YAML formatting for CSP values
  - `normalize_csp_value()` — **CSP source sorting** so reordering sources
    in YAML does not trigger an upstream change (source order is not
    significant in CSP)
  - `_apply_page_shield()` — create/update/delete via CF API
  - `_plan_page_shield()` — plan zone hook
  - `_dump_page_shield()` — dump hook with API field stripping
  - `PageShieldFormatter` — text/JSON/markdown/HTML/report formatting

### Changed
- Error wrapping uses `make_error_wrapper` and `format_api_error` from
  `octorules.provider.utils` instead of hand-rolled implementations.
- Requires `octorules>=0.17.0`.

## [0.1.0] - 2026-03-17

### Added

- Initial release: CloudflareProvider extracted from octorules core.
- Document `octorules:` rule-level metadata support (`ignored`, `included`,
  `excluded`) — inherited from octorules core.
- **Lint rule IDs use CF prefix.** All 127 rule IDs use provider-prefixed IDs
  (CF001–CF545) for consistency with AWS (WA*) and Google (GA*) providers.
- Entry point `octorules.providers: cloudflare` for auto-discovery by octorules core.
- Exception wrapping: CF SDK exceptions mapped to provider-agnostic base types.
- **`_cf_prepare_rule` hook.** Registered on all 23 Cloudflare phases via
  `Phase.prepare_rule`. Handles expression normalization, `enabled` defaulting,
  `counting_expression` normalization, and default action injection. This logic
  was previously in the octorules core planner.
- **Multi-provider linter scoping.** CF linter (yaml_validator, action_validator,
  etc.) only checks Cloudflare phases — ignores AWS/Google phases when multiple
  providers are installed.
- `CF_PHASE_NAMES`: exported frozenset of all 23 Cloudflare phase names.
- Linter plugin registers Cloudflare-specific API fields to strip
  (`register_api_fields()`) for rules, list items, and Page Shield policies.
- Linter plugin registers phase alias `waf_managed_exceptions` →
  `waf_managed_rules` via `register_phase_alias()`.
- Linter plugin registers non-phase keys (`custom_rulesets`, `lists`,
  `page_shield_policies`) via `register_non_phase_key()`.
- Schema docs (`docs/schemas.md`) and code-generation scripts
  (`scripts/sync_schemas.py`, `scripts/generate_fields.py`) moved from
  octorules core.

### Changed

- `CloudflareProvider.__init__` now uses keyword-only arguments (octodns-style
  kwargs passthrough). `token` is required; unknown kwargs are accepted and
  ignored.
- Provider method signatures use `provider_id` / `provider_ids` instead of
  `cf_phase` / `cf_phases` to match the octorules 0.16.0 `BaseProvider`
  protocol.
