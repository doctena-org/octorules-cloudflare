# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
