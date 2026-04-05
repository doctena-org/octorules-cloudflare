# Cloudflare API Token Permissions

This document lists the Cloudflare dashboard permissions required for each
octorules-cloudflare feature.  Permissions are listed as they appear in the
Cloudflare dashboard under **Manage Account > Account API Tokens**.

> **Graceful degradation** — if the token lacks a permission for an optional
> extension (`cloudflare_bot_management`, `cloudflare_zone_security`, etc.),
> the dump and plan commands silently skip that extension.  If the extension
> section IS declared in your YAML, a clear permission error is raised.

> **Verification status** — permissions marked with a checkmark have been
> verified against a live Cloudflare API token.  Unverified entries are based
> on Cloudflare's dashboard grouping and may need correction.

## Phase Rules

All phase rules use the Cloudflare Rulesets API.  Each phase maps to a
specific dashboard permission.

**Verified** (confirmed working with a token that has these permissions):

| Phase | Permission | Scope | Verified |
|---|---|---|---|
| `redirect_rules` | Zone > Single Redirect | Read/Edit | Yes |
| `url_rewrite_rules` | Zone > Transform Rules | Read/Edit | Yes |
| `request_header_rules` | Zone > Transform Rules | Read/Edit | Yes |
| `response_header_rules` | Zone > Transform Rules | Read/Edit | Yes |
| `config_rules` | Zone > Config Rules | Read/Edit | Yes |
| `origin_rules` | Zone > Origin Rules | Read/Edit | Yes |
| `cache_rules` | Zone > Cache Rules | Read/Edit | Yes |
| `compression_rules` | Zone > Response Compression | Read/Edit | Yes |
| `custom_error_rules` | Zone > Custom Error Rules | Read/Edit | Yes |
| `waf_custom_rules` | Zone > Zone WAF | Read/Edit | Yes |
| `waf_managed_rules` | Zone > Zone WAF | Read/Edit | Yes |
| `rate_limiting_rules` | Zone > Zone WAF | Read/Edit | Yes |
| `bot_fight_rules` | Zone > Bot Management | Read/Edit | Yes |
| `sensitive_data_detection` | Zone > Zone WAF | Read/Edit | Yes |
| `http_ddos_rules` | Zone > HTTP DDoS Managed Ruleset | Read/Edit | Yes |
| `log_custom_fields` | Zone > Logs | Read/Edit | Yes |
| `bulk_redirect_rules` | Account > Account Rulesets | Read/Edit | Yes |
| `network_ddos_rules` | Account > Account Rulesets | Read/Edit | Yes |
| `network_firewall_rules` | Account > Account Rulesets | Read/Edit | Yes |
| `network_firewall_managed` | Account > Account Rulesets | Read/Edit | Yes |
| `network_firewall_ratelimit` | Account > Account Rulesets | Read/Edit | Yes |
| `network_firewall_ids` | Account > Account Rulesets | Read/Edit | Yes |

**Unverified** (requires a permission not yet identified):

| Phase | Expected Permission | Scope | Notes |
|---|---|---|---|
| `url_normalization` (phase) | Unverified | Read/Edit | Returns 403; see URL Normalization note below |

## Account-Level Features

| Feature | Permission | Scope | Verified |
|---|---|---|---|
| Custom rulesets | Account > Account Rulesets | Read/Edit | Yes |
| Lists (IP, ASN, hostname, redirect) | Account > Account Filter Lists | Read/Edit | Yes |

## Zone-Level Extensions

| Extension | API Endpoint | Permission | Verified |
|---|---|---|---|
| `page_shield_policies` | `/zones/{id}/page_shield/policies` | Zone > Client-side security | Yes |
| `cloudflare_bot_management` | `/zones/{id}/bot_management` | Zone > Bot Management | Yes |
| `cloudflare_zone_security` | `/zones/{id}/settings/{setting}` | Zone > Zone Settings | Yes |
| `cloudflare_leaked_credential_check` | `/zones/{id}/leaked-credential-checks` | Zone > Zone WAF | Yes |
| `cloudflare_content_scanning` | `/zones/{id}/content-upload-scan/*` | Zone > Zone WAF | Yes |
| `cloudflare_url_normalization` | `/zones/{id}/url_normalization` | Unverified (see note below) | No |

## Base Requirements

All operations require **Zone > Zone > Read** to resolve zone names to IDs.

For sync (applying changes), the corresponding Edit permission is needed.
For plan and dump, Read is sufficient.

## URL Normalization Permission Note

The `cloudflare_url_normalization` extension uses the `/zones/{id}/url_normalization`
endpoint.  Cloudflare does not document which API token permission controls
this endpoint.  In the dashboard, the setting appears under **Rules > Settings
\> URL Normalization**.

The following permissions have been tested and confirmed **not** to grant
access (all with Edit scope, on a token with Zone > Zone > Edit):

- Zone Settings, Zone WAF, Firewall Services, Config Rules, Transform Rules,
  Bot Management, Page Rules, Single Redirect, Cache Rules, Custom Error Rules,
  Origin Rules, Response Compression, HTTP DDoS Managed Ruleset, Logs,
  Client-side security, DNS, Zone (Edit)

The endpoint may require a permission not available as a scoped API token
toggle, or it may only be accessible via a Global API Key.  If you know or
discover the correct permission, please open an issue.
