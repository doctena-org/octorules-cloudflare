# Cloudflare API Token Permissions

This document lists the Cloudflare dashboard permissions required for each
octorules-cloudflare feature. Permissions are listed as they appear in the
Cloudflare dashboard under **Manage Account > Account API Tokens**.

For the full list of available Cloudflare API token permissions, see the
[API token permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

> **Graceful degradation** — if the token lacks a permission for an optional
> extension (`cloudflare_bot_management`, `cloudflare_zone_security`, etc.),
> the dump and plan commands silently skip that extension. If the extension
> section IS declared in your YAML, a clear permission error is raised.

## Base Requirements

All operations require **Zone > Zone > Read** to resolve zone names to IDs.

For sync (applying changes), the corresponding Edit permission is needed.
For plan and dump, Read is sufficient.

## Phase Rules

All phase rules use the Cloudflare Rulesets API. Each phase maps to a
specific dashboard permission.

| Phase | Permission | Scope |
|---|---|---|
| `redirect_rules` | Zone > Single Redirect | Read/Edit |
| `url_rewrite_rules` | Zone > Transform Rules | Read/Edit |
| `request_header_rules` | Zone > Transform Rules | Read/Edit |
| `response_header_rules` | Zone > Transform Rules | Read/Edit |
| `config_rules` | Zone > Config Rules | Read/Edit |
| `origin_rules` | Zone > Origin Rules | Read/Edit |
| `cache_rules` | Zone > Cache Rules | Read/Edit |
| `compression_rules` | Zone > Response Compression | Read/Edit |
| `custom_error_rules` | Zone > Custom Error Rules | Read/Edit |
| `waf_custom_rules` | Zone > Zone WAF | Read/Edit |
| `waf_managed_rules` | Zone > Zone WAF | Read/Edit |
| `rate_limiting_rules` | Zone > Zone WAF | Read/Edit |
| `bot_fight_rules` | Zone > Bot Management | Read/Edit |
| `sensitive_data_detection` | Zone > Zone WAF | Read/Edit |
| `http_ddos_rules` | Zone > HTTP DDoS Managed Ruleset | Read/Edit |
| `log_custom_fields` | Zone > Logs | Read/Edit |
| `url_normalization` | Zone > Sanitize | Read/Edit |
| `bulk_redirect_rules` | Account > Account Rulesets | Read/Edit |
| `network_ddos_rules` | Account > Account Rulesets | Read/Edit |
| `network_firewall_rules` | Account > Account Rulesets | Read/Edit |
| `network_firewall_managed` | Account > Account Rulesets | Read/Edit |
| `network_firewall_ratelimit` | Account > Account Rulesets | Read/Edit |
| `network_firewall_ids` | Account > Account Rulesets | Read/Edit |

## Account-Level Features

| Feature | Permission | Scope |
|---|---|---|
| Custom rulesets | Account > Account Rulesets | Read/Edit |
| Lists (IP, ASN, hostname, redirect) | Account > Account Filter Lists | Read/Edit |

## Zone-Level Extensions

| Extension | API Endpoint | Permission |
|---|---|---|
| `page_shield_policies` | `/zones/{id}/page_shield/policies` | Account > Page Shield |
| `cloudflare_bot_management` | `/zones/{id}/bot_management` | Zone > Bot Management |
| `cloudflare_zone_security` | `/zones/{id}/settings/{setting}` | Zone > Zone Settings |
| `cloudflare_url_normalization` | `/zones/{id}/url_normalization` | Zone > Sanitize |
| `cloudflare_leaked_credential_check` | `/zones/{id}/leaked-credential-checks` | Zone > Zone WAF |
| `cloudflare_content_scanning` | `/zones/{id}/content-upload-scan/*` | Zone > Zone WAF |
