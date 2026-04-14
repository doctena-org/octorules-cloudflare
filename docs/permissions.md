# Cloudflare API Token Permissions

This document lists the Cloudflare dashboard permissions required for each
octorules-cloudflare feature. Permission names match the Cloudflare dashboard
under **Manage Account > Account API Tokens**.

For the full list of available Cloudflare API token permissions, see the
[API token permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

> **Graceful degradation** — if the token lacks a permission for an optional
> extension, the dump and plan commands skip that extension and log the
> reason at info level (`insufficient permissions`). If a product is not
> enabled on the zone, it is logged at debug level (`product not enabled`).
> Use `--debug` to see all skipped extensions. If the extension section IS
> declared in your YAML but the token lacks permission, a clear error is raised.

## Base Requirements

All operations require **Zone > Zone > Read** to resolve zone names to IDs.

For sync (applying changes), the corresponding Write permission is needed.
For plan and dump, Read is sufficient.

## Phase Rules

All phase rules use the Cloudflare Rulesets API. Each phase maps to a
specific dashboard permission.

| Phase | Permission | Scope |
|---|---|---|
| `redirect_rules` | Zone > Dynamic URL Redirects | Read/Write |
| `url_rewrite_rules` | Zone > Zone Transform Rules | Read/Write |
| `request_header_rules` | Zone > Zone Transform Rules | Read/Write |
| `response_header_rules` | Zone > Zone Transform Rules | Read/Write |
| `config_rules` | Zone > Config Settings | Read/Write |
| `origin_rules` | Zone > Origin | Read/Write |
| `cache_rules` | Zone > Cache Settings | Read/Write |
| `compression_rules` | Zone > Response Compression | Read/Write |
| `custom_error_rules` | Zone > Custom Errors | Read/Write |
| `waf_custom_rules` | Zone > Zone WAF | Read/Write |
| `waf_managed_rules` | Zone > Zone WAF | Read/Write |
| `rate_limiting_rules` | Zone > Zone WAF | Read/Write |
| `bot_fight_rules` | Zone > Bot Management | Read/Write |
| `sensitive_data_detection` | Zone > Zone WAF | Read/Write |
| `http_ddos_rules` | Zone > HTTP DDoS Managed Ruleset | Read/Write |
| `log_custom_fields` | Zone > Logs | Read/Write |
| `url_normalization` | Zone > Sanitize | Read/Write |
| `bulk_redirect_rules` | Account > Account Rulesets | Read/Write |
| `network_ddos_rules` | Account > Account Rulesets | Read/Write |
| `network_firewall_rules` | Account > Account Rulesets | Read/Write |
| `network_firewall_managed` | Account > Account Rulesets | Read/Write |
| `network_firewall_ratelimit` | Account > Account Rulesets | Read/Write |
| `network_firewall_ids` | Account > Account Rulesets | Read/Write |

## Account-Level Features

| Feature | Permission | Scope |
|---|---|---|
| Custom rulesets | Account > Account Rulesets | Read/Write |
| Lists (IP, ASN, hostname, redirect) | Account > Account Rule Lists | Read/Write |

## Zone-Level Extensions

| Extension | API Endpoint | Permission |
|---|---|---|
| `page_shield_policies` | `/zones/{id}/page_shield/policies` | Account > Page Shield |
| `cloudflare_bot_management` | `/zones/{id}/bot_management` | Zone > Bot Management |
| `cloudflare_zone_security` | `/zones/{id}/settings/{setting}` | Zone > Zone Settings |
| `cloudflare_url_normalization` | `/zones/{id}/url_normalization` | Zone > Sanitize |
| `cloudflare_leaked_credential_check` | `/zones/{id}/leaked-credential-checks` | Zone > Zone WAF |
| `cloudflare_content_scanning` | `/zones/{id}/content-upload-scan/*` | Zone > Zone WAF |
