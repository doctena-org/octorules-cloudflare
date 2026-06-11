# Stage 3: Plan-Tier Checks

Checks rule counts and feature availability against your Cloudflare plan tier.

## Category H — Plan/Entitlement Checks (3 rules)

### CF500 — Regex operator not available on Free plan

| Severity | Category |
|----------|----------|
| WARNING | plan |

Triggers when the plan tier is below Business and a rule's expression uses regex (`matches` operator or regex literals).

Fix: Upgrade to Business or Enterprise plan, or rewrite the expression without regex.

### CF501 — Rule count exceeds plan limit for phase

| Severity | Category |
|----------|----------|
| WARNING | plan |

Triggers when the number of rules in a phase exceeds the configured plan tier's limit (e.g., Free tier allows 10 rules for most phases, 5 for `waf_custom_rules`, and 1 `rate_limiting_rules`; Enterprise allows 300 per rules-engine phase, 1,000 `waf_custom_rules`, and 100 `rate_limiting_rules`, per Cloudflare's documented quotas after the 2025-02-12 limit increase).

Fix: Reduce the number of rules or upgrade your plan tier. Enterprise contracts can negotiate higher quotas than the documented defaults — if your zone has a negotiated limit, suppress the finding with `# octorules:disable=CF501`.

### CF502 — Expression exceeds 64 regex pattern limit

| Severity | Category |
|----------|----------|
| WARNING | plan |

Triggers when a single expression contains more than 64 regex patterns (the Cloudflare per-rule limit).

Fix: Split the rule into multiple rules to stay under the 64 regex limit.
