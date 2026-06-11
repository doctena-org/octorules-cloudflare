"""Shared constants for Cloudflare linter modules."""

# Plan tier hierarchy for comparison
PLAN_TIERS: dict[str, int] = {"free": 0, "pro": 1, "business": 2, "enterprise": 3}

# Cloudflare's Rulesets API rejects a rule expression longer than 4096
# characters with API error 20127 ("expression size N exceeded maximum
# 4096"). CF measures the canonical (whitespace-normalized) form — the same
# form octorules sends — so checks must measure the normalized length
# (CF224 in action_validator does). The cap is breached at 4097+.
MAX_EXPRESSION_LENGTH = 4096
