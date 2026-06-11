"""Zone security settings (WAF-relevant subset) managed as code.

Manages WAF-relevant zone-level settings:
- ``security_level`` — threat score threshold for challenges
- ``challenge_passage`` — seconds a visitor is allowed after challenge
- ``browser_integrity_check`` — whether BIC is on or off

These are fetched and updated via per-setting endpoints:
``client.zones.settings.get(setting_id, zone_id=...)`` and
``client.zones.settings.edit(setting_id, zone_id=..., value=...)``.

Uses the same extension hook pattern as ``page_shield.py`` and Azure's
``_policy_settings.py``: plan_zone_hook (prefetch + finalize),
apply_extension, format_extension, validate_extension, and dump_extension.
"""

import logging

from octorules.registration import idempotent_registration

from octorules_cloudflare._settings_base import (
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
)
from octorules_cloudflare._settings_common import (
    partition_unsupported,
    verify_settings_applied,
    warn_unsupported,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Setting IDs — the Cloudflare API setting_id values we manage
# ---------------------------------------------------------------------------
_SETTING_IDS: dict[str, str] = {
    "security_level": "security_level",
    "challenge_passage": "challenge_ttl",
    "browser_integrity_check": "browser_check",
}

# Valid enum values
_VALID_SECURITY_LEVELS = frozenset(
    {"off", "essentially_off", "low", "medium", "high", "under_attack"}
)
_VALID_ON_OFF = frozenset({"on", "off"})

# challenge_passage valid range (seconds)
_MIN_CHALLENGE_PASSAGE = 300
_MAX_CHALLENGE_PASSAGE = 86400


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class ZoneSecurityChange(SettingsChange):
    """A single field change in zone security settings."""


class ZoneSecurityPlan(SettingsPlan):
    """Plan for all zone security setting changes in a zone."""


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_zone_security(raw_settings: dict) -> dict:
    """Convert raw per-setting API responses to YAML-friendly canonical form.

    *raw_settings* is a dict of ``{yaml_field: api_value}`` — the caller
    fetches each setting individually and assembles the dict.
    """
    if not raw_settings:
        return {}
    result: dict = {}
    for key in ("security_level", "challenge_passage", "browser_integrity_check"):
        val = raw_settings.get(key)
        if val is not None:
            if key == "challenge_passage":
                result[key] = int(val) if not isinstance(val, int) else val
            else:
                result[key] = str(val) if not isinstance(val, str) else val
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_zone_security(current: dict, desired: dict) -> ZoneSecurityPlan:
    """Diff current vs desired zone security settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    desired, unsupported = partition_unsupported(current, desired)
    changes: list[ZoneSecurityChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(ZoneSecurityChange(field=key, current=cur, desired=des))
    return ZoneSecurityPlan(changes=changes, unsupported=unsupported)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_zone_security(all_desired, scope, provider):
    """Prefetch: fetch current zone security settings."""
    if not scope.zone_id:
        return None
    desired = all_desired.get("cloudflare_zone_security")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_zone_security_settings(scope)
    except ProviderAuthError:
        if "cloudflare_zone_security" in all_desired:
            raise  # User explicitly declared this section -- permission is needed
        log.debug("Skipping cloudflare_zone_security (no permission and not in desired config)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_zone_security: product not enabled on this zone")
            return None
        log.warning("Failed to fetch zone security settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_zone_security(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_zone_security(current, desired)
    if plan.unsupported:
        warn_unsupported("cloudflare_zone_security", scope, plan.unsupported)
    if plan.has_changes or plan.unsupported:
        zp.extension_plans.setdefault("cloudflare_zone_security", []).append(plan)


def _apply_zone_security(zp, plans, scope, provider):
    """Apply zone security setting changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_zone_security_settings(scope, desired_values)
            verify_settings_applied(
                provider.get_zone_security_settings,
                scope,
                desired_values,
                "cloudflare_zone_security",
            )
            synced.append("cloudflare_zone_security")

    return synced, None


def _validate_zone_security(desired, zone_name, errors, lines):
    """Validate cloudflare_zone_security offline."""
    settings = desired.get("cloudflare_zone_security")
    if not isinstance(settings, dict):
        return

    sl = settings.get("security_level")
    if sl is not None and sl not in _VALID_SECURITY_LEVELS:
        errors.append(
            f"  {zone_name}/cloudflare_zone_security: invalid"
            f" security_level {sl!r} (must be one of {sorted(_VALID_SECURITY_LEVELS)})"
        )

    cp = settings.get("challenge_passage")
    if cp is not None:
        if not isinstance(cp, int) or isinstance(cp, bool):
            errors.append(
                f"  {zone_name}/cloudflare_zone_security: invalid"
                f" challenge_passage {cp!r} (must be an integer)"
            )
        elif cp < _MIN_CHALLENGE_PASSAGE or cp > _MAX_CHALLENGE_PASSAGE:
            errors.append(
                f"  {zone_name}/cloudflare_zone_security: invalid"
                f" challenge_passage {cp!r}"
                f" (must be between {_MIN_CHALLENGE_PASSAGE} and {_MAX_CHALLENGE_PASSAGE})"
            )

    bic = settings.get("browser_integrity_check")
    if bic is not None and bic not in _VALID_ON_OFF:
        errors.append(
            f"  {zone_name}/cloudflare_zone_security: invalid"
            f" browser_integrity_check {bic!r} (must be 'on' or 'off')"
        )


def _dump_zone_security(scope, provider, out_dir):
    """Export current zone security settings to dump output."""
    if not scope.zone_id:
        return None
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_zone_security_settings(scope)
    except ProviderAuthError:
        log.info("cloudflare_zone_security: skipped (insufficient permissions)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_zone_security: product not enabled on this zone")
        else:
            log.debug("cloudflare_zone_security: %s", e)
        return None

    if settings:
        return {"cloudflare_zone_security": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ZoneSecurityFormatter(SettingsFormatter):
    """Formats zone security setting diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(
            plan_type=ZoneSecurityPlan,
            prefix="zone_security",
            phase="zone_security",
            provider_id="cloudflare_zone_security",
        )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_zone_security() -> None:
    """Register all zone security hooks with the core extension system."""
    from octorules.extensions import (
        register_apply_extension,
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_zone_security, _finalize_zone_security)
    register_apply_extension("cloudflare_zone_security", _apply_zone_security)
    register_format_extension("cloudflare_zone_security", ZoneSecurityFormatter())
    register_validate_extension(_validate_zone_security)
    register_dump_extension(_dump_zone_security)
