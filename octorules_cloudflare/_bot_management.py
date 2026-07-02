"""Bot management settings for Cloudflare zones.

These are non-phase YAML sections handled via extension hooks:
- ``cloudflare_bot_management`` -- fight mode, JS detection, AI bot
  protection, session scoring, and model version info

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging

from octorules.registration import idempotent_registration

from octorules_cloudflare._settings_base import (
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
)
from octorules_cloudflare._settings_common import (
    make_dump_hook,
    make_prefetch_hook,
    partition_unsupported,
    verify_settings_applied,
    warn_unsupported,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for bot management diffs
# ---------------------------------------------------------------------------
class BotManagementChange(SettingsChange):
    """A single field change in bot management settings."""


class BotManagementPlan(SettingsPlan):
    """Plan for all bot management changes in a zone."""


# ---------------------------------------------------------------------------
# Valid enum values
# ---------------------------------------------------------------------------
_VALID_AI_BOTS_PROTECTION = frozenset({"block", "disabled"})
_VALID_CRAWLER_PROTECTION = frozenset({"enabled", "disabled"})


# ---------------------------------------------------------------------------
# Normalization: SDK response -> YAML-friendly canonical form
# ---------------------------------------------------------------------------
_NORMALIZE_FIELDS: dict[str, type] = {
    "fight_mode": bool,
    "enable_js": bool,
    "ai_bots_protection": str,
    "suppress_session_score": bool,
    "using_latest_model": bool,
    "crawler_protection": str,
    "auto_update_model": bool,
}


def normalize_bot_management(raw: dict) -> dict:
    """Convert Cloudflare bot_management.get() response to YAML-friendly form.

    Only includes fields that are present in the raw response.
    """
    if not raw:
        return {}

    result: dict = {}
    for yaml_key, expected_type in _NORMALIZE_FIELDS.items():
        val = raw.get(yaml_key)
        if val is not None:
            if expected_type is bool:
                result[yaml_key] = bool(val)
            else:
                result[yaml_key] = val
    return result


# ---------------------------------------------------------------------------
# Denormalization: YAML canonical form -> SDK update kwargs
# ---------------------------------------------------------------------------
# Read-only fields: returned by the API but rejected/ignored on update.
# Excluded from both the PATCH body and the diff — diffing a field apply
# cannot send would produce a Modify that can never converge.
_READ_ONLY_FIELDS = frozenset({"using_latest_model"})


def denormalize_bot_management(settings: dict) -> dict:
    """Convert YAML canonical form back to SDK kwargs for bot_management.update().

    Only includes keys that are present in *settings* so that partial
    updates don't reset unspecified fields to defaults.

    The ``using_latest_model`` field is read-only and always excluded.
    """
    if not settings:
        return {}

    result: dict = {}
    for key in (
        "fight_mode",
        "enable_js",
        "ai_bots_protection",
        "suppress_session_score",
        "crawler_protection",
        "auto_update_model",
    ):
        if key in settings:
            result[key] = settings[key]
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_bot_management(current: dict, desired: dict) -> BotManagementPlan:
    """Diff current vs desired bot management settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    desired, unsupported = partition_unsupported(current, desired)
    changes: list[BotManagementChange] = []
    for key in sorted(desired.keys()):
        if key in _READ_ONLY_FIELDS:
            continue
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(BotManagementChange(field=key, current=cur, desired=des))
    return BotManagementPlan(changes=changes, unsupported=unsupported)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
_prefetch_bot_management = make_prefetch_hook("cloudflare_bot_management", "get_bot_management")


def _finalize_bot_management(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_bot_management(current, desired)
    if plan.unsupported:
        warn_unsupported("cloudflare_bot_management", scope, plan.unsupported)
    if plan.has_changes or plan.unsupported:
        zp.extension_plans.setdefault("cloudflare_bot_management", []).append(plan)


def _apply_bot_management(zp, plans, scope, provider):
    """Apply bot management settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_bot_management(scope, desired_values)
            verify_settings_applied(
                provider.get_bot_management, scope, desired_values, "cloudflare_bot_management"
            )
            synced.append("cloudflare_bot_management")

    return synced, None


def _validate_bot_management(desired, zone_name, errors, lines):
    """Validate cloudflare_bot_management offline."""
    settings = desired.get("cloudflare_bot_management")
    if not isinstance(settings, dict):
        return

    ai_bots = settings.get("ai_bots_protection")
    if ai_bots is not None and ai_bots not in _VALID_AI_BOTS_PROTECTION:
        errors.append(
            f"  {zone_name}/cloudflare_bot_management: invalid"
            f" ai_bots_protection {ai_bots!r}"
            f" (must be one of {sorted(_VALID_AI_BOTS_PROTECTION)})"
        )

    crawler = settings.get("crawler_protection")
    if crawler is not None and crawler not in _VALID_CRAWLER_PROTECTION:
        errors.append(
            f"  {zone_name}/cloudflare_bot_management: invalid"
            f" crawler_protection {crawler!r}"
            f" (must be one of {sorted(_VALID_CRAWLER_PROTECTION)})"
        )

    for key in ("fight_mode", "enable_js", "suppress_session_score", "auto_update_model"):
        val = settings.get(key)
        if val is not None and not isinstance(val, bool):
            errors.append(
                f"  {zone_name}/cloudflare_bot_management: invalid"
                f" {key} {val!r} (must be a boolean)"
            )

    # using_latest_model is read-only info; warn if user tries to set it
    if "using_latest_model" in settings:
        errors.append(
            f"  {zone_name}/cloudflare_bot_management:"
            f" using_latest_model is read-only and cannot be set"
        )


_dump_bot_management = make_dump_hook("cloudflare_bot_management", "get_bot_management")


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class BotManagementFormatter(SettingsFormatter):
    """Formats bot management diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(
            plan_type=BotManagementPlan,
            prefix="bot_management",
            phase="bot_management",
            provider_id="cloudflare_bot_management",
        )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_bot_management() -> None:
    """Register all bot management hooks with the core extension system."""
    from octorules.extensions import (
        register_apply_extension,
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_bot_management, _finalize_bot_management)
    register_apply_extension("cloudflare_bot_management", _apply_bot_management)
    register_format_extension("cloudflare_bot_management", BotManagementFormatter())
    register_validate_extension(_validate_bot_management)
    register_dump_extension(_dump_bot_management)
