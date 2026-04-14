"""Bot management settings for Cloudflare zones.

These are non-phase YAML sections handled via extension hooks:
- ``cloudflare_bot_management`` -- fight mode, JS detection, AI bot
  protection, session scoring, and model version info

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for bot management diffs
# ---------------------------------------------------------------------------
@dataclass
class BotManagementChange:
    """A single field change in bot management settings."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class BotManagementPlan:
    """Plan for all bot management changes in a zone."""

    changes: list[BotManagementChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


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
    changes: list[BotManagementChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(BotManagementChange(field=key, current=cur, desired=des))
    return BotManagementPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_bot_management(all_desired, scope, provider):
    """Prefetch: fetch current bot management settings."""
    if not scope.zone_id:
        return None
    desired = all_desired.get("cloudflare_bot_management")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_bot_management(scope)
    except ProviderAuthError:
        if "cloudflare_bot_management" in all_desired:
            raise  # User explicitly declared this section -- permission is needed
        log.debug("Skipping cloudflare_bot_management (no permission and not in desired config)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_bot_management: product not enabled on this zone")
            return None
        log.warning("Failed to fetch bot management settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_bot_management(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_bot_management(current, desired)
    if plan.has_changes:
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


def _dump_bot_management(scope, provider, out_dir):
    """Export current bot management settings to dump output."""
    if not scope.zone_id:
        return None
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_bot_management(scope)
    except ProviderAuthError:
        log.info("cloudflare_bot_management: skipped (insufficient permissions)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_bot_management: product not enabled on this zone")
        else:
            log.debug("cloudflare_bot_management: %s", e)
        return None

    if settings:
        return {"cloudflare_bot_management": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class BotManagementFormatter:
    """Formats bot management diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"bot_management.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
                continue
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "field": change.field,
                        "current": change.current,
                        "desired": change.desired,
                    }
                )
            if changes:
                result.append({"changes": changes})
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"bot_management.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"bot_management.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, BotManagementPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "bot_management",
                    "provider_id": "cloudflare_bot_management",
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
_registered = False


def register_bot_management() -> None:
    """Register all bot management hooks with the core extension system."""
    global _registered
    if _registered:
        return
    _registered = True

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
