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
from dataclasses import dataclass, field

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
@dataclass
class ZoneSecurityChange:
    """A single field change in zone security settings."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class ZoneSecurityPlan:
    """Plan for all zone security setting changes in a zone."""

    changes: list[ZoneSecurityChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


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
    changes: list[ZoneSecurityChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(ZoneSecurityChange(field=key, current=cur, desired=des))
    return ZoneSecurityPlan(changes=changes)


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
    if plan.has_changes:
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
class ZoneSecurityFormatter:
    """Formats zone security setting diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"zone_security.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
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
            if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"zone_security.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"zone_security.{change.field}")
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
            if not isinstance(plan, ZoneSecurityPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "zone_security",
                    "provider_id": "cloudflare_zone_security",
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


def register_zone_security() -> None:
    """Register all zone security hooks with the core extension system."""
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

    register_plan_zone_hook(_prefetch_zone_security, _finalize_zone_security)
    register_apply_extension("cloudflare_zone_security", _apply_zone_security)
    register_format_extension("cloudflare_zone_security", ZoneSecurityFormatter())
    register_validate_extension(_validate_zone_security)
    register_dump_extension(_dump_zone_security)
