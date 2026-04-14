"""Content Scanning extension for Cloudflare zones.

Manages the Content Scanning feature:
- ``enabled`` — whether content scanning is active
- ``custom_expressions`` — list of custom scan payload expressions

Cloudflare SDK methods:
- ``client.content_scanning.settings.get(zone_id=...)`` — current status
- ``client.content_scanning.enable(zone_id=...)``
- ``client.content_scanning.disable(zone_id=...)``
- ``client.content_scanning.payloads.list(zone_id=...)``
- ``client.content_scanning.payloads.create(zone_id=..., body=[...])``
- ``client.content_scanning.payloads.delete(expression_id, zone_id=...)``

Uses the same extension hook pattern as ``_zone_security.py``:
plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension.
"""

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ContentScanningChange:
    """A single change in content scanning config."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class ContentScanningPlan:
    """Plan for all content scanning changes in a zone."""

    changes: list[ContentScanningChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
def _normalize_expression(expr: dict) -> dict:
    """Normalize a single custom expression to canonical form."""
    return {"payload": expr.get("payload", "")}


def _normalize_expressions(expressions: list[dict]) -> list[dict]:
    """Normalize and sort custom expressions for stable comparison."""
    normalized = [_normalize_expression(e) for e in expressions]
    return sorted(normalized, key=lambda e: e["payload"])


def normalize_content_scanning_config(enabled: bool, expressions: list[dict]) -> dict:
    """Build normalized config dict from API responses."""
    result: dict = {"enabled": enabled}
    if expressions:
        result["custom_expressions"] = _normalize_expressions(expressions)
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_content_scanning(current: dict, desired: dict) -> ContentScanningPlan:
    """Diff current vs desired content scanning config."""
    changes: list[ContentScanningChange] = []

    # enabled toggle
    if "enabled" in desired:
        cur_enabled = current.get("enabled", False)
        des_enabled = desired["enabled"]
        if cur_enabled != des_enabled:
            changes.append(
                ContentScanningChange(field="enabled", current=cur_enabled, desired=des_enabled)
            )

    # custom expressions list
    if "custom_expressions" in desired:
        cur_exprs = _normalize_expressions(current.get("custom_expressions", []))
        des_exprs = _normalize_expressions(desired["custom_expressions"])
        if cur_exprs != des_exprs:
            changes.append(
                ContentScanningChange(
                    field="custom_expressions", current=cur_exprs, desired=des_exprs
                )
            )

    return ContentScanningPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_content_scanning(all_desired, scope, provider):
    """Prefetch: fetch current content scanning config."""
    if not scope.zone_id:
        return None
    desired = all_desired.get("cloudflare_content_scanning")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_content_scanning(scope)
    except ProviderAuthError:
        if "cloudflare_content_scanning" in all_desired:
            raise  # User explicitly declared this section -- permission is needed
        log.debug("Skipping cloudflare_content_scanning (no permission and not in desired config)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_content_scanning: product not enabled on this zone")
            return None
        log.warning("Failed to fetch content scanning config for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_content_scanning(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_content_scanning(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("cloudflare_content_scanning", []).append(plan)


def _apply_content_scanning(zp, plans, scope, provider):
    """Apply content scanning changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
            continue

        for change in plan.changes:
            if not change.has_changes:
                continue

            if change.field == "enabled":
                provider.update_content_scanning_enabled(scope, change.desired)
                synced.append("cloudflare_content_scanning:enabled")

            elif change.field == "custom_expressions":
                provider.sync_content_scanning_expressions(scope, change.current, change.desired)
                synced.append("cloudflare_content_scanning:custom_expressions")

    return synced, None


def _validate_content_scanning(desired, zone_name, errors, lines):
    """Validate cloudflare_content_scanning offline."""
    config = desired.get("cloudflare_content_scanning")
    if not isinstance(config, dict):
        return

    enabled = config.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append(
            f"  {zone_name}/cloudflare_content_scanning: invalid"
            f" enabled {enabled!r} (must be a boolean)"
        )

    exprs = config.get("custom_expressions")
    if exprs is not None:
        if not isinstance(exprs, list):
            errors.append(
                f"  {zone_name}/cloudflare_content_scanning:"
                f" custom_expressions must be a list, got {type(exprs).__name__}"
            )
        else:
            for i, expr in enumerate(exprs):
                if not isinstance(expr, dict):
                    errors.append(
                        f"  {zone_name}/cloudflare_content_scanning:"
                        f" custom_expressions[{i}] must be a dict"
                    )
                    continue
                payload = expr.get("payload")
                if not isinstance(payload, str) or not payload:
                    errors.append(
                        f"  {zone_name}/cloudflare_content_scanning:"
                        f" custom_expressions[{i}].payload must be a non-empty string"
                    )


def _dump_content_scanning(scope, provider, out_dir):
    """Export current content scanning config to dump output."""
    if not scope.zone_id:
        return None
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        config = provider.get_content_scanning(scope)
    except ProviderAuthError:
        log.info("cloudflare_content_scanning: skipped (insufficient permissions)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_content_scanning: product not enabled on this zone")
        else:
            log.debug("cloudflare_content_scanning: %s", e)
        return None

    if config:
        return {"cloudflare_content_scanning": config}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ContentScanningFormatter:
    """Formats content scanning diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"content_scanning.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
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
            if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"content_scanning.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"content_scanning.{change.field}")
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
            if not isinstance(plan, ContentScanningPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "content_scanning",
                    "provider_id": "cloudflare_content_scanning",
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


def register_content_scanning() -> None:
    """Register all content scanning hooks with the core extension system."""
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

    register_plan_zone_hook(_prefetch_content_scanning, _finalize_content_scanning)
    register_apply_extension("cloudflare_content_scanning", _apply_content_scanning)
    register_format_extension("cloudflare_content_scanning", ContentScanningFormatter())
    register_validate_extension(_validate_content_scanning)
    register_dump_extension(_dump_content_scanning)
