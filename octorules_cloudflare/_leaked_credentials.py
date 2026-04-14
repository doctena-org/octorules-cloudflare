"""Leaked Credential Check extension for Cloudflare zones.

Manages the Leaked Credential Check feature:
- ``enabled`` — whether leaked credential detection is active
- ``detections`` — list of custom detection rules (username/password
  expression pairs)

Cloudflare SDK methods:
- ``client.leaked_credential_checks.get(zone_id=...)`` — enabled status
- ``client.leaked_credential_checks.create(zone_id=..., enabled=...)``
- ``client.leaked_credential_checks.detections.list(zone_id=...)``
- ``client.leaked_credential_checks.detections.create(zone_id=..., ...)``
- ``client.leaked_credential_checks.detections.update(detection_id, zone_id=..., ...)``
- ``client.leaked_credential_checks.detections.delete(detection_id, zone_id=...)``

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
class LeakedCredentialChange:
    """A single change in leaked credential check config."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class LeakedCredentialPlan:
    """Plan for all leaked credential check changes in a zone."""

    changes: list[LeakedCredentialChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
def _normalize_detection(det: dict) -> dict:
    """Normalize a single detection rule to canonical form."""
    return {
        "username": det.get("username", ""),
        "password": det.get("password", ""),
    }


def _normalize_detections(detections: list[dict]) -> list[dict]:
    """Normalize and sort detection rules for stable comparison."""
    normalized = [_normalize_detection(d) for d in detections]
    return sorted(normalized, key=lambda d: (d["username"], d["password"]))


def normalize_leaked_credential_config(enabled: bool, detections: list[dict]) -> dict:
    """Build normalized config dict from API responses."""
    result: dict = {"enabled": enabled}
    if detections:
        result["detections"] = _normalize_detections(detections)
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_leaked_credentials(current: dict, desired: dict) -> LeakedCredentialPlan:
    """Diff current vs desired leaked credential check config."""
    changes: list[LeakedCredentialChange] = []

    # enabled toggle
    if "enabled" in desired:
        cur_enabled = current.get("enabled", False)
        des_enabled = desired["enabled"]
        if cur_enabled != des_enabled:
            changes.append(
                LeakedCredentialChange(field="enabled", current=cur_enabled, desired=des_enabled)
            )

    # detections list
    if "detections" in desired:
        cur_dets = _normalize_detections(current.get("detections", []))
        des_dets = _normalize_detections(desired["detections"])
        if cur_dets != des_dets:
            changes.append(
                LeakedCredentialChange(field="detections", current=cur_dets, desired=des_dets)
            )

    return LeakedCredentialPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_leaked_credentials(all_desired, scope, provider):
    """Prefetch: fetch current leaked credential check config."""
    if not scope.zone_id:
        return None
    desired = all_desired.get("cloudflare_leaked_credential_check")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_leaked_credential_check(scope)
    except ProviderAuthError:
        if "cloudflare_leaked_credential_check" in all_desired:
            raise  # User explicitly declared this section -- permission is needed
        log.debug(
            "Skipping cloudflare_leaked_credential_check (no permission and not in desired config)"
        )
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_leaked_credential_check: product not enabled on this zone")
            return None
        log.warning("Failed to fetch leaked credential check config for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_leaked_credentials(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_leaked_credentials(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("cloudflare_leaked_credential_check", []).append(plan)


def _apply_leaked_credentials(zp, plans, scope, provider):
    """Apply leaked credential check changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
            continue

        for change in plan.changes:
            if not change.has_changes:
                continue

            if change.field == "enabled":
                provider.update_leaked_credential_check_enabled(scope, change.desired)
                synced.append("cloudflare_leaked_credential_check:enabled")

            elif change.field == "detections":
                provider.sync_leaked_credential_detections(scope, change.current, change.desired)
                synced.append("cloudflare_leaked_credential_check:detections")

    return synced, None


def _validate_leaked_credentials(desired, zone_name, errors, lines):
    """Validate cloudflare_leaked_credential_check offline."""
    config = desired.get("cloudflare_leaked_credential_check")
    if not isinstance(config, dict):
        return

    enabled = config.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append(
            f"  {zone_name}/cloudflare_leaked_credential_check: invalid"
            f" enabled {enabled!r} (must be a boolean)"
        )

    detections = config.get("detections")
    if detections is not None:
        if not isinstance(detections, list):
            errors.append(
                f"  {zone_name}/cloudflare_leaked_credential_check:"
                f" detections must be a list, got {type(detections).__name__}"
            )
        else:
            for i, det in enumerate(detections):
                if not isinstance(det, dict):
                    errors.append(
                        f"  {zone_name}/cloudflare_leaked_credential_check:"
                        f" detections[{i}] must be a dict"
                    )
                    continue
                for field_name in ("username", "password"):
                    val = det.get(field_name)
                    if not isinstance(val, str) or not val:
                        errors.append(
                            f"  {zone_name}/cloudflare_leaked_credential_check:"
                            f" detections[{i}].{field_name} must be a non-empty string"
                        )


def _dump_leaked_credentials(scope, provider, out_dir):
    """Export current leaked credential check config to dump output."""
    if not scope.zone_id:
        return None
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        config = provider.get_leaked_credential_check(scope)
    except ProviderAuthError:
        log.info("cloudflare_leaked_credential_check: skipped (insufficient permissions)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_leaked_credential_check: product not enabled on this zone")
        else:
            log.debug("cloudflare_leaked_credential_check: %s", e)
        return None

    if config:
        return {"cloudflare_leaked_credential_check": config}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class LeakedCredentialFormatter:
    """Formats leaked credential check diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"leaked_credential_check.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
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
            if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"leaked_credential_check.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"leaked_credential_check.{change.field}")
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
            if not isinstance(plan, LeakedCredentialPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "leaked_credential_check",
                    "provider_id": "cloudflare_leaked_credential_check",
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


def register_leaked_credentials() -> None:
    """Register all leaked credential check hooks with the core extension system."""
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

    register_plan_zone_hook(_prefetch_leaked_credentials, _finalize_leaked_credentials)
    register_apply_extension("cloudflare_leaked_credential_check", _apply_leaked_credentials)
    register_format_extension("cloudflare_leaked_credential_check", LeakedCredentialFormatter())
    register_validate_extension(_validate_leaked_credentials)
    register_dump_extension(_dump_leaked_credentials)
