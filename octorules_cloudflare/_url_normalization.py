"""URL normalization settings for Cloudflare zones.

These are non-phase YAML sections handled via extension hooks:
- ``cloudflare_url_normalization`` -- scope and type of URL normalization

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging
from dataclasses import dataclass, field

from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for URL normalization diffs
# ---------------------------------------------------------------------------
@dataclass
class UrlNormalizationChange:
    """A single field change in URL normalization settings."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class UrlNormalizationPlan:
    """Plan for all URL normalization changes in a zone."""

    changes: list[UrlNormalizationChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


# ---------------------------------------------------------------------------
# Valid enum values
# ---------------------------------------------------------------------------
_VALID_SCOPES = frozenset({"incoming", "both"})
_VALID_TYPES = frozenset({"cloudflare", "rfc3986"})


# ---------------------------------------------------------------------------
# Normalization: SDK response -> YAML-friendly canonical form
# ---------------------------------------------------------------------------
def normalize_url_normalization(raw: dict) -> dict:
    """Convert Cloudflare url_normalization.get() response to YAML-friendly form.

    Only includes fields that are present in the raw response.
    """
    if not raw:
        return {}

    result: dict = {}
    scope = raw.get("scope")
    if scope is not None:
        result["scope"] = scope
    type_ = raw.get("type")
    if type_ is not None:
        result["type"] = type_
    return result


# ---------------------------------------------------------------------------
# Denormalization: YAML canonical form -> SDK update kwargs
# ---------------------------------------------------------------------------
def denormalize_url_normalization(settings: dict) -> dict:
    """Convert YAML canonical form back to SDK kwargs for url_normalization.update().

    Only includes keys that are present in *settings* so that partial
    updates don't reset unspecified fields to defaults.
    """
    if not settings:
        return {}

    result: dict = {}
    if "scope" in settings:
        result["scope"] = settings["scope"]
    if "type" in settings:
        result["type"] = settings["type"]
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_url_normalization(current: dict, desired: dict) -> UrlNormalizationPlan:
    """Diff current vs desired URL normalization settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    changes: list[UrlNormalizationChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(UrlNormalizationChange(field=key, current=cur, desired=des))
    return UrlNormalizationPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_url_normalization(all_desired, scope, provider):
    """Prefetch: fetch current URL normalization settings."""
    if not scope.zone_id:
        return None
    desired = all_desired.get("cloudflare_url_normalization")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_url_normalization(scope)
    except ProviderAuthError:
        if "cloudflare_url_normalization" in all_desired:
            raise  # User explicitly declared this section -- permission is needed
        log.debug("Skipping cloudflare_url_normalization (no permission and not in desired config)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_url_normalization: product not enabled on this zone")
            return None
        log.warning("Failed to fetch URL normalization settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_url_normalization(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_url_normalization(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("cloudflare_url_normalization", []).append(plan)


def _apply_url_normalization(zp, plans, scope, provider):
    """Apply URL normalization settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_url_normalization(scope, desired_values)
            synced.append("cloudflare_url_normalization")

    return synced, None


def _validate_url_normalization(desired, zone_name, errors, lines):
    """Validate cloudflare_url_normalization offline."""
    settings = desired.get("cloudflare_url_normalization")
    if not isinstance(settings, dict):
        return

    scope = settings.get("scope")
    if scope is not None and scope not in _VALID_SCOPES:
        errors.append(
            f"  {zone_name}/cloudflare_url_normalization: invalid"
            f" scope {scope!r} (must be one of {sorted(_VALID_SCOPES)})"
        )

    type_ = settings.get("type")
    if type_ is not None and type_ not in _VALID_TYPES:
        errors.append(
            f"  {zone_name}/cloudflare_url_normalization: invalid"
            f" type {type_!r} (must be one of {sorted(_VALID_TYPES)})"
        )


def _dump_url_normalization(scope, provider, out_dir):
    """Export current URL normalization settings to dump output."""
    if not scope.zone_id:
        return None
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_url_normalization(scope)
    except ProviderAuthError:
        log.info("cloudflare_url_normalization: skipped (insufficient permissions)")
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("cloudflare_url_normalization: product not enabled on this zone")
        else:
            log.debug("cloudflare_url_normalization: %s", e)
        return None

    if settings:
        return {"cloudflare_url_normalization": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class UrlNormalizationFormatter:
    """Formats URL normalization diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"url_normalization.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
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
            if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"url_normalization.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"url_normalization.{change.field}")
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
            if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "url_normalization_settings",
                    "provider_id": "cloudflare_url_normalization",
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
@idempotent_registration
def register_url_normalization() -> None:
    """Register all URL normalization hooks with the core extension system."""
    from octorules.extensions import (
        register_apply_extension,
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_url_normalization, _finalize_url_normalization)
    register_apply_extension("cloudflare_url_normalization", _apply_url_normalization)
    register_format_extension("cloudflare_url_normalization", UrlNormalizationFormatter())
    register_validate_extension(_validate_url_normalization)
    register_dump_extension(_dump_url_normalization)
