"""Shared data model and plan-output formatter for the flat-settings extensions.

Five extension modules manage flat field-level zone settings (bot
management, zone security, URL normalization, content scanning, leaked
credential check). Each keeps its own normalization, diff, hook, and
registration logic; the per-field Change/Plan data model and the five
``format_*`` methods are identical across them and live here.

The ``unsupported`` list is populated only by the modules that partition
plan/product-gated fields (see ``_settings_common.partition_unsupported``);
for the others it stays empty and renders nothing.
"""

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model for settings diffs
# ---------------------------------------------------------------------------
@dataclass
class SettingsChange:
    """A single field change in a settings section."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class SettingsPlan:
    """Plan for all field-level changes in a settings section."""

    changes: list[SettingsChange] = field(default_factory=list)
    # Fields declared in YAML that the zone's live config does not expose
    # (plan/product gated) -- reported as notes, never as changes.
    unsupported: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class SettingsFormatter:
    """Formats settings diffs for plan output.

    Parameterised by the concrete *plan_type* (so each formatter only
    renders its own plans), the YAML-facing *prefix* used in change
    labels, and the *phase* / *provider_id* strings used in report mode.
    """

    def __init__(self, plan_type: type, prefix: str, phase: str, provider_id: str) -> None:
        self._plan_type = plan_type
        self._prefix = prefix
        self._phase = phase
        self._provider_id = provider_id

    def _active_plans(self, plans: list):
        for plan in plans:
            if isinstance(plan, self._plan_type) and (plan.has_changes or plan.unsupported):
                yield plan

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in self._active_plans(plans):
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"{self._prefix}.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
            for name in plan.unsupported:
                line = (
                    f"  # {self._prefix}.{name}: declared in YAML but not exposed"
                    " on this zone -- ignored"
                )
                lines.append(p.muted(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in self._active_plans(plans):
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
            entry: dict = {}
            if changes:
                entry["changes"] = changes
            if plan.unsupported:
                entry["unsupported"] = list(plan.unsupported)
            if entry:
                result.append(entry)
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in self._active_plans(plans):
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"{self._prefix}.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
            for name in plan.unsupported:
                label = _md_escape(f"{self._prefix}.{name}")
                lines.append(f"| # | {label} | | not exposed on this zone -- ignored |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in self._active_plans(plans):
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"{self._prefix}.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            for name in plan.unsupported:
                label = html_escape(f"{self._prefix}.{name}")
                lines.append("  <tr>")
                lines.append("    <td>Note</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append("    <td>not exposed on this zone -- ignored</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, self._plan_type) or not plan.has_changes:
                continue
            total_modifies += plan.total_changes
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": self._phase,
                    "provider_id": self._provider_id,
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift
