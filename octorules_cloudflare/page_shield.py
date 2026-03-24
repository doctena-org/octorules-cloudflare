"""Page Shield policy planning, applying, formatting, validation, and dumping.

This module implements the Cloudflare-specific Page Shield extension for
octorules.  All five hooks (plan, apply, format, validate, dump) are
registered at import time via ``register_page_shield()``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from octorules.expression import normalize_expression
from octorules.extensions import (
    register_apply_extension,
    register_dump_extension,
    register_format_extension,
    register_plan_zone_hook,
    register_validate_extension,
)
from octorules.phases import Phase, get_api_fields
from octorules.planner import (
    ChangeType,
    RuleChange,
    RuleValidationError,
    ZonePlan,
    _make_synthetic_phase,
    _normalize_value,
)
from octorules.provider.base import (
    SUPPORTS_PAGE_SHIELD,
    BaseProvider,
    Scope,
    provider_supports,
)
from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import format_api_error as _format_api_error

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PageShieldPolicyPlan dataclass
# ---------------------------------------------------------------------------


@dataclass
class PageShieldPolicyPlan:
    description: str
    policy_id: str | None = None  # None for CREATE
    create: bool = False
    delete: bool = False
    changes: list[RuleChange] = field(default_factory=list)  # field-level changes

    @property
    def has_changes(self) -> bool:
        return self.create or self.delete or len(self.changes) > 0

    @property
    def total_changes(self) -> int:
        count = len(self.changes)
        if self.create:
            count += 1
        if self.delete:
            count += 1
        return count


# ---------------------------------------------------------------------------
# CSP normalization — sort sources within each directive to prevent
# phantom diffs when Cloudflare reorders CSP source values.
# ---------------------------------------------------------------------------


def normalize_csp_value(value: str) -> str:
    """Normalize a CSP value by sorting sources within each directive.

    Splits on ``';'`` into directives, then sorts the sources (everything
    after the directive name) alphabetically within each directive.
    The directive name itself always comes first.

    This prevents phantom diffs when Cloudflare returns CSP source values
    in a different order than the YAML specifies.
    """
    # First collapse whitespace like normalize_expression does
    value = normalize_expression(value)

    directives = value.split("; ")
    normalized_parts: list[str] = []
    for directive in directives:
        tokens = directive.rstrip(";").split(" ")
        if len(tokens) <= 2:
            # Directive name only, or single source — nothing to sort
            normalized_parts.append(directive)
            continue
        # First token is the directive name; sort the rest
        name = tokens[0]
        sources = sorted(tokens[1:])
        normalized_parts.append(f"{name} {' '.join(sources)}")
    return "; ".join(normalized_parts)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_PAGE_SHIELD_ACTIONS = frozenset({"allow", "log"})


def _require_field(entry: dict, field_name: str, context: str, expected_type: type) -> object:
    """Validate that *entry* has a *field_name* of *expected_type*."""
    if field_name not in entry:
        raise RuleValidationError(f"{context} is missing required {field_name!r} field")
    value = entry[field_name]
    if not isinstance(value, expected_type):
        raise RuleValidationError(
            f"{context} has invalid {field_name!r} (must be a {expected_type.__name__})"
        )
    return value


def _require_string_field(entry: dict, field_name: str, context: str) -> str:
    """Validate that *entry* has a non-empty string *field_name*."""
    value = _require_field(entry, field_name, context, str)
    if not value:
        raise RuleValidationError(
            f"{context} has invalid {field_name!r} (must be a non-empty string)"
        )
    return value


def validate_page_shield_policy(entry: dict, index: int) -> None:
    """Validate a page_shield_policies entry from YAML."""
    ctx = f"page_shield_policies[{index}]"
    desc = _require_string_field(entry, "description", ctx)
    ctx_desc = f"{ctx} ({desc!r})"
    _require_string_field(entry, "action", ctx_desc)
    action = entry["action"]
    if action not in _VALID_PAGE_SHIELD_ACTIONS:
        raise RuleValidationError(
            f"{ctx_desc} has invalid 'action' {action!r}."
            f" Must be one of: {', '.join(sorted(_VALID_PAGE_SHIELD_ACTIONS))}"
        )
    _require_string_field(entry, "expression", ctx_desc)
    _require_field(entry, "enabled", ctx_desc, bool)
    _require_string_field(entry, "value", ctx_desc)


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------

_PAGE_SHIELD_DIFF_FIELDS = ("action", "expression", "enabled", "value")


def _make_page_shield_phase(description: str) -> Phase:
    """Create a synthetic Phase for a page shield policy."""
    return _make_synthetic_phase(
        "page_shield",
        description,
        "page_shield_policies",
        zone_level=True,
        account_level=False,
    )


def normalize_page_shield_policy(policy: dict) -> dict:
    """Strip page_shield_policy API fields and normalize for comparison."""
    excluded = get_api_fields("page_shield_policy")
    result = {}
    for k, v in policy.items():
        if k in excluded:
            continue
        if k == "value" and isinstance(v, str):
            result[k] = normalize_csp_value(v)
        else:
            result[k] = _normalize_value(v, key=k)
    return result


def _diff_fields(desired: dict, current: dict, fields: tuple[str, ...]) -> list[RuleChange]:
    """Compute field-level diffs between desired and current dicts."""
    changes: list[RuleChange] = []
    synthetic = _make_page_shield_phase(desired.get("description", ""))
    for fname in fields:
        d_val = desired.get(fname)
        c_val = current.get(fname)
        # Normalize for comparison
        if fname == "value":
            d_cmp = normalize_csp_value(d_val) if isinstance(d_val, str) else d_val
            c_cmp = normalize_csp_value(c_val) if isinstance(c_val, str) else c_val
        else:
            d_cmp = _normalize_value(d_val, key=fname)
            c_cmp = _normalize_value(c_val, key=fname)
        if d_cmp != c_cmp:
            change = RuleChange(
                change_type=ChangeType.MODIFY,
                ref=fname,
                phase=synthetic,
                current={fname: c_cmp},
                desired={fname: d_cmp},
            )
            change.__dict__["normalized_current"] = {fname: c_cmp}
            change.__dict__["normalized_desired"] = {fname: d_cmp}
            changes.append(change)
    return changes


def diff_page_shield_policies(
    desired_policies: list[dict],
    current_policies: list[dict],
) -> list[PageShieldPolicyPlan]:
    """Compute the full diff for page shield policies using description as identity key."""
    plans: list[PageShieldPolicyPlan] = []

    # Index current by description
    current_by_desc: dict[str, dict] = {}
    for p in current_policies:
        desc = p.get("description", "")
        if desc:
            current_by_desc[desc] = p

    desired_descs: set[str] = set()

    # Desired policies
    for entry in desired_policies:
        entry = entry.copy()
        if isinstance(entry.get("expression"), str):
            entry["expression"] = normalize_expression(entry["expression"])
        desc = entry["description"]
        desired_descs.add(desc)
        current = current_by_desc.get(desc)

        if current is None:
            # CREATE
            synthetic = _make_page_shield_phase(desc)
            field_changes = []
            for f in _PAGE_SHIELD_DIFF_FIELDS:
                val = entry.get(f)
                if val is not None:
                    field_changes.append(
                        RuleChange(
                            change_type=ChangeType.ADD,
                            ref=f,
                            phase=synthetic,
                            desired={f: val},
                        )
                    )
            pp = PageShieldPolicyPlan(
                description=desc,
                create=True,
                changes=field_changes,
            )
            plans.append(pp)
        else:
            # EXISTING — field-level diff
            policy_id = current.get("id")
            field_changes = _diff_fields(entry, current, _PAGE_SHIELD_DIFF_FIELDS)
            if field_changes:
                pp = PageShieldPolicyPlan(
                    description=desc,
                    policy_id=policy_id,
                    changes=field_changes,
                )
                plans.append(pp)

    # Current not in desired → DELETE
    for desc, current in current_by_desc.items():
        if desc not in desired_descs:
            pp = PageShieldPolicyPlan(
                description=desc,
                policy_id=current.get("id"),
                delete=True,
            )
            plans.append(pp)

    return sorted(plans, key=lambda p: p.description)


# ---------------------------------------------------------------------------
# CSP value formatting (for dump output)
# ---------------------------------------------------------------------------


def format_csp_value(value: str, max_line: int = 80) -> str:
    """Format a CSP value string for readable multi-line YAML.

    Short values (<=max_line chars) are returned unchanged.  Long values
    are formatted with one source per line.
    """
    if len(value) <= max_line:
        return value

    parts = value.split("; ")
    lines: list[str] = []
    for i, part in enumerate(parts):
        tokens = part.split(" ")
        lines.append(tokens[0])
        for j, token in enumerate(tokens[1:], 1):
            if i < len(parts) - 1 and j == len(tokens) - 1:
                lines.append(f"  {token};")
            else:
                lines.append(f"  {token}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Plan zone hook
# ---------------------------------------------------------------------------


def _prefetch_page_shield(
    all_desired: dict,
    scope: Scope,
    provider: BaseProvider,
) -> object:
    """Prefetch hook: start Page Shield API call in background thread.

    Returns a (future, executor, ps_desired) tuple, or None if not needed.
    Called BEFORE get_all_phase_rules so the fetch runs concurrently.
    """
    from concurrent.futures import ThreadPoolExecutor

    ps_desired = all_desired.get("page_shield_policies")
    if ps_desired is None:
        return None
    if not provider_supports(provider, SUPPORTS_PAGE_SHIELD):
        log.warning(
            "Skipping page_shield_policies for %s: provider does not support page_shield",
            scope.label,
        )
        return None

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(provider.get_all_page_shield_policies, scope)
    except Exception:
        executor.shutdown(wait=False)
        raise
    return (future, executor, ps_desired)


def _finalize_page_shield(
    zp: ZonePlan,
    all_desired: dict,
    scope: Scope,
    provider: BaseProvider,
    ctx: object,
) -> None:
    """Finalize hook: join the prefetched data and compute diffs.

    Called AFTER plan_zone with the context from _prefetch_page_shield.
    """
    if ctx is None:
        return

    future, executor, ps_desired = ctx
    try:
        try:
            current_policies = future.result(timeout=120)
        except ProviderAuthError:
            raise
        except ProviderError as e:
            log.warning(
                "Failed to fetch Page Shield policies for %s: %s",
                zp.zone_name,
                _format_api_error(e),
            )
            current_policies = []

        policy_plans = diff_page_shield_policies(ps_desired, current_policies)
        changed = [pp for pp in policy_plans if pp.has_changes]
        if changed:
            zp.extension_plans.setdefault("page_shield", []).extend(changed)
    finally:
        executor.shutdown(wait=True)


# ---------------------------------------------------------------------------
# Apply extension
# ---------------------------------------------------------------------------


def _apply_parallel(
    tasks: list[tuple[str, Callable[[], None]]],
    max_workers: int = 0,
) -> tuple[list[str], str | None]:
    """Run tasks, collecting successes. Minimal reimplementation."""
    if not tasks:
        return [], None
    # Sequential
    successes: list[str] = []
    for label, fn in tasks:
        try:
            fn()
        except ProviderAuthError:
            raise
        except ProviderError as e:
            return successes, f"{label}: {_format_api_error(e)}"
        except TimeoutError as e:
            return successes, f"{label}: {e}"
        successes.append(label)
    return successes, None


def _apply_page_shield(
    zp: ZonePlan,
    plans: list,
    scope: Scope,
    provider: BaseProvider,
) -> tuple[list[str], str | None]:
    """Apply Page Shield policy changes."""
    max_w = provider.max_workers
    synced: list[str] = []

    # Stage 1: Creates
    create_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in plans:
        if not psp.create:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: creating policy", zp.zone_name, label)
        kwargs: dict = {"description": psp.description}
        for c in psp.changes:
            if c.normalized_desired:
                for k, v in c.normalized_desired.items():
                    kwargs[k] = v

        def create_fn(_psp=psp, _kwargs=dict(kwargs), _label=label) -> None:
            result = provider.create_page_shield_policy(scope, **_kwargs)
            _psp.policy_id = result.get("id", "")
            log.info("  %s/%s: created (id=%s)", zp.zone_name, _label, _psp.policy_id)

        create_tasks.append((full_label, create_fn))

    if create_tasks:
        create_synced, create_error = _apply_parallel(create_tasks, max_w)
        synced.extend(create_synced)
        if create_error:
            return synced, create_error

    # Stage 2: Updates
    update_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in plans:
        if psp.create or psp.delete or not psp.changes:
            continue
        if not psp.policy_id:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        n_changes = len(psp.changes)
        log.info("  %s/%s: applying %d change(s)", zp.zone_name, label, n_changes)
        kwargs = {"description": psp.description}
        for c in psp.changes:
            if c.normalized_desired:
                for k, v in c.normalized_desired.items():
                    kwargs[k] = v

        def update_fn(_psp=psp, _kwargs=dict(kwargs), _label=label) -> None:
            provider.update_page_shield_policy(scope, _psp.policy_id, **_kwargs)
            log.info("  %s/%s: updated", zp.zone_name, _label)

        update_tasks.append((full_label, update_fn))

    if update_tasks:
        update_synced, update_error = _apply_parallel(update_tasks, max_w)
        synced.extend(update_synced)
        if update_error:
            return synced, update_error

    # Stage 3: Deletes
    delete_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in plans:
        if not psp.delete or not psp.policy_id:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: deleting policy", zp.zone_name, label)

        def del_fn(_psp=psp, _label=label) -> None:
            provider.delete_page_shield_policy(scope, _psp.policy_id)
            log.info("  %s/%s: deleted", zp.zone_name, _label)

        delete_tasks.append((full_label, del_fn))

    if delete_tasks:
        del_synced, del_error = _apply_parallel(delete_tasks, max_w)
        synced.extend(del_synced)
        if del_error:
            return synced, del_error

    return synced, None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------


def _validate_page_shield(
    desired: dict,
    zone_name: str,
    errors: list[str],
    lines: list[str],
) -> None:
    """Validate page_shield_policies entries offline."""
    ps_entries = desired.get("page_shield_policies")
    if not isinstance(ps_entries, list):
        return
    for i, entry in enumerate(ps_entries):
        try:
            validate_page_shield_policy(entry, i)
            desc = entry.get("description", f"index {i}")
            msg = f"  {zone_name}/page_shield:{desc}: OK"
            log.info("%s", msg)
            lines.append(msg)
        except RuleValidationError as e:
            msg = f"  {zone_name}/page_shield_policies: {e}"
            errors.append(msg)


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------


def _clean_page_shield_policies(policies: list[dict]) -> list[dict]:
    """Clean and format page shield policies for YAML dump output."""
    from octorules.dumper import _literalize, _LiteralStr, _strip_trailing_whitespace

    psp_api_fields = get_api_fields("page_shield_policy")
    policies_list = []
    for policy in sorted(policies, key=lambda p: p.get("description", "")):
        cleaned = {}
        for k, v in policy.items():
            if k in psp_api_fields:
                continue
            if k == "value" and isinstance(v, str) and len(v) > 80:
                cleaned[k] = _LiteralStr(_strip_trailing_whitespace(format_csp_value(v)))
            else:
                cleaned[k] = _literalize(v)
        policies_list.append(cleaned)
    return policies_list


def _dump_page_shield(
    scope: Scope,
    provider: BaseProvider,
    out_dir: Path,
) -> dict | None:
    """Dump hook: fetch Page Shield policies, clean, and return as extra_sections."""
    if not provider_supports(provider, SUPPORTS_PAGE_SHIELD):
        return None
    try:
        policies = provider.get_all_page_shield_policies(scope)
    except ProviderAuthError:
        raise
    except ProviderError as e:
        log.warning(
            "Failed to fetch Page Shield policies for %s: %s",
            scope.label,
            _format_api_error(e),
        )
        return None
    if not policies:
        return None
    cleaned = _clean_page_shield_policies(policies)
    if cleaned:
        return {"extra_sections": {"page_shield_policies": cleaned}}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------


class PageShieldFormatter:
    """Formatter for Page Shield policy plans."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules.formatter import (
            BOLD,
            GREEN,
            RED,
            _color,
            format_change,
        )

        lines: list[str] = []
        for psp in plans:
            header = f"  page_shield: {psp.description}"
            lines.append(_color(header, BOLD, use_color))
            if psp.create:
                lines.append(_color("  + create policy", GREEN, use_color))
            if psp.delete:
                lines.append(_color("  - delete policy", RED, use_color))
            for change in psp.changes:
                lines.extend(format_change(change, use_color))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        from octorules.formatter import _change_to_dict

        result = []
        for psp in plans:
            entry: dict = {
                "description": psp.description,
                "create": psp.create,
                "delete": psp.delete,
            }
            if psp.policy_id:
                entry["policy_id"] = psp.policy_id
            psp_changes = [_change_to_dict(c) for c in psp.changes]
            if psp_changes:
                entry["changes"] = psp_changes
            result.append(entry)
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_change_row, _md_escape

        lines: list[str] = []
        for psp in plans:
            phase_label = f"page_shield:{psp.description}"
            if psp.create:
                lines.append(f"| + | {_md_escape(phase_label)} | | create policy |")
            if psp.delete:
                lines.append(f"| - | {_md_escape(phase_label)} | | delete policy |")
            for c in psp.changes:
                lines.append(_md_change_row(c, phase_label, pending_diffs, has_reorder=False))
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import (
            _HTML_TABLE_HEADER,
            _html_render_changes,
            _html_summary_row,
        )

        e = html_escape
        total_creates = total_removes = total_modifies = 0

        for psp in plans:
            lines.append(f"<h3>page_shield: {e(psp.description)}</h3>")
            lines.extend(_HTML_TABLE_HEADER)

            psp_creates = psp_removes = psp_modifies = 0

            if psp.create:
                psp_creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                lines.append("    <td>create policy</td>")
                lines.append("  </tr>")
            if psp.delete:
                psp_removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete policy</td>")
                lines.append("  </tr>")

            c_creates, c_removes, c_modifies, _ = _html_render_changes(psp.changes, lines)
            psp_creates += c_creates
            psp_removes += c_removes
            psp_modifies += c_modifies
            lines.extend(_html_summary_row(psp_creates, psp_removes, psp_modifies, 0))
            lines.append("</table>")

            total_creates += psp_creates
            total_removes += psp_removes
            total_modifies += psp_modifies

        return total_creates, total_removes, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        for psp in plans:
            psp_adds = psp_removes = psp_modifies = 0
            if psp.create:
                psp_adds += 1
            if psp.delete:
                psp_removes += 1
            for c in psp.changes:
                if c.change_type == ChangeType.ADD:
                    psp_adds += 1
                elif c.change_type == ChangeType.REMOVE:
                    psp_removes += 1
                elif c.change_type == ChangeType.MODIFY:
                    psp_modifies += 1
            psp_status = "drifted" if (psp_adds or psp_removes or psp_modifies) else "in_sync"
            if psp_status != "in_sync":
                zone_has_drift = True
            phases_data.append(
                {
                    "phase": f"page_shield:{psp.description}",
                    "provider_id": "page_shield_policies",
                    "status": psp_status,
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": psp_adds,
                    "removes": psp_removes,
                    "modifies": psp_modifies,
                }
            )
        return zone_has_drift


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

_registered = False


def register_page_shield() -> None:
    """Register all Page Shield hooks with the core extension system."""
    global _registered
    if _registered:
        return
    _registered = True
    register_plan_zone_hook(_prefetch_page_shield, _finalize_page_shield)
    register_apply_extension("page_shield", _apply_page_shield)
    register_format_extension("page_shield", PageShieldFormatter())
    register_validate_extension(_validate_page_shield)
    register_dump_extension(_dump_page_shield)
