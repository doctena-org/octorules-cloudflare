"""Managed Transforms (managed request/response headers), managed as code.

Cloudflare ships a fixed catalogue of managed header transforms -- request-side
ones like ``add_true_client_ip_headers`` and ``add_visitor_location_headers``,
response-side ones like ``add_security_headers`` -- each a single on/off
switch. The YAML groups them the way the API does:

.. code-block:: yaml

    managed_transforms:
      request:
        add_true_client_ip_headers: true
      response:
        add_security_headers: true

Fetched via ``GET /zones/{id}/managed_headers`` and updated via ``PATCH``,
which accepts one or more entries per side -- the API's own model is partial,
so apply sends exactly the transforms whose state changed.

The catalogue is the API's to define, not ours: a transform named in YAML but
absent from the live list is reported as unsupported rather than validated
against a hardcoded set, and the conflict check below reads each transform's
``conflicts_with`` declaration from the live response instead of pinning
today's one conflicting pair.
"""

import logging

from octorules.extensions import (
    ProviderExtension,
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
)
from octorules.planner import RuleValidationError
from octorules.registration import idempotent_registration

from octorules_cloudflare._settings_common import (
    make_dump_hook,
    verify_settings_applied,
    warn_unsupported,
)

log = logging.getLogger(__name__)

SECTION = "cloudflare.managed_transforms"

_SIDES = ("request", "response")
_API_KEYS = {
    "request": "managed_request_headers",
    "response": "managed_response_headers",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class ManagedTransformsChange(SettingsChange):
    """A single transform toggle change, with a ``side.id`` field label."""


class ManagedTransformsPlan(SettingsPlan):
    """Plan for all managed transform changes in a zone."""


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_managed_transforms(raw: dict) -> dict:
    """Convert the API list response to YAML-friendly canonical form.

    ``{"managed_request_headers": [{"id": ..., "enabled": ...}, ...], ...}``
    becomes ``{"request": {id: enabled, ...}, "response": {...}}``. The
    conflict metadata is deliberately not carried here -- it is plan-time
    input, not zone-file state; :func:`extract_conflicts` reads it.
    """
    if not raw:
        return {}
    result: dict = {}
    for side, api_key in _API_KEYS.items():
        entries = raw.get(api_key)
        if not isinstance(entries, list):
            continue
        side_map: dict = {}
        for entry in entries:
            if isinstance(entry, dict) and "id" in entry:
                side_map[entry["id"]] = bool(entry.get("enabled"))
        result[side] = side_map
    return result


def extract_conflicts(raw: dict) -> dict[str, list[str]]:
    """Read each transform's ``conflicts_with`` declaration from the API response.

    Returns ``{transform_id: [conflicting_ids, ...]}`` for transforms that
    declare any. Transform ids are unique across the request and response
    sides, so one flat map covers both.
    """
    conflicts: dict[str, list[str]] = {}
    if not raw:
        return conflicts
    for api_key in _API_KEYS.values():
        entries = raw.get(api_key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            declared = entry.get("conflicts_with")
            if declared and "id" in entry:
                conflicts[entry["id"]] = sorted(declared)
    return conflicts


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_managed_transforms(current: dict, desired: dict) -> ManagedTransformsPlan:
    """Diff current vs desired managed transforms.

    Only diffs transforms named in *desired* (partial update semantics). A
    transform named in YAML but absent from a non-empty live side is not
    available on this zone -- reported as unsupported, mirroring
    ``partition_unsupported``. An empty *current* means the live read failed;
    support is unknown, so everything desired is proposed (the standard
    recovery behaviour).
    """
    changes: list[ManagedTransformsChange] = []
    unsupported: list[str] = []
    for side in _SIDES:
        des_side = desired.get(side)
        if not isinstance(des_side, dict):
            continue
        cur_side = current.get(side) if current else None
        for tid in sorted(des_side):
            if isinstance(cur_side, dict) and tid not in cur_side:
                unsupported.append(f"{side}.{tid}")
                continue
            cur = cur_side.get(tid) if isinstance(cur_side, dict) else None
            des = des_side[tid]
            if des != cur:
                changes.append(
                    ManagedTransformsChange(field=f"{side}.{tid}", current=cur, desired=des)
                )
    return ManagedTransformsPlan(changes=changes, unsupported=unsupported)


# ---------------------------------------------------------------------------
# Conflict check (plan-time, against the live conflicts_with declarations)
# ---------------------------------------------------------------------------
def check_transform_conflicts(
    current: dict,
    desired: dict,
    conflicts: dict[str, list[str]],
    zone_label: str,
) -> None:
    """Fail the plan when the state after apply would enable a conflicting pair.

    The effective state is the zone's current toggles overlaid with the YAML's
    declarations, so this also fires when the YAML enables one transform while
    its declared counterpart is already enabled on the zone by hand. The pair
    itself comes from the live ``conflicts_with`` metadata, never a hardcoded
    list, so it stays correct when Cloudflare adds transforms.

    Pairs made entirely of dashboard state -- neither side named in the YAML --
    are left alone: partial semantics mean unmanaged toggles are not this
    zone file's business.
    """
    effective: dict[str, bool] = {}
    declared: set[str] = set()
    for side in _SIDES:
        cur_side = current.get(side)
        if isinstance(cur_side, dict):
            effective.update(cur_side)
        des_side = desired.get(side)
        if isinstance(des_side, dict):
            for tid, value in des_side.items():
                declared.add(tid)
                if isinstance(value, bool):
                    effective[tid] = value

    reported: set[frozenset] = set()
    for tid in sorted(effective):
        if effective[tid] is not True:
            continue
        for other in conflicts.get(tid, []):
            if effective.get(other) is not True:
                continue
            pair = frozenset((tid, other))
            if pair in reported:
                continue
            reported.add(pair)
            if tid not in declared and other not in declared:
                continue
            sources = {
                t: "the zone file" if t in declared else f"already enabled on {zone_label}"
                for t in sorted(pair)
            }
            detail = "; ".join(f"{t!r} ({src})" for t, src in sources.items())
            raise RuleValidationError(
                f"{SECTION}: conflicting managed transforms would both be enabled"
                f" on {zone_label}: {detail}. Cloudflare declares these mutually"
                " exclusive -- disable one of them."
            )


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_managed_transforms(all_desired, scope, provider):
    """Prefetch: fetch the live transform list once, keeping conflict metadata.

    A custom hook rather than ``make_prefetch_hook`` because the conflict
    check needs the raw response's ``conflicts_with`` declarations, which
    the normalized settings deliberately drop. Error handling mirrors the
    factory.
    """
    if not scope.zone_id:
        return None
    desired = all_desired.get(SECTION)
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        raw = provider.get_managed_transforms_raw(scope)
    except ProviderAuthError:
        raise  # The section is declared -- permission is needed
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("%s: product not enabled on this zone", SECTION)
            return None
        log.warning("Failed to fetch %s settings for %s", SECTION, scope.label)
        raw = {}

    return (normalize_managed_transforms(raw), desired, extract_conflicts(raw))


def _finalize_managed_transforms(zp, all_desired, scope, provider, ctx):
    """Finalize: run the conflict check, compute diff, add to zone plan."""
    if ctx is None:
        return

    current, desired, conflicts = ctx
    check_transform_conflicts(current, desired, conflicts, scope.label)
    plan = diff_managed_transforms(current, desired)
    if plan.unsupported:
        warn_unsupported(SECTION, scope, plan.unsupported)
    if plan.has_changes or plan.unsupported:
        zp.extension_plans.setdefault(SECTION, []).append(plan)


def _apply_managed_transforms(zp, plans, scope, provider):
    """Apply managed transform changes.

    The ``PATCH`` endpoint accepts a partial list per side, so only the
    transforms whose state changed are sent.
    """
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ManagedTransformsPlan) or not plan.has_changes:
            continue

        desired_values: dict = {}
        for c in plan.changes:
            if not c.has_changes:
                continue
            side, _, tid = c.field.partition(".")
            desired_values.setdefault(side, {})[tid] = c.desired
        if desired_values:
            provider.update_managed_transforms(scope, desired_values)
            verify_settings_applied(
                provider.get_managed_transforms,
                scope,
                desired_values,
                SECTION,
            )
            synced.append(SECTION)

    return synced, None


_dump_managed_transforms = make_dump_hook(SECTION, "get_managed_transforms")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _validate_managed_transforms(desired, zone_name, errors, lines):
    """Validate the managed transforms section offline.

    Structure only: the transform catalogue itself is API-defined, so which
    ids exist (and which conflict) is checked at plan time against the live
    response, not against a hardcoded list here.
    """
    settings = desired.get(SECTION)
    if not isinstance(settings, dict):
        return

    where = f"  {zone_name}/{SECTION}"

    unknown = sorted(k for k in settings if k not in _SIDES)
    if unknown:
        errors.append(f"{where}: unknown key(s) {unknown} (valid: {sorted(_SIDES)})")

    for side in _SIDES:
        side_map = settings.get(side)
        if side_map is None:
            continue
        if not isinstance(side_map, dict):
            errors.append(f"{where}: {side} must be a mapping, got {type(side_map).__name__}")
            continue
        for tid, value in sorted(side_map.items()):
            if not isinstance(tid, str) or not tid:
                errors.append(f"{where}: {side} keys must be transform ids, got {tid!r}")
            if not isinstance(value, bool):
                errors.append(f"{where}: {side}.{tid} must be true or false, got {value!r}")


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ManagedTransformsFormatter(SettingsFormatter):
    """Formats managed transform diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(plan_type=ManagedTransformsPlan, prefix="managed_transforms")


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class ManagedTransformsExtension(ProviderExtension):
    """Cloudflare's catalogue of managed header transforms."""

    section = SECTION

    def prefetch(self, desired, scope, provider):
        return _prefetch_managed_transforms(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_managed_transforms(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_managed_transforms(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_managed_transforms(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_managed_transforms() -> None:
    """Register all managed transform hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension(SECTION, ManagedTransformsFormatter())
    register_validate_extension(_validate_managed_transforms)
