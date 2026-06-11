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

from octorules.registration import idempotent_registration

from octorules_cloudflare._settings_base import (
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
)
from octorules_cloudflare._settings_common import verify_settings_applied

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class LeakedCredentialChange(SettingsChange):
    """A single change in leaked credential check config."""


class LeakedCredentialPlan(SettingsPlan):
    """Plan for all leaked credential check changes in a zone."""


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
                verify_settings_applied(
                    provider.get_leaked_credential_check,
                    scope,
                    {"enabled": change.desired},
                    "cloudflare_leaked_credential_check",
                )
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
class LeakedCredentialFormatter(SettingsFormatter):
    """Formats leaked credential check diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(
            plan_type=LeakedCredentialPlan,
            prefix="leaked_credential_check",
            phase="leaked_credential_check",
            provider_id="cloudflare_leaked_credential_check",
        )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_leaked_credentials() -> None:
    """Register all leaked credential check hooks with the core extension system."""
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
