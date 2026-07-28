"""URL normalization settings for Cloudflare zones.

These are non-phase YAML sections handled via extension hooks:
- ``cloudflare_url_normalization`` -- scope and type of URL normalization

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging

from octorules.extensions import (
    ProviderExtension,
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
)
from octorules.registration import idempotent_registration

from octorules_cloudflare._settings_common import (
    make_dump_hook,
    make_prefetch_hook,
    partition_unsupported,
    verify_settings_applied,
    warn_unsupported,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for URL normalization diffs
# ---------------------------------------------------------------------------
class UrlNormalizationChange(SettingsChange):
    """A single field change in URL normalization settings."""


class UrlNormalizationPlan(SettingsPlan):
    """Plan for all URL normalization changes in a zone."""


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
    desired, unsupported = partition_unsupported(current, desired)
    changes: list[UrlNormalizationChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(UrlNormalizationChange(field=key, current=cur, desired=des))
    return UrlNormalizationPlan(changes=changes, unsupported=unsupported)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
_prefetch_url_normalization = make_prefetch_hook(
    "cloudflare.url_normalization_settings", "get_url_normalization"
)


def _finalize_url_normalization(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_url_normalization(current, desired)
    if plan.unsupported:
        warn_unsupported("cloudflare.url_normalization_settings", scope, plan.unsupported)
    if plan.has_changes or plan.unsupported:
        zp.extension_plans.setdefault("cloudflare.url_normalization_settings", []).append(plan)


def _apply_url_normalization(zp, plans, scope, provider):
    """Apply URL normalization settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, UrlNormalizationPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_url_normalization(scope, desired_values)
            verify_settings_applied(
                provider.get_url_normalization,
                scope,
                desired_values,
                "cloudflare.url_normalization_settings",
            )
            synced.append("cloudflare.url_normalization_settings")

    return synced, None


def _validate_url_normalization(desired, zone_name, errors, lines):
    """Validate cloudflare_url_normalization offline."""
    settings = desired.get("cloudflare.url_normalization_settings")
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


_dump_url_normalization = make_dump_hook(
    "cloudflare.url_normalization_settings", "get_url_normalization"
)


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class UrlNormalizationFormatter(SettingsFormatter):
    """Formats URL normalization diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(
            plan_type=UrlNormalizationPlan,
            prefix="cloudflare.url_normalization",
        )


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class UrlNormalizationExtension(ProviderExtension):
    """Zone URL-normalization settings."""

    section = "cloudflare.url_normalization_settings"
    formatter = UrlNormalizationFormatter()

    def prefetch(self, desired, scope, provider):
        return _prefetch_url_normalization(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_url_normalization(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_url_normalization(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_url_normalization(scope, provider)

    def validate(self, desired, zone_name, errors, lines):
        return _validate_url_normalization(desired, zone_name, errors, lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_url_normalization() -> None:
    """Register all URL normalization hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension("cloudflare.url_normalization_settings", UrlNormalizationFormatter())
    register_validate_extension(_validate_url_normalization)
