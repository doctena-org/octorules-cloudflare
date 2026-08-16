"""security.txt (RFC 9116) zone settings, managed as code.

Cloudflare's Security Center can serve ``/.well-known/security.txt`` for a
zone, generated from a set of fields configured through
``GET/PUT /zones/{id}/security-center/securitytxt``. The YAML mirrors the API
field names one-to-one:

- ``enabled`` -- whether Cloudflare serves the file
- ``contact`` -- URIs a reporter should use (RFC 9116 requires at least one)
- ``expires`` -- when the file stops being valid (RFC 9116 requires it)
- ``acknowledgments``, ``canonical``, ``encryption``, ``hiring``, ``policy``
  -- optional URI lists
- ``preferred_languages`` -- comma-separated language tags

Unlike the per-setting zone extensions, the whole object is one ``PUT``:
apply overlays the desired fields onto the zone's current value and sends
the merged object, so fields the zone file does not name keep whatever the
dashboard set.

The check that earns its keep here is the ``expires`` one: an expired
security.txt advertises a disclosure path nobody maintains, which is worse
than serving none at all.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

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
    merge_onto,
    verify_settings_applied,
)

log = logging.getLogger(__name__)

SECTION = "cloudflare.security_txt"

_LIST_FIELDS = (
    "acknowledgments",
    "canonical",
    "contact",
    "encryption",
    "hiring",
    "policy",
)
_KNOWN_FIELDS = frozenset(_LIST_FIELDS) | {"enabled", "expires", "preferred_languages"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class SecurityTxtChange(SettingsChange):
    """A single field change in the security.txt settings."""


@dataclass
class SecurityTxtPlan(SettingsPlan):
    """Plan for all security.txt field changes in a zone.

    Carries the zone's full current object: the endpoint is a whole-object
    ``PUT``, so an update must resend the fields the zone file does not
    manage or the API would clear them.
    """

    current_settings: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def canonicalize_expires(value: object) -> object:
    """Return *value* as a canonical UTC ISO-8601 string, if it parses.

    The API returns ``expires`` as a datetime while YAML authors write a
    string (or PyYAML hands over a datetime for an unquoted timestamp), so
    both sides are canonicalized before comparison. A string that does not
    parse is returned unchanged -- validation reports it; the diff just
    compares the raw values.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_security_txt(raw: dict) -> dict:
    """Convert the API response to YAML-friendly canonical form.

    Keeps only known fields with actual values -- the API returns every field
    as ``None`` when unset, and carrying those would make a zone file naming
    only ``contact`` diff against phantom ``None`` fields forever.
    """
    if not raw:
        return {}
    result: dict = {}
    for key in sorted(_KNOWN_FIELDS):
        val = raw.get(key)
        if val is None:
            continue
        if key == "expires":
            result[key] = canonicalize_expires(val)
        elif key in _LIST_FIELDS:
            result[key] = [str(v) for v in val] if isinstance(val, list) else val
        else:
            result[key] = val
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_security_txt(current: dict, desired: dict) -> SecurityTxtPlan:
    """Diff current vs desired security.txt settings.

    Only diffs keys present in *desired* (partial update semantics). Every
    RFC 9116 field exists on every zone, so there is no unsupported-field
    partition here: a field absent from the live value is merely unset,
    not plan-gated.
    """
    changes: list[SecurityTxtChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if key == "expires":
            des = canonicalize_expires(des)
        if des != cur:
            changes.append(SecurityTxtChange(field=key, current=cur, desired=des))
    return SecurityTxtPlan(changes=changes, current_settings=dict(current))


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
_prefetch_security_txt = make_prefetch_hook(SECTION, "get_security_txt")


def _finalize_security_txt(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_security_txt(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault(SECTION, []).append(plan)


def _apply_security_txt(zp, plans, scope, provider):
    """Apply security.txt changes.

    The endpoint is a whole-object ``PUT``, so the desired fields are
    overlaid onto the current value and the merged object is sent -- fields
    the zone file does not name keep their dashboard-set values.
    """
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, SecurityTxtPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            merged = merge_onto(desired_values, plan.current_settings)
            provider.update_security_txt(scope, merged)
            verify_settings_applied(
                provider.get_security_txt,
                scope,
                merged,
                SECTION,
            )
            synced.append(SECTION)

    return synced, None


_dump_security_txt = make_dump_hook(SECTION, "get_security_txt")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _validate_security_txt(desired, zone_name, errors, lines):
    """Validate the security.txt section offline.

    *errors* are configurations that cannot do what they claim -- including a
    file that RFC 9116 makes invalid (``enabled`` without ``contact`` and
    ``expires``, or a contact entry that is not a URI). *lines* are warnings;
    the one here is an ``expires`` in the past, which advertises a disclosure
    path nobody maintains.
    """
    settings = desired.get(SECTION)
    if not isinstance(settings, dict):
        return

    where = f"  {zone_name}/{SECTION}"

    unknown = sorted(k for k in settings if k not in _KNOWN_FIELDS)
    if unknown:
        errors.append(f"{where}: unknown field(s) {unknown} (valid: {sorted(_KNOWN_FIELDS)})")

    enabled = settings.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append(f"{where}: enabled must be true or false, got {enabled!r}")

    pl = settings.get("preferred_languages")
    if pl is not None and not isinstance(pl, str):
        errors.append(f"{where}: preferred_languages must be a string, got {pl!r}")

    for list_field in _LIST_FIELDS:
        val = settings.get(list_field)
        if val is None:
            continue
        if not isinstance(val, list):
            errors.append(f"{where}: {list_field} must be a list, got {type(val).__name__}")
            continue
        for item in val:
            if not isinstance(item, str) or not item:
                errors.append(
                    f"{where}: {list_field} entries must be non-empty strings, got {item!r}"
                )
            elif list_field == "contact" and ":" not in item:
                # RFC 9116 § 2.5.3: Contact values MUST be URIs. A bare
                # email address is the common mistake; the fix is mailto:.
                errors.append(
                    f"{where}: contact entry {item!r} is not a URI"
                    " (an email address needs the mailto: scheme)"
                )

    _validate_expires(settings, where, errors, lines)

    if enabled is True:
        # RFC 9116 § 2.5.3 / § 2.5.5: Contact and Expires are mandatory.
        if not settings.get("contact"):
            errors.append(
                f"{where}: enabled is true but 'contact' is missing or empty"
                " (RFC 9116 requires at least one Contact entry)"
            )
        if settings.get("expires") is None:
            errors.append(
                f"{where}: enabled is true but 'expires' is missing"
                " (RFC 9116 requires an Expires timestamp)"
            )


def _validate_expires(settings: dict, where: str, errors: list[str], lines: list[str]) -> None:
    expires = settings.get("expires")
    if expires is None:
        return
    if isinstance(expires, datetime):
        dt = expires
    elif isinstance(expires, str):
        try:
            dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"{where}: expires {expires!r} is not a valid ISO-8601 timestamp")
            return
    else:
        errors.append(f"{where}: expires must be an ISO-8601 timestamp string, got {expires!r}")
        return
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt < datetime.now(timezone.utc):
        lines.append(
            f"{where}: expires ({canonicalize_expires(expires)}) is in the past -- an"
            " expired security.txt advertises a disclosure path nobody maintains;"
            " update it or disable the file"
        )


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class SecurityTxtFormatter(SettingsFormatter):
    """Formats security.txt diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(plan_type=SecurityTxtPlan, prefix="security_txt")


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class SecurityTxtExtension(ProviderExtension):
    """The zone's /.well-known/security.txt file."""

    section = SECTION

    def prefetch(self, desired, scope, provider):
        return _prefetch_security_txt(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_security_txt(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_security_txt(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_security_txt(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_security_txt() -> None:
    """Register all security.txt hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension(SECTION, SecurityTxtFormatter())
    register_validate_extension(_validate_security_txt)
