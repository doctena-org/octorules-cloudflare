"""SSL/TLS zone settings, managed as code.

Mirrors Cloudflare's own SSL/TLS tab, which is where an operator finds every
setting here:

- ``ssl`` — how Cloudflare reaches the origin (off / flexible / full / strict)
- ``min_tls_version``, ``tls_1_3``, ``zero_rtt`` — handshake floor and features
- ``always_use_https`` — redirect every HTTP request to HTTPS
- ``automatic_https_rewrites`` — rewrite http:// subresources in HTML
- ``security_header`` — HSTS, the one nested value here

Three of them are HTTPS *enforcement* rather than TLS configuration — HSTS is
a response header, not a handshake setting — so the section name is a little
broader than it reads. It follows Cloudflare's grouping deliberately: someone
writing a zone file has the dashboard open, and a section that matches the tab
they are looking at is worth more than one that is taxonomically tidier.

Kept separate from ``zone_security``, which is the challenge and scrape-shield
surface (``security_level``, ``challenge_passage``, ``browser_integrity_check``).
Those decide *who gets blocked*; these decide *how the connection is made*.

Fetched and updated through the same per-setting endpoints as ``zone_security``:
``client.zones.settings.get(setting_id, zone_id=...)`` and
``client.zones.settings.edit(setting_id, zone_id=..., value=...)``.
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
    merge_onto,
    partition_unsupported,
    value_matches,
    verify_settings_applied,
    warn_unsupported,
)

log = logging.getLogger(__name__)

SECTION = "cloudflare.zone_tls"

# ---------------------------------------------------------------------------
# Setting IDs — the Cloudflare API setting_id values we manage
# ---------------------------------------------------------------------------
_SETTING_IDS: dict[str, str] = {
    "ssl": "ssl",
    "min_tls_version": "min_tls_version",
    "tls_1_3": "tls_1_3",
    "zero_rtt": "0rtt",
    "always_use_https": "always_use_https",
    "automatic_https_rewrites": "automatic_https_rewrites",
    "security_header": "security_header",
}

# Valid values, confirmed against Cloudflare's zone-settings API reference.
_VALID_ON_OFF = frozenset({"on", "off"})
_VALID_SSL_MODES = frozenset({"off", "flexible", "full", "strict"})
_VALID_MIN_TLS = frozenset({"1.0", "1.1", "1.2", "1.3"})
# ``zrt`` is listed as a valid value but Cloudflare does not define it, which is
# why nothing below infers a relationship between tls_1_3 and zero_rtt.
_VALID_TLS_1_3 = frozenset({"on", "off", "zrt"})

# ``security_header`` is the only nested value here. Cloudflare wraps HSTS in a
# ``strict_transport_security`` object, and the YAML mirrors that shape rather
# than flattening it: a dump round-trips into a zone file with no translation,
# and there is no private mapping to get wrong later.
_HSTS_KEY = "strict_transport_security"
_HSTS_BOOL_FIELDS = frozenset({"enabled", "include_subdomains", "preload", "nosniff"})
_HSTS_FIELDS = _HSTS_BOOL_FIELDS | {"max_age"}

# The HSTS preload list's published submission requirements
# (https://hstspreload.org): a max-age of at least one year, includeSubDomains,
# the preload directive, and an HTTP-to-HTTPS redirect on the same host. The
# last one is why preload is checked against always_use_https below.
_HSTS_PRELOAD_MIN_MAX_AGE = 31536000

_SCALAR_STR_FIELDS = (
    "ssl",
    "min_tls_version",
    "tls_1_3",
    "zero_rtt",
    "always_use_https",
    "automatic_https_rewrites",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class ZoneTlsChange(SettingsChange):
    """A single field change in the SSL/TLS settings."""


class ZoneTlsPlan(SettingsPlan):
    """Plan for all SSL/TLS setting changes in a zone."""


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_zone_tls(raw_settings: dict) -> dict:
    """Convert raw per-setting API responses to YAML-friendly canonical form.

    *raw_settings* is a dict of ``{yaml_field: api_value}`` — the caller fetches
    each setting individually and assembles the dict.
    """
    if not raw_settings:
        return {}
    result: dict = {}
    for key in _SCALAR_STR_FIELDS:
        val = raw_settings.get(key)
        if val is not None:
            result[key] = str(val) if not isinstance(val, str) else val

    sh = raw_settings.get("security_header")
    if isinstance(sh, dict):
        hsts = sh.get(_HSTS_KEY)
        if isinstance(hsts, dict):
            normalized: dict = {}
            for field in sorted(_HSTS_FIELDS):
                if field not in hsts:
                    continue
                v = hsts[field]
                if field == "max_age":
                    normalized[field] = int(v) if not isinstance(v, int) else v
                else:
                    normalized[field] = bool(v)
            if normalized:
                result["security_header"] = {_HSTS_KEY: normalized}
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_zone_tls(current: dict, desired: dict) -> ZoneTlsPlan:
    """Diff current vs desired SSL/TLS settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    desired, unsupported = partition_unsupported(current, desired)
    changes: list[ZoneTlsChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        # Subset comparison, not equality: security_header comes back from the
        # API with every sub-key populated, so a zone file naming only
        # ``enabled`` would otherwise diff on every run forever.
        if not value_matches(des, cur):
            changes.append(ZoneTlsChange(field=key, current=cur, desired=des))
    return ZoneTlsPlan(changes=changes, unsupported=unsupported)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
_prefetch_zone_tls = make_prefetch_hook(SECTION, "get_zone_tls_settings")


def _finalize_zone_tls(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_zone_tls(current, desired)
    if plan.unsupported:
        warn_unsupported(SECTION, scope, plan.unsupported)
    if plan.has_changes or plan.unsupported:
        zp.extension_plans.setdefault(SECTION, []).append(plan)


def _apply_zone_tls(zp, plans, scope, provider):
    """Apply SSL/TLS setting changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ZoneTlsPlan) or not plan.has_changes:
            continue

        # Send a complete value per setting: the desired fields overlaid on what
        # the zone currently has. Cloudflare's edit endpoint takes the whole
        # value, and whether it merges a partial nested object or replaces it is
        # not something to assume — a replace would silently reset the HSTS
        # sub-keys the zone file did not mention.
        desired_values = {
            c.field: merge_onto(c.desired, c.current) for c in plan.changes if c.has_changes
        }
        if desired_values:
            provider.update_zone_tls_settings(scope, desired_values)
            verify_settings_applied(
                provider.get_zone_tls_settings,
                scope,
                desired_values,
                SECTION,
            )
            synced.append(SECTION)

    return synced, None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _enum_error(where: str, field: str, value: object, valid: frozenset[str]) -> str:
    return f"{where}: invalid {field} {value!r} (must be one of {sorted(valid)})"


def _validate_zone_tls(desired, zone_name, errors, lines):
    """Validate the HTTPS settings offline.

    *errors* are configurations that cannot do what they claim. *lines* are
    warnings: legal, deployable settings whose security consequence is easy to
    miss. Nothing that is merely bold goes in *errors* — choosing ``ssl:
    strict`` is correct and the plan shows it before it applies.
    """
    settings = desired.get(SECTION)
    if not isinstance(settings, dict):
        return

    where = f"  {zone_name}/{SECTION}"

    ssl = settings.get("ssl")
    if ssl is not None and ssl not in _VALID_SSL_MODES:
        errors.append(_enum_error(where, "ssl", ssl, _VALID_SSL_MODES))
    elif ssl == "flexible":
        lines.append(
            f"{where}: ssl is 'flexible' — Cloudflare reaches the origin over plain"
            " HTTP, so the final hop is unencrypted while the browser still shows a"
            " padlock. Use 'full', or 'strict' if the origin certificate validates."
        )
    elif ssl == "off":
        lines.append(
            f"{where}: ssl is 'off' — the zone is served over plain HTTP with no"
            " encryption to the visitor."
        )

    mtv = settings.get("min_tls_version")
    if mtv is not None and mtv not in _VALID_MIN_TLS:
        errors.append(_enum_error(where, "min_tls_version", mtv, _VALID_MIN_TLS))
    elif mtv in ("1.0", "1.1"):
        lines.append(
            f"{where}: min_tls_version is {mtv!r} — TLS 1.0 and 1.1 are deprecated"
            " (RFC 8996) and below the PCI DSS floor. Use '1.2' or higher unless a"
            " known legacy client requires otherwise."
        )

    tls13 = settings.get("tls_1_3")
    if tls13 is not None and tls13 not in _VALID_TLS_1_3:
        errors.append(_enum_error(where, "tls_1_3", tls13, _VALID_TLS_1_3))

    # A 1.3 floor with 1.3 disabled is contradictory whichever way it resolves.
    # Deliberately the only cross-check between these two: no rule relates
    # tls_1_3 to zero_rtt, because Cloudflare does not define what 'zrt' means
    # and a guess would be worse than silence.
    if mtv == "1.3" and tls13 == "off":
        errors.append(f"{where}: min_tls_version '1.3' requires TLS 1.3, but tls_1_3 is 'off'")

    for field in ("zero_rtt", "always_use_https", "automatic_https_rewrites"):
        val = settings.get(field)
        if val is not None and val not in _VALID_ON_OFF:
            errors.append(_enum_error(where, field, val, _VALID_ON_OFF))

    _validate_security_header(settings, where, errors)


def _validate_security_header(settings: dict, where: str, errors: list[str]) -> None:
    """Validate the HSTS block.

    Everything reported here is a configuration that cannot do what it says,
    rather than one that is merely bold. Choosing to enable preload is the
    operator's call and the plan shows it before it applies; declaring preload
    while failing the preload list's own published requirements is not a choice,
    it is a header that will never be accepted.
    """
    sh = settings.get("security_header")
    if sh is None:
        return
    if not isinstance(sh, dict):
        errors.append(f"{where}: security_header must be a mapping, got {type(sh).__name__}")
        return

    unknown_top = sorted(k for k in sh if k != _HSTS_KEY)
    if unknown_top:
        errors.append(
            f"{where}: security_header has unknown key(s) {unknown_top}"
            f" (only {_HSTS_KEY!r} is supported)"
        )
    hsts = sh.get(_HSTS_KEY)
    if hsts is None:
        return
    if not isinstance(hsts, dict):
        errors.append(f"{where}: {_HSTS_KEY} must be a mapping, got {type(hsts).__name__}")
        return

    unknown = sorted(k for k in hsts if k not in _HSTS_FIELDS)
    if unknown:
        errors.append(
            f"{where}: {_HSTS_KEY} has unknown field(s) {unknown} (valid: {sorted(_HSTS_FIELDS)})"
        )

    for field in sorted(_HSTS_BOOL_FIELDS & set(hsts)):
        if not isinstance(hsts[field], bool):
            errors.append(
                f"{where}: {_HSTS_KEY}.{field} must be true or false, got {hsts[field]!r}"
            )

    max_age = hsts.get("max_age")
    if max_age is not None:
        if not isinstance(max_age, int) or isinstance(max_age, bool):
            errors.append(f"{where}: {_HSTS_KEY}.max_age must be an integer, got {max_age!r}")
            max_age = None
        elif max_age < 0:
            errors.append(f"{where}: {_HSTS_KEY}.max_age must not be negative, got {max_age}")
            max_age = None

    if hsts.get("enabled") is True and max_age == 0:
        errors.append(
            f"{where}: {_HSTS_KEY} is enabled with max_age 0, which sends a header"
            " that instructs browsers to forget the policy immediately — set a"
            " non-zero max_age or disable it"
        )

    if hsts.get("preload") is True:
        if hsts.get("include_subdomains") is not True:
            errors.append(
                f"{where}: {_HSTS_KEY}.preload requires include_subdomains: true"
                " (an HSTS preload submission is rejected without it)"
            )
        if max_age is not None and max_age < _HSTS_PRELOAD_MIN_MAX_AGE:
            errors.append(
                f"{where}: {_HSTS_KEY}.preload requires max_age of at least"
                f" {_HSTS_PRELOAD_MIN_MAX_AGE} (one year), got {max_age}"
            )
        if settings.get("always_use_https") == "off":
            errors.append(
                f"{where}: {_HSTS_KEY}.preload requires an HTTP-to-HTTPS redirect"
                " on the same host, but always_use_https is 'off'"
            )


_dump_zone_tls = make_dump_hook(SECTION, "get_zone_tls_settings")


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ZoneTlsFormatter(SettingsFormatter):
    """Formats HTTPS setting diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(plan_type=ZoneTlsPlan, prefix="zone_tls")


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class ZoneTlsExtension(ProviderExtension):
    """HTTPS negotiation and enforcement."""

    section = SECTION

    def prefetch(self, desired, scope, provider):
        return _prefetch_zone_tls(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_zone_tls(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_zone_tls(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_zone_tls(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_zone_tls() -> None:
    """Register all HTTPS-settings hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension(SECTION, ZoneTlsFormatter())
    register_validate_extension(_validate_zone_tls)
