"""Shared helpers for the flat zone-settings extensions.

Used by ``_bot_management``, ``_zone_security``, and ``_url_normalization``,
which all diff a flat ``{field: value}`` dict of desired YAML settings
against the zone's live configuration, and by the toggle extensions
(``_leaked_credentials``, ``_content_scanning``) for post-apply
verification of the ``enabled`` switch.

Includes factory functions for _prefetch_*, _finalize_*, and _dump_* hooks
to reduce duplication across modules.
"""

import logging
from collections.abc import Callable

log = logging.getLogger(__name__)

_MISSING = object()


def partition_unsupported(current: dict, desired: dict) -> tuple[dict, list[str]]:
    """Split *desired* into manageable fields and zone-unsupported ones.

    A field declared in YAML but absent from a **non-empty** live response
    is not exposed on this zone (plan- or product-gated): an update sends
    it, the API ignores it, and the next read omits it again — so diffing
    it produces a Modify that apply can never close. Such fields are
    split out so plans can report them as notes instead of phantom
    changes.

    An **empty** *current* means the live read failed or returned nothing —
    field support is unknown, so every desired field stays manageable and
    the diff proposes all of them (the pre-existing recovery behaviour).
    """
    if not current:
        return dict(desired), []
    unsupported = sorted(k for k in desired if k not in current)
    managed = {k: v for k, v in desired.items() if k in current}
    return managed, unsupported


def warn_unsupported(section: str, scope, unsupported: list[str]) -> None:
    """Log a warning for each YAML field the zone does not expose.

    Plan output only renders zones that have actual changes, so a plan
    carrying nothing but unsupported-field notes would otherwise be
    invisible. The warning guarantees a signal on every plan/sync run;
    the plan-output note additionally shows whenever the zone renders.
    """
    for name in unsupported:
        log.warning(
            "%s: %r is declared in YAML but not exposed on zone %s --"
            " ignored (remove it from the YAML or check the zone's plan)",
            section,
            name,
            scope.label,
        )


def verify_settings_applied(fetch, scope, sent: dict, section: str) -> list[str]:
    """Re-read settings after an update and warn about values that did not take.

    Cloudflare can accept an update (HTTP 200) yet ignore or clamp an
    individual value — e.g. a value gated by the zone's plan. Without a
    read-back that only ever surfaces as a diff that reappears on every
    later plan. *fetch* is the provider getter (returns the normalized
    settings dict), *sent* the normalized values just written.

    Returns the field names that did not take, logging a warning for
    each. Read-back problems are logged and swallowed — verification
    must never turn a successful update into an apply failure. A field
    that did not take is also only a warning: it may be plan-gated, or
    (rarely) a stale read-after-write.
    """
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = fetch(scope)
    except (ProviderAuthError, ProviderError) as e:
        log.warning(
            "%s: update succeeded for %s but the verification read-back"
            " failed (%s); skipping verification",
            section,
            scope.label,
            e,
        )
        return []

    failed: list[str] = []
    for name, value in sorted(sent.items()):
        got = current.get(name, _MISSING)
        if got != value:
            failed.append(name)
            log.warning(
                "%s: Cloudflare accepted the update for %s but %r reads"
                " back as %s (sent %r) -- the value may not be available"
                " on this zone's plan",
                section,
                scope.label,
                name,
                "absent" if got is _MISSING else repr(got),
                value,
            )
    return failed


# ---------------------------------------------------------------------------
# Factory functions for _prefetch_*, _finalize_*, and _dump_* hooks
# ---------------------------------------------------------------------------
def make_prefetch_hook(section_name: str, getter_attr: str) -> Callable:
    """Create a _prefetch_* hook function for a settings extension.

    Args:
        section_name: The YAML section name (e.g. "cloudflare_bot_management")
        getter_attr: The provider method name to fetch current settings
                     (e.g. "get_bot_management")

    Returns a function matching the _prefetch_* signature that fetches
    current settings and returns (current, desired) or None.
    """

    def _prefetch_hook(all_desired, scope, provider):
        """Prefetch: fetch current settings."""
        if not scope.zone_id:
            return None
        desired = all_desired.get(section_name)
        if desired is None:
            return None

        from octorules.provider.exceptions import ProviderAuthError, ProviderError

        getter = getattr(provider, getter_attr)
        try:
            current = getter(scope)
        except ProviderAuthError:
            if section_name in all_desired:
                raise  # User explicitly declared this section -- permission is needed
            log.debug("%s: skipped (no permission and not in desired config)", section_name)
            return None
        except ProviderError as e:
            if "not been enabled" in str(e) or "not enabled" in str(e):
                log.debug("%s: product not enabled on this zone", section_name)
                return None
            log.warning("Failed to fetch %s settings for %s", section_name, scope.label)
            current = {}

        return (current, desired)

    return _prefetch_hook


def make_dump_hook(section_name: str, getter_attr: str) -> Callable:
    """Create a _dump_* hook function for a settings extension.

    Args:
        section_name: The YAML section name (e.g. "cloudflare_bot_management")
        getter_attr: The provider method name to fetch current settings
                     (e.g. "get_bot_management")

    Returns a function matching the _dump_* signature that exports
    current settings to dump output.
    """

    def _dump_hook(scope, provider, out_dir):
        """Export current settings to dump output."""
        if not scope.zone_id:
            return None
        from octorules.provider.exceptions import ProviderAuthError, ProviderError

        getter = getattr(provider, getter_attr)
        try:
            settings = getter(scope)
        except ProviderAuthError:
            log.info("%s: skipped (insufficient permissions)", section_name)
            return None
        except ProviderError as e:
            if "not been enabled" in str(e) or "not enabled" in str(e):
                log.debug("%s: product not enabled on this zone", section_name)
            else:
                log.debug("%s: %s", section_name, e)
            return None

        if settings:
            return {section_name: settings}
        return None

    return _dump_hook
