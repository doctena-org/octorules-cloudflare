"""Schema registry loader — populates field/function registries at import time.

Builds the registry dynamically from octorules-wirefilter's get_schema_info()
(a required dependency) merged with overlay.toml metadata (phase restrictions,
plan requirements, is_response flags).
"""

import functools
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_SCHEMAS_DIR = Path(__file__).resolve().parent
_OVERLAY_PATH = _SCHEMAS_DIR / "overlay.toml"

# Cloudflare's account-level Magic Transit / Layer-4 phases. Their fields come
# from wirefilter's "magic_firewall" scheme and are available only in these
# phases. Single source for both the field registry (phase policy here) and the
# expression bridge (scheme selection).
MAGIC_FIREWALL_PHASES = frozenset(
    {
        "network_ddos_rules",
        "network_firewall_rules",
        "network_firewall_managed",
        "network_firewall_ratelimit",
        "network_firewall_ids",
    }
)


@functools.lru_cache(maxsize=1)
def _load_overlay() -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    with open(_OVERLAY_PATH, "rb") as f:
        return tomllib.load(f)


def merge_wirefilter_overlay(wirefilter_schema: dict) -> dict:
    """Merge wirefilter schema data with overlay.toml metadata.

    Takes raw wirefilter schema (from ``get_schema_info()``) and enriches it
    with Python-only metadata from overlay.toml (phase restrictions, plan
    requirements, is_response flags).
    """
    overlay = _load_overlay()
    field_overlay = overlay.get("fields", {})
    func_overlay = overlay.get("functions", {})

    fields = []
    for entry in wirefilter_schema["fields"]:
        name = entry["name"]
        meta = field_overlay.get(name, {})
        f: dict = {"name": name, "type": entry["type"]}
        if meta.get("requires_plan"):
            f["requires_plan"] = meta["requires_plan"]
        if meta.get("is_response"):
            f["is_response"] = True
        fields.append(f)

    all_func_names = list(wirefilter_schema["functions"])
    for name in func_overlay:
        if name not in all_func_names:
            all_func_names.append(name)

    functions = []
    for name in all_func_names:
        meta = func_overlay.get(name, {})
        f = {"name": name}
        if meta.get("restricted_phases"):
            f["restricted_phases"] = sorted(meta["restricted_phases"])
        if meta.get("requires_plan"):
            f["requires_plan"] = meta["requires_plan"]
        functions.append(f)

    return {"fields": fields, "functions": functions}


def build_schema_from_wirefilter(get_schema_info) -> dict:
    """Build the full merged schema (HTTP + Magic Transit L4) from wirefilter.

    HTTP fields come from the default scheme + overlay metadata. Layer-4 fields
    come from wirefilter's ``magic_firewall`` scheme — names and types are
    derived from wirefilter (the single source of truth), tagged here with the
    L4 phase policy. Fields shared with the HTTP context (e.g. ``ip.src``) keep
    their all-phase HTTP definition.
    """
    data = merge_wirefilter_overlay(get_schema_info())
    http_names = {f["name"] for f in data["fields"]}
    for entry in get_schema_info(scheme="magic_firewall")["fields"]:
        if entry["name"] in http_names:
            continue
        data["fields"].append(
            {
                "name": entry["name"],
                "type": entry["type"],
                "phases": sorted(MAGIC_FIREWALL_PHASES),
            }
        )
    return data


def load_schema() -> dict:
    """Load schema data from wirefilter + overlay.

    octorules-wirefilter is a required dependency, so the FFI is always present;
    there is no frozen fallback.
    """
    try:
        from octorules_wirefilter import get_schema_info
    except ImportError as e:  # pragma: no cover - wirefilter is a required dependency
        raise ImportError(
            "octorules-wirefilter is required but not importable. "
            "Reinstall octorules-cloudflare (it depends on octorules-wirefilter)."
        ) from e
    return build_schema_from_wirefilter(get_schema_info)


def load_managed_lists() -> frozenset[str]:
    """Load valid Cloudflare managed list names from overlay.toml."""
    overlay = _load_overlay()
    ml = overlay.get("managed_lists", {})
    # New format: kinds = {name: kind}
    kinds = ml.get("kinds", {})
    if kinds:
        return frozenset(kinds.keys())
    # Legacy format: names = [...]
    return frozenset(ml.get("names", []))


def load_managed_list_kinds() -> dict[str, str]:
    """Load managed list name → kind mapping from overlay.toml."""
    overlay = _load_overlay()
    return dict(overlay.get("managed_lists", {}).get("kinds", {}))
