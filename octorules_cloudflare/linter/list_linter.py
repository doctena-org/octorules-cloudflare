"""List validation — Category Q rules.

Validates the structural correctness and item validity of lists
(IP, ASN, hostname, redirect).
"""

import ipaddress
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity

RULE_IDS = frozenset({"CF470", "CF471", "CF472", "CF473", "CF474", "CF475", "CF476"})

_VALID_KINDS = frozenset({"ip", "asn", "hostname", "redirect"})

# Required item field per list kind
_ITEM_FIELD_BY_KIND: dict[str, str] = {
    "ip": "ip",
    "asn": "asn",
    "hostname": "hostname",
    "redirect": "redirect",
}


def lint_lists(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all list validation checks."""
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        return

    seen_names: set[str] = set()
    for i, entry in enumerate(lists_section):
        if not isinstance(entry, dict):
            continue
        ctx.set_location(entry)

        name = entry.get("name")
        name_label = name if isinstance(name, str) and name else f"index {i}"

        # CF470: Missing or invalid name
        if not isinstance(name, str) or not name:
            ctx.add(
                LintResult(
                    rule_id="CF470",
                    severity=Severity.ERROR,
                    message=f"List at index {i} is missing required 'name' field",
                    phase="lists",
                )
            )
        elif name in seen_names:
            ctx.add(
                LintResult(
                    rule_id="CF470",
                    severity=Severity.ERROR,
                    message=f"Duplicate list name {name!r}",
                    phase="lists",
                    ref=name_label,
                )
            )
        else:
            seen_names.add(name)

        # CF471: Missing or invalid kind
        kind = entry.get("kind")
        if not isinstance(kind, str) or not kind:
            ctx.add(
                LintResult(
                    rule_id="CF471",
                    severity=Severity.ERROR,
                    message=f"List {name_label!r} is missing required 'kind' field",
                    phase="lists",
                    ref=name_label,
                )
            )
            continue
        if kind not in _VALID_KINDS:
            ctx.add(
                LintResult(
                    rule_id="CF471",
                    severity=Severity.ERROR,
                    message=(
                        f"Invalid list kind {kind!r} for list {name_label!r}."
                        f" Must be one of: {', '.join(sorted(_VALID_KINDS))}"
                    ),
                    phase="lists",
                    ref=name_label,
                    field="kind",
                )
            )
            continue

        # Validate items
        items = entry.get("items")
        if not isinstance(items, list):
            continue

        _lint_list_items(items, kind, name_label, ctx)

        # CF476: list exceeds maximum item count (10,000)
        if len(items) > 10000:
            ctx.add(
                LintResult(
                    rule_id="CF476",
                    severity=Severity.WARNING,
                    message=(
                        f"List {name_label!r} has {len(items):,} items (exceeds 10,000 item limit)"
                    ),
                    phase="lists",
                    ref=name_label,
                )
            )


def _lint_list_items(items: list[Any], kind: str, name_label: str, ctx: LintContext) -> None:
    """Validate individual list items (CF472-CF475)."""
    required_field = _ITEM_FIELD_BY_KIND.get(kind, "")
    seen_values: set[str] = set()

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue

        # CF472: Missing required field for kind
        item_val = item.get(required_field)
        if item_val is None:
            ctx.add(
                LintResult(
                    rule_id="CF472",
                    severity=Severity.ERROR,
                    message=(
                        f"Item at index {i} in list {name_label!r}"
                        f" is missing required '{required_field}' field"
                    ),
                    phase="lists",
                    ref=name_label,
                )
            )
            continue

        # Kind-specific validation
        if kind == "ip":
            _lint_ip_item(item_val, i, name_label, seen_values, ctx)
        elif kind == "asn":
            _lint_asn_item(item_val, i, name_label, seen_values, ctx)
        elif kind == "hostname":
            _lint_hostname_item(item_val, i, name_label, seen_values, ctx)
        elif kind == "redirect":
            _lint_redirect_item(item_val, i, name_label, seen_values, ctx)


def _lint_ip_item(val: Any, index: int, name_label: str, seen: set[str], ctx: LintContext) -> None:
    """CF473: Invalid IP, CF475: Duplicate."""
    if not isinstance(val, str):
        return
    try:
        ipaddress.ip_network(val, strict=False)
    except ValueError:
        ctx.add(
            LintResult(
                rule_id="CF473",
                severity=Severity.ERROR,
                message=f"Invalid IP address {val!r} at index {index} in list {name_label!r}",
                phase="lists",
                ref=name_label,
            )
        )
        return

    if val in seen:
        ctx.add(
            LintResult(
                rule_id="CF475",
                severity=Severity.WARNING,
                message=f"Duplicate IP {val!r} in list {name_label!r}",
                phase="lists",
                ref=name_label,
            )
        )
    seen.add(val)


def _lint_asn_item(val: Any, index: int, name_label: str, seen: set[str], ctx: LintContext) -> None:
    """CF474: Invalid ASN, CF475: Duplicate."""
    if not isinstance(val, int) or isinstance(val, bool):
        ctx.add(
            LintResult(
                rule_id="CF474",
                severity=Severity.ERROR,
                message=(
                    f"ASN value at index {index} in list {name_label!r}"
                    f" must be an integer, got {type(val).__name__}"
                ),
                phase="lists",
                ref=name_label,
            )
        )
        return
    if val < 0 or val > 4294967295:
        ctx.add(
            LintResult(
                rule_id="CF474",
                severity=Severity.ERROR,
                message=(
                    f"ASN value {val} at index {index} in list {name_label!r}"
                    " is outside valid range (0-4294967295)"
                ),
                phase="lists",
                ref=name_label,
            )
        )
        return

    key = str(val)
    if key in seen:
        ctx.add(
            LintResult(
                rule_id="CF475",
                severity=Severity.WARNING,
                message=f"Duplicate ASN {val} in list {name_label!r}",
                phase="lists",
                ref=name_label,
            )
        )
    seen.add(key)


def _lint_hostname_item(
    val: Any, index: int, name_label: str, seen: set[str], ctx: LintContext
) -> None:
    """CF475: Duplicate hostname."""
    if not isinstance(val, dict):
        return
    url_hostname = val.get("url_hostname", "")
    if not isinstance(url_hostname, str) or not url_hostname:
        return
    if url_hostname in seen:
        ctx.add(
            LintResult(
                rule_id="CF475",
                severity=Severity.WARNING,
                message=f"Duplicate hostname {url_hostname!r} in list {name_label!r}",
                phase="lists",
                ref=name_label,
            )
        )
    seen.add(url_hostname)


def _lint_redirect_item(
    val: Any, index: int, name_label: str, seen: set[str], ctx: LintContext
) -> None:
    """CF475: Duplicate redirect source."""
    if not isinstance(val, dict):
        return
    source = val.get("source_url", "")
    if not isinstance(source, str) or not source:
        return
    if source in seen:
        ctx.add(
            LintResult(
                rule_id="CF475",
                severity=Severity.WARNING,
                message=f"Duplicate redirect source_url {source!r} in list {name_label!r}",
                phase="lists",
                ref=name_label,
            )
        )
    seen.add(source)
