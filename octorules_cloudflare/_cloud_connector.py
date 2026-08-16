"""Cloud Connector rules, managed as code.

Cloud Connector routes matching requests directly to an object-storage
provider -- Cloudflare R2, AWS S3, Google Cloud Storage, or Azure Storage --
via an ordered list of expression-matched rules:

.. code-block:: yaml

    cloud_connector_rules:
      - description: "Serve /assets from the R2 bucket"
        expression: 'starts_with(http.request.uri.path, "/assets/")'
        provider: cloudflare_r2
        parameters:
          host: assets.account-a.r2.cloudflarestorage.com

The rules look phase-like but do not live in the Ruleset Engine's public
surface: the only endpoints are ``GET/PUT /zones/{id}/cloud_connector/rules``,
and the ``PUT`` replaces the whole list. Two consequences shape this module:

- **Identity is the description.** Ruleset phases persist each rule's ``ref``
  and octorules diffs on it; the Cloud Connector API has no such field, so a
  rule here is identified by its ``description`` -- the same convention as
  Page Shield policies. Descriptions are therefore required and must be
  unique.
- **Apply is wholesale.** Any change -- add, remove, modify, or reorder --
  is applied as one ``PUT`` of the full desired list. Rules that persist
  across the update keep their API-side ``id`` so Cloudflare sees an update
  rather than a delete-and-recreate.
"""

import logging
from dataclasses import dataclass, field

from octorules.expression import normalize_expression
from octorules.extensions import ProviderExtension, make_synthetic_phase
from octorules.planner import ChangeType, RuleChange, normalize_rule
from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)

SECTION = "cloudflare.cloud_connector_rules"

# The plan bucket and formatter key ("cloud_connector: ..." in plan output).
PLAN_KEY = "cloud_connector"

# Cloud Provider type -- a closed enum in the Cloudflare API schema.
VALID_PROVIDERS = frozenset({"aws_s3", "cloudflare_r2", "gcp_storage", "azure_storage"})

_REQUIRED_FIELDS = ("description", "expression", "provider")
_KNOWN_FIELDS = frozenset({"description", "enabled", "expression", "parameters", "provider"})
_KNOWN_PARAMETERS = frozenset({"host"})


# ---------------------------------------------------------------------------
# Plan dataclass
# ---------------------------------------------------------------------------
@dataclass
class CloudConnectorPlan:
    """All Cloud Connector rule changes for a zone.

    One plan per zone rather than one per rule: the API's ``PUT`` replaces
    the whole list, so the plan carries the full prepared desired list for
    apply alongside the per-rule changes shown to the reviewer.
    """

    changes: list[RuleChange] = field(default_factory=list)
    desired_rules: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0

    @property
    def total_changes(self) -> int:
        return len(self.changes)


def _make_cloud_connector_phase(description: str):
    """Create a synthetic Phase for plan formatting and expression linting."""
    return make_synthetic_phase(
        "cloud_connector",
        description,
        SECTION,
        zone_level=True,
        account_level=False,
    )


# ---------------------------------------------------------------------------
# Preparation and diff
# ---------------------------------------------------------------------------
def prepare_cloud_connector_rules(desired_rules: list[dict]) -> list[dict]:
    """Prepare desired rules: normalize expressions, default ``enabled``.

    Returns new dicts -- the originals are never mutated. No action or ref
    handling here: Cloud Connector rules have neither.
    """
    prepared: list[dict] = []
    for rule in desired_rules:
        rule = rule.copy()
        if isinstance(rule.get("expression"), str):
            rule["expression"] = normalize_expression(rule["expression"])
        if "enabled" not in rule:
            rule["enabled"] = True
        prepared.append(rule)
    return prepared


def _rules_by_description(rules: list[dict]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for rule in rules:
        desc = rule.get("description")
        if isinstance(desc, str) and desc:
            if desc in result:
                log.warning(
                    "Duplicate Cloud Connector rule description %r -- later entry"
                    " overwrites earlier in the diff",
                    desc,
                )
            result[desc] = rule
    return result


def diff_cloud_connector_rules(
    desired_rules: list[dict],
    current_rules: list[dict],
) -> CloudConnectorPlan:
    """Compute the diff for Cloud Connector rules, keyed by description.

    Order is part of the desired state: when the two sides hold the same
    rules in a different sequence, the plan carries a REORDER change. Rules
    that persist keep the ``id`` Cloudflare assigned them, so the wholesale
    ``PUT`` reads as an update rather than a delete-and-recreate.
    """
    desired = prepare_cloud_connector_rules(desired_rules)
    desired_by_desc = _rules_by_description(desired)
    current_by_desc = _rules_by_description(current_rules)

    changes: list[RuleChange] = []

    for desc, rule in desired_by_desc.items():
        current = current_by_desc.get(desc)
        if current is None:
            changes.append(
                RuleChange(
                    change_type=ChangeType.ADD,
                    ref=desc,
                    phase=_make_cloud_connector_phase(desc),
                    desired=rule,
                )
            )
        elif normalize_rule(rule) != normalize_rule(current):
            changes.append(
                RuleChange(
                    change_type=ChangeType.MODIFY,
                    ref=desc,
                    phase=_make_cloud_connector_phase(desc),
                    current=current,
                    desired=rule,
                )
            )

    for desc, current in current_by_desc.items():
        if desc not in desired_by_desc:
            changes.append(
                RuleChange(
                    change_type=ChangeType.REMOVE,
                    ref=desc,
                    phase=_make_cloud_connector_phase(desc),
                    current=current,
                )
            )

    desired_order = [d for d in (r.get("description") for r in desired) if d]
    current_order = [d for d in (r.get("description") for r in current_rules) if d]
    if set(desired_order) == set(current_order) and desired_order != current_order:
        changes.append(
            RuleChange(
                change_type=ChangeType.REORDER,
                ref="*",
                phase=_make_cloud_connector_phase("*"),
            )
        )

    # Attach the API-side id of every persisting rule to the payload.
    payload: list[dict] = []
    for rule in desired:
        desc = rule.get("description")
        current = current_by_desc.get(desc) if isinstance(desc, str) else None
        if current is not None and current.get("id"):
            rule = {**rule, "id": current["id"]}
        payload.append(rule)

    return CloudConnectorPlan(changes=changes, desired_rules=payload)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_cloud_connector(all_desired, scope, provider):
    """Prefetch: fetch the zone's current Cloud Connector rules."""
    if not scope.zone_id:
        return None
    desired = all_desired.get(SECTION)
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_cloud_connector_rules(scope)
    except ProviderAuthError:
        raise  # The section is declared -- permission is needed
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("%s: product not enabled on this zone", SECTION)
            return None
        log.warning("Failed to fetch Cloud Connector rules for %s", scope.label)
        current = []

    return (current, desired)


def _finalize_cloud_connector(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    if not isinstance(desired, list):
        return
    plan = diff_cloud_connector_rules(desired, current)
    if plan.has_changes:
        zp.extension_plans.setdefault(PLAN_KEY, []).append(plan)


def _apply_cloud_connector(zp, plans, scope, provider):
    """Apply Cloud Connector rule changes as one wholesale ``PUT``."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, CloudConnectorPlan) or not plan.has_changes:
            continue
        n_rules = len(plan.desired_rules)
        log.info(
            "  %s/%s: replacing rule list (%d rule(s))",
            zp.zone_name,
            PLAN_KEY,
            n_rules,
        )
        provider.put_cloud_connector_rules(scope, plan.desired_rules)
        synced.append(f"{zp.zone_name}/{PLAN_KEY}")

    return synced, None


def _dump_cloud_connector(scope, provider):
    """Dump hook: fetch current rules, strip API-only fields, keep order."""
    if not scope.zone_id:
        return None

    from octorules.phases import strip_api_fields
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        rules = provider.get_cloud_connector_rules(scope)
    except ProviderAuthError:
        log.info("%s: skipped (insufficient permissions)", SECTION)
        return None
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("%s: product not enabled on this zone", SECTION)
        else:
            log.debug("%s: %s", SECTION, e)
        return None
    if not rules:
        return None
    return {SECTION: [strip_api_fields(r, "rule") for r in rules]}


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
def validate_cloud_connector_rule(entry: dict, index: int) -> list[str]:
    """Validate one cloud_connector_rules entry. Returns error strings."""
    problems: list[str] = []
    ctx = f"cloud_connector_rules[{index}]"
    desc = entry.get("description")
    if isinstance(desc, str) and desc:
        ctx = f"{ctx} ({desc!r})"

    for field_name in _REQUIRED_FIELDS:
        value = entry.get(field_name)
        if not isinstance(value, str) or not value:
            problems.append(f"{ctx}: {field_name!r} must be a non-empty string")

    provider_name = entry.get("provider")
    if isinstance(provider_name, str) and provider_name not in VALID_PROVIDERS:
        problems.append(
            f"{ctx}: invalid provider {provider_name!r} (must be one of {sorted(VALID_PROVIDERS)})"
        )

    enabled = entry.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        problems.append(f"{ctx}: 'enabled' must be true or false, got {enabled!r}")

    unknown = sorted(k for k in entry if k not in _KNOWN_FIELDS)
    if unknown:
        hint = " (rules here are identified by description, not ref)" if "ref" in unknown else ""
        problems.append(f"{ctx}: unknown field(s) {unknown}{hint}")

    parameters = entry.get("parameters")
    if parameters is not None:
        if not isinstance(parameters, dict):
            problems.append(
                f"{ctx}: 'parameters' must be a mapping, got {type(parameters).__name__}"
            )
        else:
            unknown_params = sorted(k for k in parameters if k not in _KNOWN_PARAMETERS)
            if unknown_params:
                problems.append(f"{ctx}: unknown parameters key(s) {unknown_params}")
            host = parameters.get("host")
            if host is not None and (not isinstance(host, str) or not host):
                problems.append(f"{ctx}: parameters.host must be a non-empty string")

    return problems


def _validate_cloud_connector(desired, zone_name, errors, lines):
    """Validate cloud_connector_rules entries offline."""
    entries = desired.get(SECTION)
    if not isinstance(entries, list):
        return

    seen: set[str] = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(
                f"  {zone_name}/{SECTION}: entry at index {i} must be a mapping,"
                f" got {type(entry).__name__}"
            )
            continue
        for problem in validate_cloud_connector_rule(entry, i):
            errors.append(f"  {zone_name}/{SECTION}: {problem}")
        desc = entry.get("description")
        if isinstance(desc, str) and desc:
            if desc in seen:
                errors.append(
                    f"  {zone_name}/{SECTION}: duplicate description {desc!r}"
                    " -- descriptions are identity keys"
                )
            seen.add(desc)


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class CloudConnectorFormatter:
    """Formatter for Cloud Connector rule plans."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules.formatter import Pen, format_change

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            lines.append(p.header("  cloud_connector"))
            for change in plan.changes:
                lines.extend(format_change(change, use_color))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        from octorules.formatter import change_to_dict

        result = []
        for plan in plans:
            entry: dict = {"changes": [change_to_dict(c) for c in plan.changes]}
            result.append(entry)
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import md_change_row

        lines: list[str] = []
        for plan in plans:
            for c in plan.changes:
                lines.append(md_change_row(c, PLAN_KEY, pending_diffs, has_reorder=True))
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from octorules.formatter import (
            HTML_TABLE_HEADER,
            html_render_changes,
            html_summary_row,
        )

        total_creates = total_removes = total_modifies = total_reorders = 0

        for plan in plans:
            lines.append("<h3>cloud_connector</h3>")
            lines.extend(HTML_TABLE_HEADER)
            creates, removes, modifies, reorders = html_render_changes(plan.changes, lines)
            lines.extend(html_summary_row(creates, removes, modifies, reorders))
            lines.append("</table>")
            total_creates += creates
            total_removes += removes
            total_modifies += modifies
            total_reorders += reorders

        return total_creates, total_removes, total_modifies, total_reorders


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class CloudConnectorExtension(ProviderExtension):
    """Cloud Connector routing rules.

    ``section`` and ``name`` differ: the zone-file key is
    ``cloud_connector_rules`` while plans bucket under ``cloud_connector``.
    """

    section = SECTION
    name = PLAN_KEY

    def prefetch(self, desired, scope, provider):
        return _prefetch_cloud_connector(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_cloud_connector(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_cloud_connector(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_cloud_connector(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_cloud_connector() -> None:
    """Register all Cloud Connector hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension(PLAN_KEY, CloudConnectorFormatter())
    register_validate_extension(_validate_cloud_connector)
