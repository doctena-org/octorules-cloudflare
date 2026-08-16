"""Notification policies (account-scoped alerting), managed as code.

Cloudflare's notification policies live on the account, not on a zone:
``/accounts/{id}/alerting/v3/policies``. The section therefore belongs in the
account-scoped rules file, and this is the first extension that runs on an
account scope -- every other extension skips itself when ``scope.zone_id`` is
empty; this one skips itself when ``scope.account_id`` is.

.. code-block:: yaml

    # account-scoped file, e.g. rules/account-a.yaml
    cloudflare:
      alerting_policies:
        - name: "Certificate expiring soon"
          alert_type: dedicated_ssl_certificate_event_type
          enabled: true
          mechanisms:
            email: ["security@account-a.example"]
            webhooks: ["$Ops Slack"]

Three translations keep the YAML free of UUIDs:

- **Webhook mechanisms** are referenced by destination name with a ``$``
  prefix (``"$Ops Slack"``), resolved against the account's webhook
  destinations at plan time. A raw UUID also passes through unchanged.
- **``filters.zones``** carries zone names in YAML; the API stores zone ids.
  Names are resolved on plan and ids translated back on dump.
- **``alert_type``** is validated against the account's own
  ``available_alerts`` registry at plan time -- which types this account can
  use, and which filters each accepts -- rather than a hardcoded table. A
  filter the registry marks as required (``Range`` starting ``1``) must be
  declared; an unknown filter key is only warned about, since the registry
  moves faster than any pinned list.

Policies have no ``ref``; ``name`` is the only human-stable field, so it is
the identity key (required and unique), the same convention as Page Shield's
``description``. Fields the YAML declares replace the live value wholesale on
update; optional fields the YAML omits (``description``, ``alert_interval``,
``filters``) keep whatever the dashboard set.
"""

import logging
import re
from dataclasses import dataclass, field

from octorules.extensions import ProviderExtension, make_synthetic_phase
from octorules.phases import get_api_fields
from octorules.planner import ChangeType, RuleChange, RuleValidationError
from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)

SECTION = "cloudflare.alerting_policies"

# The plan bucket and formatter key ("alerting: ..." in plan output).
PLAN_KEY = "alerting"

_REQUIRED_FIELDS = ("name", "alert_type", "enabled", "mechanisms")
_KNOWN_FIELDS = frozenset(_REQUIRED_FIELDS) | {"alert_interval", "description", "filters"}
_MECHANISM_KEYS = ("email", "pagerduty", "webhooks")
_DIFF_FIELDS = (
    "alert_type",
    "enabled",
    "description",
    "alert_interval",
    "filters",
    "mechanisms",
)

_ZONE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# Plan dataclass
# ---------------------------------------------------------------------------
@dataclass
class AlertingPolicyPlan:
    """Lifecycle plan for a single notification policy."""

    name: str
    policy_id: str | None = None  # None for CREATE
    create: bool = False
    delete: bool = False
    changes: list[RuleChange] = field(default_factory=list)  # field-level changes
    desired_policy: dict | None = None  # resolved (id-space) desired state
    current_policy: dict | None = None  # normalized live state, for update carry-over

    @property
    def description(self) -> str:
        """Identity label. Safety checks and the plan hash duck-type on
        ``description``; for a policy that label is its name."""
        return self.name

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


def _make_alerting_phase(name: str):
    """Create a synthetic Phase for plan formatting."""
    return make_synthetic_phase("alerting", name, SECTION, zone_level=False, account_level=True)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def _normalize_mechanisms(raw: object) -> dict:
    """``{email: [{"id": addr}, ...]}`` (API) or ``{email: [addr, ...]}``
    (YAML) -> ``{email: sorted([addr, ...])}``, dropping empty types."""
    if not isinstance(raw, dict):
        return {}
    result: dict = {}
    for key in _MECHANISM_KEYS:
        entries = raw.get(key)
        if not entries:
            continue
        values = []
        for entry in entries:
            if isinstance(entry, dict):
                if entry.get("id"):
                    values.append(str(entry["id"]))
            elif entry:
                values.append(str(entry))
        if values:
            result[key] = sorted(values)
    return result


def _normalize_filters(raw: object) -> dict:
    """Filter values are sets of strings as far as comparison goes."""
    if not isinstance(raw, dict):
        return {}
    result: dict = {}
    for key, values in raw.items():
        if isinstance(values, list):
            result[key] = sorted(str(v) for v in values)
    return result


def normalize_alerting_policy(policy: dict) -> dict:
    """Strip API-only fields and normalize a policy for comparison."""
    excluded = get_api_fields("alerting_policy")
    result: dict = {}
    for k, v in policy.items():
        if k in excluded or v is None:
            continue
        if k == "mechanisms":
            result[k] = _normalize_mechanisms(v)
        elif k == "filters":
            result[k] = _normalize_filters(v)
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# Name resolution (webhook $references, zone names in filters)
# ---------------------------------------------------------------------------
def resolve_alerting_policy(
    entry: dict,
    webhook_ids: dict[str, str],
    zone_ids: dict[str, str],
) -> dict:
    """Translate a YAML policy entry into the id-space the API stores.

    ``$name`` webhook references become webhook ids; zone names inside
    ``filters.zones`` become zone ids. Raw UUIDs pass through either way.
    Raises :class:`RuleValidationError` for a reference that resolves to
    nothing -- a create or update built on it would fail at the API.
    """
    entry = {k: v for k, v in entry.items() if k in _KNOWN_FIELDS}
    name = entry.get("name", "?")

    mechanisms = entry.get("mechanisms")
    if isinstance(mechanisms, dict):
        resolved_mech = dict(mechanisms)
        webhooks = mechanisms.get("webhooks")
        if isinstance(webhooks, list):
            resolved_webhooks = []
            for ref in webhooks:
                if isinstance(ref, str) and ref.startswith("$"):
                    webhook_name = ref[1:]
                    if webhook_name not in webhook_ids:
                        known = ", ".join(sorted(webhook_ids)) or "none"
                        raise RuleValidationError(
                            f"alerting_policies ({name!r}): webhook destination"
                            f" {webhook_name!r} does not exist on this account"
                            f" (available: {known})"
                        )
                    resolved_webhooks.append(webhook_ids[webhook_name])
                else:
                    resolved_webhooks.append(ref)
            resolved_mech["webhooks"] = resolved_webhooks
        entry["mechanisms"] = resolved_mech

    filters = entry.get("filters")
    if isinstance(filters, dict) and isinstance(filters.get("zones"), list):
        resolved_zones = []
        for zone in filters["zones"]:
            if isinstance(zone, str) and zone in zone_ids:
                resolved_zones.append(zone_ids[zone])
            elif isinstance(zone, str) and _ZONE_ID_RE.match(zone):
                resolved_zones.append(zone)
            else:
                raise RuleValidationError(
                    f"alerting_policies ({name!r}): filters.zones entry {zone!r}"
                    " is neither a zone name this token can see nor a zone id"
                )
        entry["filters"] = {**filters, "zones": resolved_zones}

    return entry


def unresolve_alerting_policy(
    policy: dict,
    webhook_names: dict[str, str],
    zone_names: dict[str, str],
) -> dict:
    """Translate a normalized live policy back to the YAML-facing form.

    Webhook ids become ``$name`` references and zone ids inside
    ``filters.zones`` become zone names, wherever a mapping is known --
    unknown ids stay as they are rather than guessing.
    """
    policy = dict(policy)
    mechanisms = policy.get("mechanisms")
    if isinstance(mechanisms, dict) and mechanisms.get("webhooks"):
        policy["mechanisms"] = {
            **mechanisms,
            "webhooks": [
                f"${webhook_names[w]}" if w in webhook_names else w for w in mechanisms["webhooks"]
            ],
        }
    filters = policy.get("filters")
    if isinstance(filters, dict) and filters.get("zones"):
        policy["filters"] = {
            **filters,
            "zones": [zone_names.get(z, z) for z in filters["zones"]],
        }
    return policy


# ---------------------------------------------------------------------------
# Capability validation (against the account's available_alerts registry)
# ---------------------------------------------------------------------------
def check_against_available_alerts(
    desired_policies: list[dict],
    available: dict[str, list[dict]],
    account_label: str,
) -> None:
    """Validate desired policies against the account's own alert registry.

    - An ``alert_type`` the registry does not list fails the plan (the
      create would 400, or the account lacks the entitlement).
    - A filter the registry marks required (``Range`` starting with ``1``)
      but the YAML does not declare fails the plan for the same reason.
    - A declared filter key the registry does not list for the type is only
      warned about: Cloudflare's registry grows faster than documentation.

    Skipped wholesale when *available* is empty (the registry read failed).
    """
    if not available:
        return
    for entry in desired_policies:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "?")
        alert_type = entry.get("alert_type")
        if not isinstance(alert_type, str):
            continue  # offline validation reports the structural error
        if alert_type not in available:
            raise RuleValidationError(
                f"alerting_policies ({name!r}): alert_type {alert_type!r} is not"
                f" available on account {account_label} (per its available_alerts"
                " registry)"
            )
        options = {
            opt["Key"]: opt
            for opt in available[alert_type]
            if isinstance(opt, dict) and opt.get("Key")
        }
        filters = entry.get("filters") if isinstance(entry.get("filters"), dict) else {}
        for key, opt in options.items():
            range_spec = str(opt.get("Range") or "")
            if range_spec.startswith("1") and not filters.get(key):
                raise RuleValidationError(
                    f"alerting_policies ({name!r}): alert_type {alert_type!r}"
                    f" requires the {key!r} filter (Range {range_spec}) and the"
                    " policy does not declare it"
                )
        for key in filters:
            if key not in options:
                log.warning(
                    "alerting_policies (%r): filter %r is not listed for"
                    " alert_type %r in the account's available_alerts registry",
                    name,
                    key,
                    alert_type,
                )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
def _diff_policy_fields(desired: dict, current: dict) -> list[RuleChange]:
    """Field-level diff over the fields *desired* declares."""
    changes: list[RuleChange] = []
    synthetic = _make_alerting_phase(desired.get("name", ""))
    for fname in _DIFF_FIELDS:
        if fname not in desired:
            continue  # undeclared optional fields keep their live value
        d_val = desired.get(fname)
        c_val = current.get(fname)
        if fname == "mechanisms":
            d_cmp, c_cmp = _normalize_mechanisms(d_val), _normalize_mechanisms(c_val)
        elif fname == "filters":
            d_cmp, c_cmp = _normalize_filters(d_val), _normalize_filters(c_val)
        else:
            d_cmp, c_cmp = d_val, c_val
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


def diff_alerting_policies(
    desired_policies: list[dict],
    current_policies: list[dict],
) -> list[AlertingPolicyPlan]:
    """Compute the full diff for notification policies, keyed by name.

    *desired_policies* must already be resolved to id-space
    (:func:`resolve_alerting_policy`); *current_policies* are raw API dicts.
    """
    plans: list[AlertingPolicyPlan] = []

    current_by_name: dict[str, dict] = {}
    for p in current_policies:
        name = p.get("name", "")
        if name:
            if name in current_by_name:
                log.warning(
                    "Duplicate notification policy name %r on the account --"
                    " only the last one is used for the diff",
                    name,
                )
            current_by_name[name] = p

    desired_names: set[str] = set()

    for entry in desired_policies:
        name = entry["name"]
        desired_names.add(name)
        current = current_by_name.get(name)

        if current is None:
            synthetic = _make_alerting_phase(name)
            field_changes = []
            for fname in _DIFF_FIELDS:
                if fname in entry:
                    field_changes.append(
                        RuleChange(
                            change_type=ChangeType.ADD,
                            ref=fname,
                            phase=synthetic,
                            desired={fname: entry[fname]},
                        )
                    )
            plans.append(
                AlertingPolicyPlan(
                    name=name,
                    create=True,
                    changes=field_changes,
                    desired_policy=entry,
                )
            )
        else:
            normalized_current = normalize_alerting_policy(current)
            field_changes = _diff_policy_fields(entry, normalized_current)
            if field_changes:
                plans.append(
                    AlertingPolicyPlan(
                        name=name,
                        policy_id=current.get("id"),
                        changes=field_changes,
                        desired_policy=entry,
                        current_policy=normalized_current,
                    )
                )

    for name, current in current_by_name.items():
        if name not in desired_names:
            plans.append(AlertingPolicyPlan(name=name, policy_id=current.get("id"), delete=True))

    return sorted(plans, key=lambda p: p.name)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_alerting(all_desired, scope, provider):
    """Prefetch: policies, the alert-type registry, and -- when the YAML
    references them -- webhook destinations and the zone id map."""
    if not scope.account_id:
        return None
    desired = all_desired.get(SECTION)
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_alerting_policies(scope)
    except ProviderAuthError:
        raise  # The section is declared -- permission is needed
    except ProviderError as e:
        if "not been enabled" in str(e) or "not enabled" in str(e):
            log.debug("%s: product not enabled on this account", SECTION)
            return None
        log.warning("Failed to fetch notification policies for %s", scope.label)
        current = []

    def _secondary(label: str, fetch) -> dict:
        try:
            return fetch(scope)
        except (ProviderAuthError, ProviderError) as e:
            log.warning("%s: could not fetch %s (%s)", SECTION, label, e)
            return {}

    available = _secondary("available_alerts", provider.get_available_alerts)

    entries = [e for e in desired if isinstance(e, dict)] if isinstance(desired, list) else []
    webhook_ids: dict[str, str] = {}
    if _uses_webhook_refs(entries):
        webhooks = _secondary("webhook destinations", provider.get_alerting_webhooks)
        webhook_ids = {w["name"]: w["id"] for w in webhooks if w.get("name") and w.get("id")}

    zone_ids: dict[str, str] = {}
    if any(isinstance(e.get("filters"), dict) and e["filters"].get("zones") for e in entries):
        zone_ids = _secondary("zone id map", provider.get_zone_id_map)

    return (current, desired, webhook_ids, zone_ids, available)


def _uses_webhook_refs(entries: list[dict]) -> bool:
    """Does any policy reference a webhook destination by ``$name``?"""
    for entry in entries:
        mechanisms = entry.get("mechanisms")
        if not isinstance(mechanisms, dict):
            continue
        refs = mechanisms.get("webhooks")
        if isinstance(refs, list) and any(isinstance(r, str) and r.startswith("$") for r in refs):
            return True
    return False


def _finalize_alerting(zp, all_desired, scope, provider, ctx):
    """Finalize: capability-check, resolve references, diff, add to plan."""
    if ctx is None:
        return

    current, desired, webhook_ids, zone_ids, available = ctx
    if not isinstance(desired, list):
        return

    entries = [e for e in desired if isinstance(e, dict)]
    check_against_available_alerts(entries, available, scope.label)
    resolved = [resolve_alerting_policy(e, webhook_ids, zone_ids) for e in entries]

    policy_plans = diff_alerting_policies(resolved, current)
    changed = [pp for pp in policy_plans if pp.has_changes]
    if changed:
        zp.extension_plans.setdefault(PLAN_KEY, []).extend(changed)


def _denormalize_mechanisms(mechanisms: dict) -> dict:
    """``{email: [addr, ...]}`` -> the API's ``{email: [{"id": addr}, ...]}``."""
    return {
        key: [{"id": v} for v in values]
        for key, values in mechanisms.items()
        if key in _MECHANISM_KEYS and isinstance(values, list)
    }


def _policy_kwargs(desired: dict, current: dict | None) -> dict:
    """Build the create/update payload: declared fields replace the live
    value wholesale; undeclared optional fields carry over from *current*."""
    merged: dict = dict(current or {})
    merged.update(desired)
    kwargs: dict = {}
    for fname in ("name", "alert_type", "enabled", "description", "alert_interval"):
        if fname in merged:
            kwargs[fname] = merged[fname]
    if "filters" in merged:
        kwargs["filters"] = _normalize_filters(merged["filters"])
    if "mechanisms" in merged:
        kwargs["mechanisms"] = _denormalize_mechanisms(_normalize_mechanisms(merged["mechanisms"]))
    return kwargs


def _apply_alerting(zp, plans, scope, provider):
    """Apply notification policy changes: creates, then updates, then deletes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, AlertingPolicyPlan) or not plan.has_changes:
            continue
        label = f"{PLAN_KEY}:{plan.name}"
        if plan.create:
            log.info("  %s/%s: creating policy", zp.zone_name, label)
            result = provider.create_alerting_policy(
                scope, **_policy_kwargs(plan.desired_policy, None)
            )
            plan.policy_id = result.get("id", "")
        elif plan.delete:
            if not plan.policy_id:
                continue
            log.info("  %s/%s: deleting policy", zp.zone_name, label)
            provider.delete_alerting_policy(scope, plan.policy_id)
        else:
            if not plan.policy_id:
                continue
            log.info("  %s/%s: applying %d change(s)", zp.zone_name, label, len(plan.changes))
            provider.update_alerting_policy(
                scope,
                plan.policy_id,
                **_policy_kwargs(plan.desired_policy, plan.current_policy),
            )
        synced.append(f"{zp.zone_name}/{label}")

    return synced, None


def _dump_alerting(scope, provider):
    """Dump hook: policies in YAML-facing form, ids translated to names."""
    if not scope.account_id:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        policies = provider.get_alerting_policies(scope)
        if not policies:
            return None
        webhooks = provider.get_alerting_webhooks(scope)
        zone_ids = provider.get_zone_id_map(scope)
    except ProviderAuthError:
        log.info("%s: skipped (insufficient permissions)", SECTION)
        return None
    except ProviderError as e:
        log.debug("%s: %s", SECTION, e)
        return None

    webhook_names = {w["id"]: w["name"] for w in webhooks if w.get("id") and w.get("name")}
    zone_names = {zid: name for name, zid in zone_ids.items()}

    dumped = [
        unresolve_alerting_policy(normalize_alerting_policy(p), webhook_names, zone_names)
        for p in sorted(policies, key=lambda p: p.get("name", ""))
    ]
    return {SECTION: dumped}


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
def validate_alerting_policy(entry: dict, index: int) -> list[str]:
    """Validate one alerting_policies entry offline. Returns error strings."""
    problems: list[str] = []
    ctx = f"alerting_policies[{index}]"
    name = entry.get("name")
    if isinstance(name, str) and name:
        ctx = f"{ctx} ({name!r})"

    for field_name in ("name", "alert_type"):
        value = entry.get(field_name)
        if not isinstance(value, str) or not value:
            problems.append(f"{ctx}: {field_name!r} must be a non-empty string")

    if not isinstance(entry.get("enabled"), bool):
        problems.append(f"{ctx}: 'enabled' must be true or false (it is required)")

    for field_name in ("description", "alert_interval"):
        value = entry.get(field_name)
        if value is not None and not isinstance(value, str):
            problems.append(f"{ctx}: {field_name!r} must be a string, got {value!r}")

    unknown = sorted(k for k in entry if k not in _KNOWN_FIELDS)
    if unknown:
        hint = " (policies here are identified by name, not ref)" if "ref" in unknown else ""
        problems.append(f"{ctx}: unknown field(s) {unknown}{hint}")

    problems.extend(_validate_mechanisms(entry.get("mechanisms"), ctx))

    filters = entry.get("filters")
    if filters is not None:
        if not isinstance(filters, dict):
            problems.append(f"{ctx}: 'filters' must be a mapping, got {type(filters).__name__}")
        else:
            for key, values in sorted(filters.items()):
                if not isinstance(values, list):
                    problems.append(
                        f"{ctx}: filters.{key} must be a list, got {type(values).__name__}"
                    )
                    continue
                for v in values:
                    if not isinstance(v, str | int) or isinstance(v, bool) or v == "":
                        problems.append(f"{ctx}: filters.{key} entries must be strings, got {v!r}")

    return problems


def _validate_mechanisms(mechanisms: object, ctx: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(mechanisms, dict):
        problems.append(f"{ctx}: 'mechanisms' must be a mapping (it is required)")
        return problems

    unknown = sorted(k for k in mechanisms if k not in _MECHANISM_KEYS)
    if unknown:
        problems.append(
            f"{ctx}: unknown mechanisms key(s) {unknown} (valid: {sorted(_MECHANISM_KEYS)})"
        )

    any_entries = False
    for key in _MECHANISM_KEYS:
        entries = mechanisms.get(key)
        if entries is None:
            continue
        if not isinstance(entries, list):
            problems.append(f"{ctx}: mechanisms.{key} must be a list, got {type(entries).__name__}")
            continue
        for entry in entries:
            if not isinstance(entry, str) or not entry:
                problems.append(
                    f"{ctx}: mechanisms.{key} entries must be non-empty strings, got {entry!r}"
                )
            else:
                any_entries = True

    if not problems and not any_entries:
        problems.append(f"{ctx}: mechanisms must name at least one destination")
    return problems


def _validate_alerting(desired, zone_name, errors, lines):
    """Validate alerting_policies entries offline."""
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
        for problem in validate_alerting_policy(entry, i):
            errors.append(f"  {zone_name}/{SECTION}: {problem}")
        name = entry.get("name")
        if isinstance(name, str) and name:
            if name in seen:
                errors.append(
                    f"  {zone_name}/{SECTION}: duplicate name {name!r} -- names are identity keys"
                )
            seen.add(name)


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class AlertingFormatter:
    """Formatter for notification policy plans."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules.formatter import Pen, format_change

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            lines.append(p.header(f"  {PLAN_KEY}: {plan.name}"))
            if plan.create:
                lines.append(p.success("  + create policy"))
            if plan.delete:
                lines.append(p.error("  - delete policy"))
            for change in plan.changes:
                lines.extend(format_change(change, use_color))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        from octorules.formatter import change_to_dict

        result = []
        for plan in plans:
            entry: dict = {
                "name": plan.name,
                "create": plan.create,
                "delete": plan.delete,
            }
            if plan.policy_id:
                entry["policy_id"] = plan.policy_id
            changes = [change_to_dict(c) for c in plan.changes]
            if changes:
                entry["changes"] = changes
            result.append(entry)
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import md_change_row, md_escape

        lines: list[str] = []
        for plan in plans:
            label = f"{PLAN_KEY}:{plan.name}"
            if plan.create:
                lines.append(f"| + | {md_escape(label)} | | create policy |")
            if plan.delete:
                lines.append(f"| - | {md_escape(label)} | | delete policy |")
            for c in plan.changes:
                lines.append(md_change_row(c, label, pending_diffs, has_reorder=False))
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import (
            HTML_TABLE_HEADER,
            html_render_changes,
            html_summary_row,
        )

        total_creates = total_removes = total_modifies = 0

        for plan in plans:
            lines.append(f"<h3>{PLAN_KEY}: {html_escape(plan.name)}</h3>")
            lines.extend(HTML_TABLE_HEADER)

            creates = removes = modifies = 0
            if plan.create:
                creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                lines.append("    <td>create policy</td>")
                lines.append("  </tr>")
            if plan.delete:
                removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete policy</td>")
                lines.append("  </tr>")

            c_creates, c_removes, c_modifies, _ = html_render_changes(plan.changes, lines)
            creates += c_creates
            removes += c_removes
            modifies += c_modifies
            lines.extend(html_summary_row(creates, removes, modifies, 0))
            lines.append("</table>")

            total_creates += creates
            total_removes += removes
            total_modifies += modifies

        return total_creates, total_removes, total_modifies, 0


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class AlertingExtension(ProviderExtension):
    """Account-scoped notification policies.

    ``section`` and ``name`` differ: the rules-file key is
    ``alerting_policies`` while plans bucket under ``alerting``.
    """

    section = SECTION
    name = PLAN_KEY
    zone_level = False
    account_level = True

    def prefetch(self, desired, scope, provider):
        return _prefetch_alerting(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_alerting(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_alerting(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_alerting(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_alerting() -> None:
    """Register all alerting hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension(PLAN_KEY, AlertingFormatter())
    register_validate_extension(_validate_alerting)
