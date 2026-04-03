"""Cloudflare SDK wrapper for phase rulesets.

Public API:
    CloudflareProvider
"""

import json as _json
import logging
import random
import threading
import time

import cloudflare
import httpx
from cloudflare import DefaultHttpxClient
from octorules.config import ConfigError
from octorules.phases import (
    ACCOUNT_PROVIDER_IDS,
    ALL_PROVIDER_IDS,
    ZONE_PROVIDER_IDS,
    strip_api_fields,
)
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderError,
)
from octorules.provider.utils import fetch_parallel, make_error_wrapper
from octorules.retry import retry_with_backoff

from octorules_cloudflare.exceptions import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
)

_wrap_provider_errors = make_error_wrapper(
    auth_errors=(AuthenticationError, PermissionDeniedError),
    generic_errors=(APIError, APIConnectionError),
)


def _zone_phase_set() -> set[str]:
    return set(ZONE_PROVIDER_IDS)


def _account_phase_set() -> set[str]:
    return set(ACCOUNT_PROVIDER_IDS)


log = logging.getLogger(__name__)

_KNOWN_PLANS = {"free", "pro", "business", "enterprise"}
_LIST_ITEMS_PER_PAGE = 500
_LIST_PAGE_BACKOFF = (1.0, 2.0, 3.0, 5.0)
_BULK_POLL_BACKOFF = (1.0, 2.0, 3.0, 5.0)


def _normalize_plan_name(raw: str) -> str:
    """Normalize a Cloudflare API plan name to an octorules tier.

    The API returns names like "Free Website", "Pro Website",
    "Business Website", "Enterprise Website" or just "Free", etc.
    """
    lower = raw.lower()
    for plan in _KNOWN_PLANS:
        if plan in lower:
            return plan
    log.warning("Unknown Cloudflare plan name %r, using %r as tier", raw, lower)
    return lower


def _fmt_scope(scope: Scope) -> str:
    """Format scope for log messages."""
    if scope.label:
        kw = scope.api_kwargs
        key = next(iter(kw))
        return f"{scope.label} ({key}={kw[key]})"
    kw = scope.api_kwargs
    key = next(iter(kw))
    return f"{key}={kw[key]}"


class CloudflareProvider:
    """Wraps the Cloudflare Python SDK for ruleset phase operations."""

    SUPPORTS = frozenset({"custom_rulesets", "lists", "page_shield", "zone_discovery"})

    def __init__(
        self,
        *,
        token: str = "",
        max_retries: int = 2,
        timeout: float | None = 30.0,
        max_workers: int = 1,
        client: cloudflare.Cloudflare | None = None,
        **_extra: object,
    ) -> None:
        if not token and client is None:
            raise ConfigError("Cloudflare provider requires a 'token'")
        if client is not None:
            self._client = client
        else:
            kwargs: dict = {"api_token": token, "max_retries": max_retries}
            if timeout is not None:
                kwargs["timeout"] = timeout
            # Scale connection pool to match concurrency
            if max_workers > 1:
                pool_size = max_workers * len(ALL_PROVIDER_IDS)
                kwargs["http_client"] = DefaultHttpxClient(
                    limits=httpx.Limits(
                        max_connections=max(100, pool_size),
                        max_keepalive_connections=max(20, max_workers * 4),
                    ),
                )
            self._client = cloudflare.Cloudflare(**kwargs)
        self._max_workers = max_workers
        self._lock = threading.Lock()
        self._account_id: str | None = None
        self._account_name: str | None = None
        self._zone_plans: dict[str, str] = {}

    @property
    def max_workers(self) -> int:
        """Maximum concurrent workers for parallel operations."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        """Cloudflare account ID, populated after the first resolve_zone_id call."""
        return self._account_id

    @property
    def account_name(self) -> str | None:
        """Cloudflare account name, populated after the first resolve_zone_id call."""
        return self._account_name

    @property
    def zone_plans(self) -> dict[str, str]:
        """Zone name -> normalized plan tier, populated during resolve_zone_id."""
        return self._zone_plans

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a zone name to its Cloudflare zone ID.

        Raises ConfigError if zero or more than one zone matches.
        Also stashes account info from the first successful resolution.

        Called concurrently from ThreadPoolExecutor. Shared state writes
        are protected by ``_lock``.
        """
        result = self._client.zones.list(name=zone_name)
        matches = [z for z in result if z.name == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No zone found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple zones found for {zone_name!r}")
        zone = matches[0]
        with self._lock:
            if getattr(zone, "account", None) and not self._account_id:
                self._account_id = zone.account.id
                self._account_name = zone.account.name
            if getattr(zone, "plan", None) and getattr(zone.plan, "name", None):
                self._zone_plans[zone_name] = _normalize_plan_name(zone.plan.name)
        return zone.id

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all zone names accessible with the current API token."""
        zones = self._client.zones.list()
        return [z.name for z in zones]

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Fetch rules for a single phase. Returns empty list if no ruleset exists."""
        log.debug("GET rulesets/phases/%s %s", provider_id, _fmt_scope(scope))
        try:
            ruleset = self._client.rulesets.phases.get(
                provider_id,
                **scope.api_kwargs,
            )
            rules = ruleset.rules or []
            return [_to_dict(r) for r in rules]
        except NotFoundError:
            return []
        except BadRequestError:
            # Cloudflare returns 400 for phases the zone/account doesn't
            # support (e.g. SBFM without the entitlement).  Treat the same
            # as "no ruleset" so callers aren't surprised.
            log.debug(
                "Skipping phase %s for %s (not supported on this plan)",
                provider_id,
                _fmt_scope(scope),
            )
            return []
        except PermissionDeniedError:
            # Token lacks permission for this specific phase (e.g. ddos_l7,
            # http_log_custom_fields).  Skip rather than aborting the entire
            # operation -- the caller can still process other phases.
            log.debug(
                "Skipping phase %s for %s (token lacks permission)",
                provider_id,
                _fmt_scope(scope),
            )
            return []

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Atomically replace all rules in a phase.

        Returns the number of rules in the response (for verification).
        """
        sl = _fmt_scope(scope)
        log.debug("PUT rulesets/phases/%s %s rules=%d", provider_id, sl, len(rules))
        result = self._client.rulesets.phases.update(
            provider_id,
            **scope.api_kwargs,
            rules=rules,
        )
        response_rules = result.rules or []
        response_count = len(response_rules)
        if response_count != len(rules):
            log.warning(
                "PUT %s %s: sent %d rule(s) but response contains %d",
                provider_id,
                sl,
                len(rules),
                response_count,
            )
        return response_count

    @_wrap_provider_errors
    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for supported phases in parallel. Returns provider_id -> rules mapping.

        AuthenticationError and PermissionDeniedError propagate immediately
        (permanent errors). Transient errors (rate limit, server error,
        connection) are logged and the phase is recorded in ``result.failed_phases``.

        For account scopes, automatically restricts to account-compatible phases.

        Args:
            scope: The Scope (zone or account) to fetch rules for.
            provider_ids: Optional list of provider phase identifiers to fetch.
                          Defaults to all supported phases.
        """
        phases_to_fetch = provider_ids if provider_ids is not None else ALL_PROVIDER_IDS
        if scope.is_account:
            account_set = _account_phase_set()
            phases_to_fetch = [p for p in phases_to_fetch if p in account_set]
        else:
            zone_set = _zone_phase_set()
            phases_to_fetch = [p for p in phases_to_fetch if p in zone_set]
        sl = _fmt_scope(scope)
        log.debug("Fetching %d phase(s) for %s", len(phases_to_fetch), sl)

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        def _result_fn(phase: str, rules: list[dict]) -> tuple[str, list[dict]] | None:
            return (phase, rules) if rules else None

        rules, failed = fetch_parallel(
            phases_to_fetch,
            submit_fn=lambda ex, p: ex.submit(self.get_phase_rules, scope, p),
            key_fn=lambda p: p,
            result_fn=_result_fn,
            label="phase",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return PhaseRulesResult(rules, failed_phases=failed)

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """List custom rulesets (kind == 'custom') for a scope.

        Returns list of {id, name, phase, description} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST rulesets (custom) %s", sl)
        result = self._client.rulesets.list(**scope.api_kwargs)
        custom = []
        for rs in result:
            rs_dict = _to_dict(rs)
            if rs_dict.get("kind") != "custom":
                continue
            custom.append(
                {
                    "id": rs_dict["id"],
                    "name": rs_dict.get("name", ""),
                    "phase": rs_dict.get("phase", ""),
                    "description": rs_dict.get("description", ""),
                }
            )
        return custom

    @_wrap_provider_errors
    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        """Fetch rules inside a single custom ruleset. Returns list of rule dicts."""
        sl = _fmt_scope(scope)
        log.debug("GET rulesets/%s %s", ruleset_id, sl)
        ruleset = self._client.rulesets.get(ruleset_id, **scope.api_kwargs)
        rules = ruleset.rules or []
        return [_to_dict(r) for r in rules]

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Replace all rules in a custom ruleset. Returns rule count from response."""
        sl = _fmt_scope(scope)
        log.debug("PUT rulesets/%s %s rules=%d", ruleset_id, sl, len(rules))
        result = self._client.rulesets.update(ruleset_id, **scope.api_kwargs, rules=rules)
        response_rules = result.rules or []
        response_count = len(response_rules)
        if response_count != len(rules):
            log.warning(
                "PUT ruleset %s %s: sent %d rule(s) but response contains %d",
                ruleset_id,
                sl,
                len(rules),
                response_count,
            )
        return response_count

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        """Create a custom ruleset. Cloudflare ignores capacity (no limit)."""
        sl = _fmt_scope(scope)
        log.debug("CREATE ruleset %s %s phase=%s", name, sl, phase)
        result = self._client.rulesets.create(
            **scope.api_kwargs, name=name, kind="custom", phase=phase, rules=[]
        )
        return {"id": result.id, "name": result.name}

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        """Delete a custom ruleset."""
        sl = _fmt_scope(scope)
        log.debug("DELETE ruleset %s %s", ruleset_id, sl)
        self._client.rulesets.delete(ruleset_id, **scope.api_kwargs)

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all custom rulesets in parallel.

        Returns {ruleset_id: {"name": ..., "phase": ..., "rules": [...]}}.
        If ruleset_ids is None, discovers via list_custom_rulesets.
        """
        if ruleset_ids is None:
            rulesets_meta = self.list_custom_rulesets(scope)
        else:
            rulesets_meta = [{"id": rid, "name": "", "phase": ""} for rid in ruleset_ids]

        if not rulesets_meta:
            return {}

        sl = _fmt_scope(scope)
        log.debug("Fetching %d custom ruleset(s) for %s", len(rulesets_meta), sl)

        def _result_fn(rs: dict, rules: list[dict]) -> tuple[str, dict]:
            return (
                rs["id"],
                {"name": rs.get("name", ""), "phase": rs.get("phase", ""), "rules": rules},
            )

        results, _ = fetch_parallel(
            rulesets_meta,
            submit_fn=lambda ex, rs: ex.submit(self.get_custom_ruleset, scope, rs["id"]),
            key_fn=lambda rs: rs["id"],
            result_fn=_result_fn,
            label="custom ruleset",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return results

    # --- Lists API ---

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        """List all account-level lists.

        Returns list of {id, name, kind, description} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST rules/lists %s", sl)
        result = self._client.rules.lists.list(**scope.api_kwargs)
        lists = []
        for item in result:
            d = _to_dict(item)
            lists.append(
                {
                    "id": d.get("id", ""),
                    "name": d.get("name", ""),
                    "kind": d.get("kind", ""),
                    "description": d.get("description", ""),
                }
            )
        return lists

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Create a new list. Returns created list metadata dict."""
        sl = _fmt_scope(scope)
        log.debug("CREATE rules/lists %s name=%s kind=%s", sl, name, kind)
        result = self._client.rules.lists.create(
            **scope.api_kwargs, kind=kind, name=name, description=description
        )
        return _to_dict(result)

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Delete a list by ID."""
        sl = _fmt_scope(scope)
        log.debug("DELETE rules/lists/%s %s", list_id, sl)
        self._client.rules.lists.delete(list_id, **scope.api_kwargs)

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Update list metadata (description)."""
        sl = _fmt_scope(scope)
        log.debug("UPDATE rules/lists/%s %s description=%r", list_id, sl, description)
        self._client.rules.lists.update(list_id, **scope.api_kwargs, description=description)

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str, *, _page_retries: int = 2) -> list[dict]:
        """Fetch all items in a list, handling cursor-based pagination.

        Strips list_item API fields from each item.
        Uses raw responses to extract pagination cursors, since the SDK
        returns a plain list without cursor metadata.

        Each page is retried up to *_page_retries* times on transient errors
        (``APIError``, ``APIConnectionError``, ``JSONDecodeError``) via
        :func:`retry_with_backoff`.  ``AuthenticationError`` and
        ``PermissionDeniedError`` propagate immediately (not in the
        retryable set).
        """
        sl = _fmt_scope(scope)
        log.debug("GET rules/lists/%s/items %s", list_id, sl)
        # Auth errors (AuthenticationError, PermissionDeniedError) are
        # subclasses of APIError, so we re-raise them as ProviderAuthError
        # inside the operation to bypass retry_with_backoff's catch.
        _auth_errors = (AuthenticationError, PermissionDeniedError)
        _retryable = (APIError, APIConnectionError, _json.JSONDecodeError)
        all_items: list[dict] = []
        cursor: str | None = None
        while True:
            kwargs: dict = {**scope.api_kwargs, "per_page": _LIST_ITEMS_PER_PAGE}
            if cursor:
                kwargs["cursor"] = cursor

            def _fetch_page(kw: dict = kwargs) -> dict:
                try:
                    raw = self._client.rules.lists.items.with_raw_response.list(list_id, **kw)
                except _auth_errors as exc:
                    raise ProviderAuthError(str(exc)) from exc
                return _json.loads(raw.http_response.text)

            try:
                body = retry_with_backoff(
                    _fetch_page,
                    retryable=_retryable,
                    max_attempts=_page_retries + 1,
                    backoff=_LIST_PAGE_BACKOFF,
                    jitter=0.5,
                    label=f"list {list_id} page fetch ({sl})",
                )
            except _json.JSONDecodeError as exc:
                raise ProviderError(
                    f"Invalid JSON in list items response for {list_id}: {exc}"
                ) from exc
            for item in body.get("result", []):
                all_items.append(strip_api_fields(item, "list_item"))
            # Extract next cursor from result_info
            cursor = None
            result_info = body.get("result_info")
            if isinstance(result_info, dict):
                cursors = result_info.get("cursors")
                if isinstance(cursors, dict):
                    cursor = cursors.get("after") or None
            if not cursor:
                break
        return all_items

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Replace all items in a list (async). Returns operation_id.

        Unlike ``put_phase_rules``, no count-check is performed here because
        this is an async bulk operation -- the actual items are applied
        server-side and validated during ``poll_bulk_operation``.
        """
        sl = _fmt_scope(scope)
        log.debug("PUT rules/lists/%s/items %s items=%d", list_id, sl, len(items))
        result = self._client.rules.lists.items.update(list_id, **scope.api_kwargs, body=items)
        d = _to_dict(result)
        return d.get("operation_id", "")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """Poll a bulk operation until completion.

        Uses graduated backoff with jitter: 1s -> 2s -> 3s -> 5s (capped),
        plus up to 0.5s random jitter per interval.
        Returns "completed". Raises APIError on "failed", ProviderError on timeout.
        """
        sl = _fmt_scope(scope)
        log.debug("POLL bulk_operations/%s %s", operation_id, sl)
        start = time.monotonic()
        poll_count = 0
        while True:
            result = self._client.rules.lists.bulk_operations.get(operation_id, **scope.api_kwargs)
            d = _to_dict(result)
            status = d.get("status", "")
            if status == "completed":
                return "completed"
            if status == "failed":
                error = d.get("error", "unknown error")
                raise APIError(
                    f"Bulk operation {operation_id} failed: {error}",
                    request=None,
                    body=None,
                )
            elapsed = time.monotonic() - start
            log.debug(
                "Bulk operation %s status=%r elapsed=%.1fs poll=%d %s",
                operation_id,
                status,
                elapsed,
                poll_count,
                sl,
            )
            if elapsed >= timeout:
                raise ProviderError(
                    f"Bulk operation {operation_id} timed out after {timeout}s (status={status})"
                )
            interval = _BULK_POLL_BACKOFF[min(poll_count, len(_BULK_POLL_BACKOFF) - 1)]
            interval += random.uniform(0, 0.5)
            time.sleep(interval)
            poll_count += 1

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all lists and their items in parallel.

        Returns {list_name: {"id": ..., "kind": ..., "description": ..., "items": [...]}}.
        If list_names is provided, filters to those names only.
        """
        all_meta = self.list_lists(scope)
        if list_names is not None:
            name_set = set(list_names)
            all_meta = [m for m in all_meta if m["name"] in name_set]

        if not all_meta:
            return {}

        sl = _fmt_scope(scope)
        log.debug("Fetching items for %d list(s) for %s", len(all_meta), sl)

        def _result_fn(meta: dict, items: list[dict]) -> tuple[str, dict]:
            return (
                meta["name"],
                {
                    "id": meta["id"],
                    "kind": meta["kind"],
                    "description": meta["description"],
                    "items": items,
                },
            )

        results, _ = fetch_parallel(
            all_meta,
            submit_fn=lambda ex, m: ex.submit(self.get_list_items, scope, m["id"]),
            key_fn=lambda m: m["name"],
            result_fn=_result_fn,
            label="list",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return results

    # --- Page Shield Policies API ---

    @_wrap_provider_errors
    def list_page_shield_policies(self, scope: Scope) -> list[dict]:
        """List all Page Shield policies for a zone.

        Returns list of {id, description, action, expression, enabled, value} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST page_shield/policies %s", sl)
        result = self._client.page_shield.policies.list(zone_id=scope.zone_id)
        policies = []
        for item in result:
            d = _to_dict(item)
            policies.append(
                {
                    "id": d.get("id", ""),
                    "description": d.get("description", ""),
                    "action": d.get("action", ""),
                    "expression": d.get("expression", ""),
                    "enabled": d.get("enabled", False),
                    "value": d.get("value", ""),
                }
            )
        return policies

    @_wrap_provider_errors
    def create_page_shield_policy(
        self,
        scope: Scope,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict:
        """Create a new Page Shield policy. Returns created policy dict."""
        sl = _fmt_scope(scope)
        log.debug("CREATE page_shield/policies %s description=%r", sl, description)
        result = self._client.page_shield.policies.create(
            zone_id=scope.zone_id,
            description=description,
            action=action,
            expression=expression,
            enabled=enabled,
            value=value,
        )
        return _to_dict(result)

    @_wrap_provider_errors
    def update_page_shield_policy(
        self,
        scope: Scope,
        policy_id: str,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict:
        """Update an existing Page Shield policy. Returns updated policy dict."""
        sl = _fmt_scope(scope)
        log.debug("UPDATE page_shield/policies/%s %s", policy_id, sl)
        result = self._client.page_shield.policies.update(
            policy_id,
            zone_id=scope.zone_id,
            description=description,
            action=action,
            expression=expression,
            enabled=enabled,
            value=value,
        )
        return _to_dict(result)

    @_wrap_provider_errors
    def delete_page_shield_policy(self, scope: Scope, policy_id: str) -> None:
        """Delete a Page Shield policy by ID."""
        sl = _fmt_scope(scope)
        log.debug("DELETE page_shield/policies/%s %s", policy_id, sl)
        self._client.page_shield.policies.delete(policy_id, zone_id=scope.zone_id)

    @_wrap_provider_errors
    def get_all_page_shield_policies(self, scope: Scope) -> list[dict]:
        """Fetch all Page Shield policies, stripping API-only fields.

        Returns list of {description, action, expression, enabled, value} dicts.
        """
        policies = self.list_page_shield_policies(scope)
        return [strip_api_fields(p, "page_shield_policy") for p in policies]


def _to_dict(obj: object) -> dict:
    """Convert a Cloudflare SDK object to a plain dict.

    The SDK returns Pydantic-like model objects.  This handles all
    variants: ``model_dump``, ``to_dict``, and ``dict()`` fallback.

    Raises ``ProviderError`` if none of the methods succeed.
    """
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    try:
        return dict(obj)
    except (TypeError, ValueError) as e:
        raise ProviderError(f"Cannot convert {type(obj).__name__} to dict: {e}") from e


__all__ = [
    "CloudflareProvider",
]
