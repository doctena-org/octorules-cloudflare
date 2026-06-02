"""Tests for CloudflareProvider Page Shield policy methods."""

import typing
from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider

from .mocks import MockRule


def _zs(zone_id: str = "zone-123") -> Scope:
    return Scope(zone_id=zone_id)


class TestPageShieldPolicies:
    """Tests for CloudflareProvider Page Shield policy methods."""

    def test_list_page_shield_policies(self, mock_cf_client):
        """list_page_shield_policies returns filtered dicts."""
        mock_cf_client.page_shield.policies.list.return_value = [
            MockRule(
                {
                    "id": "pol-1",
                    "description": "CSP on all",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                    "last_updated": "2024-01-01T00:00:00Z",
                }
            ),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.list_page_shield_policies(scope)
        assert len(result) == 1
        assert result[0] == {
            "id": "pol-1",
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }
        mock_cf_client.page_shield.policies.list.assert_called_once_with(zone_id="zone-123")

    def test_list_page_shield_policies_empty(self, mock_cf_client):
        """list_page_shield_policies returns empty list when no policies."""
        mock_cf_client.page_shield.policies.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.list_page_shield_policies(scope)
        assert result == []

    def test_create_page_shield_policy(self, mock_cf_client):
        """create_page_shield_policy calls SDK and returns dict."""
        mock_cf_client.page_shield.policies.create.return_value = MockRule(
            {
                "id": "pol-new",
                "description": "New CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.create_page_shield_policy(
            scope,
            description="New CSP",
            action="allow",
            expression="true",
            enabled=True,
            value="script-src 'self'",
        )
        assert result["id"] == "pol-new"
        assert result["description"] == "New CSP"
        mock_cf_client.page_shield.policies.create.assert_called_once_with(
            zone_id="zone-123",
            description="New CSP",
            action="allow",
            expression="true",
            enabled=True,
            value="script-src 'self'",
        )

    def test_update_page_shield_policy(self, mock_cf_client):
        """update_page_shield_policy calls SDK with policy_id."""
        mock_cf_client.page_shield.policies.update.return_value = MockRule(
            {
                "id": "pol-1",
                "description": "Updated CSP",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self' https:",
            }
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.update_page_shield_policy(
            scope,
            "pol-1",
            description="Updated CSP",
            action="log",
            expression="true",
            enabled=True,
            value="script-src 'self' https:",
        )
        assert result["id"] == "pol-1"
        assert result["action"] == "log"
        mock_cf_client.page_shield.policies.update.assert_called_once_with(
            "pol-1",
            zone_id="zone-123",
            description="Updated CSP",
            action="log",
            expression="true",
            enabled=True,
            value="script-src 'self' https:",
        )

    def test_delete_page_shield_policy(self, mock_cf_client):
        """delete_page_shield_policy calls SDK with correct args."""
        mock_cf_client.page_shield.policies.delete.return_value = None
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        provider.delete_page_shield_policy(scope, "pol-1")
        mock_cf_client.page_shield.policies.delete.assert_called_once_with(
            "pol-1", zone_id="zone-123"
        )

    def test_get_all_page_shield_policies(self, mock_cf_client):
        """get_all_page_shield_policies preserves ``id`` (the planner needs it
        to target updates/deletes) and strips noise fields like last_updated."""
        mock_cf_client.page_shield.policies.list.return_value = [
            MockRule(
                {
                    "id": "pol-1",
                    "description": "CSP on all",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                    "last_updated": "2024-01-01T00:00:00Z",
                }
            ),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.get_all_page_shield_policies(scope)
        assert len(result) == 1
        assert result[0]["id"] == "pol-1"  # preserved — planner targets updates/deletes by id
        assert "last_updated" not in result[0]  # noise still stripped
        assert result[0] == {
            "id": "pol-1",
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }

    def test_existing_policy_update_not_silently_skipped(self, mock_cf_client):
        """Regression: an update to an EXISTING policy must reach the API.

        Previously ``get_all_page_shield_policies`` stripped ``id``, so the
        planner saw ``policy_id=None`` for every existing policy and the apply
        stage silently skipped all updates/deletes (``if not psp.policy_id:
        continue``) — no error, no API call. This drives the full
        fetch -> diff -> apply seam that the other apply tests bypass by
        hand-feeding an id-bearing ``current``.
        """
        from octorules.planner import ZonePlan

        from octorules_cloudflare.page_shield import (
            _apply_page_shield,
            diff_page_shield_policies,
        )

        mock_cf_client.page_shield.policies.list.return_value = [
            MockRule(
                {
                    "id": "pol-1",
                    "description": "CSP",
                    "action": "log",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                    "last_updated": "2024-01-01T00:00:00Z",
                }
            ),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")

        current = provider.get_all_page_shield_policies(scope)
        desired = [
            {
                "description": "CSP",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self' https://new.example",
            }
        ]
        plans = diff_page_shield_policies(desired, current)

        assert len(plans) == 1
        assert plans[0].policy_id == "pol-1"  # was None under the bug
        assert plans[0].changes  # the CSP value change is detected

        apply_provider = MagicMock()
        apply_provider.max_workers = 1
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": plans})
        _synced, error = _apply_page_shield(zp, plans, scope, apply_provider)

        assert error is None
        apply_provider.update_page_shield_policy.assert_called_once()
        assert apply_provider.update_page_shield_policy.call_args[0][1] == "pol-1"

    def test_get_all_page_shield_policies_empty(self, mock_cf_client):
        """get_all_page_shield_policies returns empty list when no policies."""
        mock_cf_client.page_shield.policies.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.get_all_page_shield_policies(scope)
        assert result == []

    # --- Error wrapping tests ---

    # Mapping from method name -> (sdk_path, lambda calling the provider method).
    # Keeps the parametrized test compact while still exercising every
    # public Page Shield method.
    _PS_METHODS: typing.ClassVar[dict] = {
        "list": (
            "page_shield.policies.list",
            lambda p: p.list_page_shield_policies(_zs()),
        ),
        "create": (
            "page_shield.policies.create",
            lambda p: p.create_page_shield_policy(
                _zs(),
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            ),
        ),
        "update": (
            "page_shield.policies.update",
            lambda p: p.update_page_shield_policy(
                _zs(),
                "pol-1",
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            ),
        ),
        "delete": (
            "page_shield.policies.delete",
            lambda p: p.delete_page_shield_policy(_zs(), "pol-1"),
        ),
        "get_all": (
            "page_shield.policies.list",  # get_all uses .list under the hood
            lambda p: p.get_all_page_shield_policies(_zs()),
        ),
    }

    @staticmethod
    def _sdk_attr(client, dotted: str):
        obj = client
        for part in dotted.split("."):
            obj = getattr(obj, part)
        return obj

    @pytest.mark.parametrize(
        "error_factory,expected_exc,match",
        [
            (
                lambda: __import__("cloudflare").AuthenticationError(
                    message="Invalid API token",
                    response=MagicMock(status_code=401),
                    body=None,
                ),
                ProviderAuthError,
                "Invalid API token",
            ),
            (
                lambda: __import__("cloudflare").PermissionDeniedError(
                    message="Forbidden",
                    response=MagicMock(status_code=403),
                    body=None,
                ),
                ProviderAuthError,
                "Forbidden",
            ),
            (
                lambda: __import__("cloudflare").APIError(
                    "Server Error", request=MagicMock(), body=None
                ),
                ProviderError,
                "Server Error",
            ),
            (
                lambda: __import__("cloudflare").APIConnectionError(request=MagicMock()),
                ProviderError,
                "",  # APIConnectionError has no specific message we can match on
            ),
        ],
        ids=["auth", "permission_denied", "api_error", "connection"],
    )
    @pytest.mark.parametrize("method_name", list(_PS_METHODS.keys()))
    def test_error_wrapping(self, mock_cf_client, method_name, error_factory, expected_exc, match):
        """Each Page Shield public method wraps SDK errors into the provider
        exception hierarchy. Verified for every (method × error type) pair.
        """
        sdk_path, invoke = self._PS_METHODS[method_name]
        self._sdk_attr(mock_cf_client, sdk_path).side_effect = error_factory()
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(expected_exc, match=match):
            invoke(provider)
