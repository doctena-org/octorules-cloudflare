"""Tests for CloudflareProvider Page Shield policy methods."""

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
        """get_all_page_shield_policies strips API fields."""
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
        assert "id" not in result[0]
        assert "last_updated" not in result[0]
        assert result[0] == {
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }

    def test_get_all_page_shield_policies_empty(self, mock_cf_client):
        """get_all_page_shield_policies returns empty list when no policies."""
        mock_cf_client.page_shield.policies.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.get_all_page_shield_policies(scope)
        assert result == []

    # --- Error wrapping tests ---

    def test_list_page_shield_policies_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on list_page_shield_policies is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.page_shield.policies.list.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.list_page_shield_policies(_zs())

    def test_list_page_shield_policies_api_error_wraps(self, mock_cf_client):
        """APIError on list_page_shield_policies is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.page_shield.policies.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.list_page_shield_policies(_zs())

    def test_create_page_shield_policy_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on create_page_shield_policy is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.page_shield.policies.create.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.create_page_shield_policy(
                _zs(),
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            )

    def test_create_page_shield_policy_api_error_wraps(self, mock_cf_client):
        """APIError on create_page_shield_policy is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.page_shield.policies.create.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.create_page_shield_policy(
                _zs(),
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            )

    def test_update_page_shield_policy_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on update_page_shield_policy is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.page_shield.policies.update.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.update_page_shield_policy(
                _zs(),
                "pol-1",
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            )

    def test_update_page_shield_policy_api_error_wraps(self, mock_cf_client):
        """APIError on update_page_shield_policy is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.page_shield.policies.update.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.update_page_shield_policy(
                _zs(),
                "pol-1",
                description="test",
                action="allow",
                expression="true",
                enabled=True,
                value="script-src 'self'",
            )

    def test_delete_page_shield_policy_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on delete_page_shield_policy is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.page_shield.policies.delete.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.delete_page_shield_policy(_zs(), "pol-1")

    def test_delete_page_shield_policy_api_error_wraps(self, mock_cf_client):
        """APIError on delete_page_shield_policy is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.page_shield.policies.delete.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.delete_page_shield_policy(_zs(), "pol-1")

    def test_get_all_page_shield_policies_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on get_all_page_shield_policies is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.page_shield.policies.list.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.get_all_page_shield_policies(_zs())

    def test_get_all_page_shield_policies_api_error_wraps(self, mock_cf_client):
        """APIError on get_all_page_shield_policies is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.page_shield.policies.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.get_all_page_shield_policies(_zs())

    def test_list_page_shield_policies_permission_denied_wraps(self, mock_cf_client):
        """PermissionDeniedError on list_page_shield_policies is wrapped as ProviderAuthError."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.page_shield.policies.list.side_effect = PermissionDeniedError(
            message="Forbidden", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Forbidden"):
            provider.list_page_shield_policies(_zs())

    def test_list_page_shield_policies_connection_error_wraps(self, mock_cf_client):
        """APIConnectionError on list_page_shield_policies is wrapped as ProviderError."""
        from cloudflare import APIConnectionError

        mock_cf_client.page_shield.policies.list.side_effect = APIConnectionError(
            request=MagicMock()
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError):
            provider.list_page_shield_policies(_zs())
