"""Tests for custom ruleset provider methods."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare.provider import _to_dict

from .mocks import MockRule, MockRuleset, MockRuleWithToDict


class TestRulesetToDict:
    """Tests for _to_dict helper."""

    def test_dict_passthrough(self):
        rs = {"id": "rs1", "kind": "custom", "name": "Test"}
        assert _to_dict(rs) == rs

    def test_model_dump(self):
        rs = MockRule({"id": "rs1", "kind": "custom", "name": "Test", "extra": None})
        result = _to_dict(rs)
        assert result["id"] == "rs1"
        assert "extra" not in result

    def test_to_dict_fallback(self):
        rs = MockRuleWithToDict({"id": "rs1", "kind": "custom"})
        result = _to_dict(rs)
        assert result["id"] == "rs1"


class TestCustomRulesets:
    """Tests for custom ruleset provider methods."""

    def test_list_custom_rulesets(self, mock_cf_client):
        """list_custom_rulesets should filter to kind=custom."""
        mock_cf_client.rulesets.list.return_value = [
            MockRule(
                {
                    "id": "rs1",
                    "kind": "custom",
                    "name": "Block attackers",
                    "phase": "http_request_firewall_custom",
                    "description": "Custom WAF",
                }
            ),
            MockRule(
                {
                    "id": "rs2",
                    "kind": "managed",
                    "name": "CF Managed",
                    "phase": "http_request_firewall_managed",
                }
            ),
            MockRule(
                {
                    "id": "rs3",
                    "kind": "custom",
                    "name": "Rate limits",
                    "phase": "http_ratelimit",
                }
            ),
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_custom_rulesets(scope)
        assert len(result) == 2
        assert result[0]["id"] == "rs1"
        assert result[0]["name"] == "Block attackers"
        assert result[1]["id"] == "rs3"

    def test_list_custom_rulesets_empty(self, mock_cf_client):
        """list_custom_rulesets returns empty when no custom rulesets."""
        mock_cf_client.rulesets.list.return_value = [
            MockRule({"id": "rs1", "kind": "managed", "name": "CF Managed"})
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_custom_rulesets(scope)
        assert result == []

    def test_get_custom_ruleset(self, mock_cf_client):
        """get_custom_ruleset returns rules inside a custom ruleset."""
        mock_cf_client.rulesets.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "block"},
                {"ref": "r2", "expression": "false", "action": "log"},
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        rules = provider.get_custom_ruleset(scope, "rs1")
        assert len(rules) == 2
        assert rules[0]["ref"] == "r1"
        mock_cf_client.rulesets.get.assert_called_once_with("rs1", account_id="acct-123")

    def test_get_custom_ruleset_empty(self, mock_cf_client):
        """get_custom_ruleset returns empty list for empty ruleset."""
        mock_cf_client.rulesets.get.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        rules = provider.get_custom_ruleset(scope, "rs1")
        assert rules == []

    def test_put_custom_ruleset(self, mock_cf_client):
        """put_custom_ruleset sends rules and returns count."""
        rules = [{"ref": "r1", "expression": "true", "action": "block"}]
        mock_cf_client.rulesets.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        count = provider.put_custom_ruleset(scope, "rs1", rules)
        assert count == 1
        mock_cf_client.rulesets.update.assert_called_once_with(
            "rs1", account_id="acct-123", rules=rules
        )

    def test_put_custom_ruleset_count_mismatch_warns(self, mock_cf_client, caplog):
        """Mismatched rule count should log warning."""
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.update.return_value = MockRuleset(rules=[{"ref": "r1"}])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            count = provider.put_custom_ruleset(scope, "rs1", rules)
        assert count == 1
        assert "sent 2 rule(s) but response contains 1" in caplog.text

    def test_get_all_custom_rulesets_discovers(self, mock_cf_client):
        """get_all_custom_rulesets discovers rulesets when ids not given."""
        mock_cf_client.rulesets.list.return_value = [
            MockRule(
                {
                    "id": "rs1",
                    "kind": "custom",
                    "name": "Block",
                    "phase": "http_request_firewall_custom",
                }
            ),
        ]
        mock_cf_client.rulesets.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "block"}]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_custom_rulesets(scope)
        assert "rs1" in result
        assert result["rs1"]["name"] == "Block"
        assert result["rs1"]["phase"] == "http_request_firewall_custom"
        assert len(result["rs1"]["rules"]) == 1

    def test_get_all_custom_rulesets_with_ids(self, mock_cf_client):
        """get_all_custom_rulesets fetches specific IDs when given."""
        mock_cf_client.rulesets.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "block"}]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_custom_rulesets(scope, ruleset_ids=["rs1"])
        assert "rs1" in result
        # Should not call list since IDs were provided
        mock_cf_client.rulesets.list.assert_not_called()

    def test_get_all_custom_rulesets_empty(self, mock_cf_client):
        """get_all_custom_rulesets returns empty when no rulesets found."""
        mock_cf_client.rulesets.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_custom_rulesets(scope)
        assert result == {}

    def test_get_all_custom_rulesets_auth_error_propagates(self, mock_cf_client):
        """AuthenticationError should propagate from get_all_custom_rulesets."""
        from cloudflare import AuthenticationError

        mock_cf_client.rulesets.list.return_value = [
            MockRule({"id": "rs1", "kind": "custom", "name": "X", "phase": "p"})
        ]
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderAuthError):
            provider.get_all_custom_rulesets(scope)

    def test_get_all_custom_rulesets_transient_error_skips(self, mock_cf_client, caplog):
        """Transient API error on one ruleset should skip it and continue."""
        from cloudflare import APIError

        mock_cf_client.rulesets.list.return_value = [
            MockRule({"id": "rs1", "kind": "custom", "name": "A", "phase": "p"}),
            MockRule({"id": "rs2", "kind": "custom", "name": "B", "phase": "p"}),
        ]

        def mock_get(ruleset_id, **kwargs):
            if ruleset_id == "rs1":
                raise APIError("Server Error", request=MagicMock(), body=None)
            return MockRuleset(rules=[{"ref": "r1", "expression": "true", "action": "block"}])

        mock_cf_client.rulesets.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            result = provider.get_all_custom_rulesets(scope)
        assert "rs1" not in result
        assert "rs2" in result
        assert "Failed to fetch custom ruleset rs1" in caplog.text


class TestCreateCustomRuleset:
    """Tests for create_custom_ruleset."""

    def test_create_success(self, mock_cf_client):
        """create_custom_ruleset sends correct SDK args and returns id+name."""
        mock_result = MagicMock()
        mock_result.id = "new-rs-id"
        mock_result.name = "My Custom Ruleset"
        mock_cf_client.rulesets.create.return_value = mock_result

        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.create_custom_ruleset(
            scope, name="My Custom Ruleset", phase="http_request_firewall_custom", capacity=100
        )

        assert result == {"id": "new-rs-id", "name": "My Custom Ruleset"}
        mock_cf_client.rulesets.create.assert_called_once_with(
            account_id="acct-123",
            name="My Custom Ruleset",
            kind="custom",
            phase="http_request_firewall_custom",
            rules=[],
        )

    def test_create_zone_scope(self, mock_cf_client):
        """create_custom_ruleset works with zone scope."""
        mock_result = MagicMock()
        mock_result.id = "zone-rs-id"
        mock_result.name = "Zone Ruleset"
        mock_cf_client.rulesets.create.return_value = mock_result

        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-456")
        result = provider.create_custom_ruleset(
            scope, name="Zone Ruleset", phase="http_request_firewall_custom", capacity=50
        )

        assert result == {"id": "zone-rs-id", "name": "Zone Ruleset"}
        mock_cf_client.rulesets.create.assert_called_once_with(
            zone_id="zone-456",
            name="Zone Ruleset",
            kind="custom",
            phase="http_request_firewall_custom",
            rules=[],
        )

    def test_create_auth_error(self, mock_cf_client):
        """AuthenticationError wraps to ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.create.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderAuthError):
            provider.create_custom_ruleset(
                scope,
                name="Test",
                phase="http_request_firewall_custom",
                capacity=10,
            )

    def test_create_api_error(self, mock_cf_client):
        """Generic APIError wraps to ProviderError."""
        from cloudflare import APIError

        mock_cf_client.rulesets.create.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError):
            provider.create_custom_ruleset(
                scope,
                name="Test",
                phase="http_request_firewall_custom",
                capacity=10,
            )


class TestDeleteCustomRuleset:
    """Tests for delete_custom_ruleset."""

    def test_delete_success(self, mock_cf_client):
        """delete_custom_ruleset calls SDK with correct args."""
        mock_cf_client.rulesets.delete.return_value = None
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.delete_custom_ruleset(scope, "rs-to-delete")

        assert result is None
        mock_cf_client.rulesets.delete.assert_called_once_with(
            "rs-to-delete", account_id="acct-123"
        )

    def test_delete_zone_scope(self, mock_cf_client):
        """delete_custom_ruleset works with zone scope."""
        mock_cf_client.rulesets.delete.return_value = None
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(zone_id="zone-789")
        provider.delete_custom_ruleset(scope, "rs-zone-del")

        mock_cf_client.rulesets.delete.assert_called_once_with("rs-zone-del", zone_id="zone-789")

    def test_delete_auth_error(self, mock_cf_client):
        """AuthenticationError wraps to ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.delete.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderAuthError):
            provider.delete_custom_ruleset(scope, "rs-del")

    def test_delete_api_error(self, mock_cf_client):
        """Generic APIError wraps to ProviderError."""
        from cloudflare import APIError

        mock_cf_client.rulesets.delete.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError):
            provider.delete_custom_ruleset(scope, "rs-del")
