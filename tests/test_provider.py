"""Tests for the Cloudflare provider."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare.provider import _normalize_plan_name, _to_dict

from .mocks import MockRule, MockRuleIterableOnly, MockRuleset, MockRuleWithToDict


# Helper to create a zone scope for tests
def _zs(zone_id: str = "zone-123", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


class TestScope:
    """Tests for the Scope dataclass."""

    def test_zone_api_kwargs(self):
        scope = Scope(zone_id="z123")
        assert scope.api_kwargs == {"zone_id": "z123"}

    def test_account_api_kwargs(self):
        scope = Scope(account_id="a456")
        assert scope.api_kwargs == {"account_id": "a456"}

    def test_account_takes_priority(self):
        scope = Scope(zone_id="z123", account_id="a456")
        assert scope.api_kwargs == {"account_id": "a456"}

    def test_no_id_raises(self):
        scope = Scope()
        with pytest.raises(ValueError, match="either zone_id or account_id"):
            scope.api_kwargs  # noqa: B018

    def test_is_account_true(self):
        scope = Scope(account_id="a456")
        assert scope.is_account is True

    def test_is_account_false(self):
        scope = Scope(zone_id="z123")
        assert scope.is_account is False

    def test_label(self):
        scope = Scope(zone_id="z123", label="example.com")
        assert scope.label == "example.com"


class TestRuleToDict:
    def test_dict_passthrough(self):
        rule = {"ref": "r1", "expression": "true"}
        assert _to_dict(rule) == rule

    def test_model_dump(self):
        rule = MockRule({"ref": "r1", "expression": "true", "version": None})
        result = _to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}

    def test_to_dict_fallback(self):
        rule = MockRuleWithToDict({"ref": "r1", "expression": "true"})
        result = _to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}

    def test_dict_constructor_fallback(self):
        rule = MockRuleIterableOnly({"ref": "r1", "expression": "true"})
        result = _to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}


class TestCloudflareProvider:
    def test_get_phase_rules(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"
        mock_cf_client.rulesets.phases.get.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
        )

    def test_get_phase_rules_account_scope(self, mock_cf_client):
        """Account scope should pass account_id to SDK."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "block"}]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        rules = provider.get_phase_rules(scope, "http_request_firewall_custom")
        assert len(rules) == 1
        mock_cf_client.rulesets.phases.get.assert_called_once_with(
            "http_request_firewall_custom",
            account_id="acct-123",
        )

    def test_get_phase_rules_not_found(self, mock_cf_client):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found",
            response=mock_response,
            body=None,
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_empty_ruleset(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_multiple(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                {"ref": "r2", "expression": "false", "action": "redirect"},
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert rules[0]["ref"] == "r1"
        assert rules[1]["ref"] == "r2"

    def test_get_phase_rules_with_model_objects(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[MockRule({"ref": "r1", "expression": "true", "action": "redirect"})]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"

    def test_put_phase_rules(self, mock_cf_client):
        rules = [{"ref": "r1", "expression": "true", "action": "redirect"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 1
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=rules,
        )

    def test_put_phase_rules_account_scope(self, mock_cf_client):
        """Account scope should pass account_id to SDK."""
        rules = [{"ref": "r1", "expression": "true", "action": "block"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        count = provider.put_phase_rules(scope, "http_request_firewall_custom", rules)
        assert count == 1
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_firewall_custom",
            account_id="acct-123",
            rules=rules,
        )

    def test_put_phase_rules_empty(self, mock_cf_client):
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", [])
        assert count == 0
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=[],
        )

    def test_get_all_phase_rules(self, mock_cf_client):
        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert len(result) == 1

    def test_get_all_phase_rules_multiple(self, mock_cf_client):
        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" in result
        assert len(result) == 2

    def test_get_all_phase_rules_empty(self, mock_cf_client):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert result == {}

    @patch("octorules_cloudflare.provider.cloudflare.Cloudflare")
    def test_max_retries_passed_to_client(self, mock_cf_cls):
        CloudflareProvider(token="token", max_retries=5)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=5, timeout=30.0)

    @patch("octorules_cloudflare.provider.cloudflare.Cloudflare")
    def test_default_max_retries(self, mock_cf_cls):
        CloudflareProvider(token="token")
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2, timeout=30.0)

    @patch("octorules_cloudflare.provider.cloudflare.Cloudflare")
    def test_timeout_passed_to_client(self, mock_cf_cls):
        CloudflareProvider(token="token", timeout=30.0)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2, timeout=30.0)

    @patch("octorules_cloudflare.provider.cloudflare.Cloudflare")
    def test_timeout_none_not_passed(self, mock_cf_cls):
        CloudflareProvider(token="token", timeout=None)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2)

    def test_get_phase_rules_logs_debug(self, mock_cf_client, caplog):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.DEBUG, logger="octorules_cloudflare"):
            provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert "GET rulesets/phases/http_request_dynamic_redirect" in caplog.text
        assert "zone-123" in caplog.text

    def test_get_all_phase_rules_partial_failure(self, mock_cf_client, caplog):
        """Non-404 error on one phase should log warning and continue."""
        from cloudflare import APIError

        call_count = 0

        def mock_get(provider_id, **kwargs):
            nonlocal call_count
            call_count += 1
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                raise APIError("Internal Server Error", request=MagicMock(), body=None)
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            result = provider.get_all_phase_rules(_zs())
        # redirect phase succeeded, cache phase failed, rest were 404
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "Failed to fetch phase" in caplog.text
        assert "http_request_cache_settings" in caplog.text
        # All zone-level phases should have been attempted
        from octorules.phases import ZONE_PROVIDER_IDS

        assert call_count == len(ZONE_PROVIDER_IDS)

    def test_get_all_phase_rules_filtered(self, mock_cf_client):
        """When provider_ids is given, only those phases should be fetched."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs(), provider_ids=["http_request_dynamic_redirect"])
        assert "http_request_dynamic_redirect" in result
        # Should only have been called once (for the single filtered phase)
        mock_cf_client.rulesets.phases.get.assert_called_once()

    def test_get_all_phase_rules_filter_none_fetches_all_zone(self, mock_cf_client):
        """When provider_ids is None with zone scope, all zone-level phases should be fetched."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs(), provider_ids=None)
        from octorules.phases import ZONE_PROVIDER_IDS

        assert mock_cf_client.rulesets.phases.get.call_count == len(ZONE_PROVIDER_IDS)

    def test_put_phase_rules_logs_debug(self, mock_cf_client, caplog):
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.DEBUG, logger="octorules_cloudflare"):
            provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert "PUT rulesets/phases/http_request_dynamic_redirect" in caplog.text
        assert "zone-123" in caplog.text
        assert "rules=2" in caplog.text

    def test_put_phase_rules_count_mismatch_warns(self, mock_cf_client, caplog):
        """PUT response with different rule count should log a warning."""
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(
            rules=[{"ref": "r1"}]  # Only 1 rule in response
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 1
        assert "sent 2 rule(s) but response contains 1" in caplog.text

    def test_put_phase_rules_null_response_rules(self, mock_cf_client, caplog):
        """PUT response with null rules should treat as 0 rules."""
        rules = [{"ref": "r1"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 0
        assert "sent 1 rule(s) but response contains 0" in caplog.text

    def test_get_all_phase_rules_auth_error_propagates(self, mock_cf_client):
        """AuthenticationError should propagate immediately, not be caught."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.phases.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)

        with pytest.raises(ProviderAuthError):
            provider.get_all_phase_rules(_zs())

    def test_get_phase_rules_permission_denied_returns_empty(self, mock_cf_client):
        """PermissionDeniedError on a single phase returns [] (skip, not fatal)."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.rulesets.phases.get.side_effect = PermissionDeniedError(
            message="Missing zone permission", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_phase_rules(_zs(), "ddos_l7")
        assert result == []

    def test_get_all_phase_rules_permission_denied_skips_phase(self, mock_cf_client):
        """PermissionDeniedError on individual phases should be skipped, not fatal."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.rulesets.phases.get.side_effect = PermissionDeniedError(
            message="Missing zone permission", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)

        result = provider.get_all_phase_rules(_zs())
        # Should complete without raising — all phases skipped
        assert len(result) == 0

    def test_get_all_phase_rules_failed_phases_tracked(self, mock_cf_client):
        """Transient errors should be tracked in result.failed_phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                raise APIError("Server Error", request=MagicMock(), body=None)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "http_request_cache_settings" in result.failed_phases

    def test_get_all_phase_rules_no_failed_phases(self, mock_cf_client):
        """When all phases succeed, failed_phases should be empty."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert result.failed_phases == []

    def test_get_all_phase_rules_account_scope_filters_phases(self, mock_cf_client):
        """Account scope should only fetch account-compatible phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        provider.get_all_phase_rules(scope)
        from octorules.phases import ACCOUNT_PROVIDER_IDS

        assert set(call_args) == set(ACCOUNT_PROVIDER_IDS)
        assert len(call_args) == len(ACCOUNT_PROVIDER_IDS)

    def test_get_all_phase_rules_account_scope_with_filter(self, mock_cf_client):
        """Account scope with provider_ids filter should intersect with account phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        # Request both account-level and zone-only phases; zone-only should be filtered out
        provider.get_all_phase_rules(
            scope,
            provider_ids=["http_request_firewall_custom", "http_request_dynamic_redirect"],
        )
        assert call_args == ["http_request_firewall_custom"]

    def test_get_all_phase_rules_zone_scope_filters_to_zone_phases(self, mock_cf_client):
        """Zone scope should only fetch zone-level phases, excluding account-only ones."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        from octorules.phases import ZONE_PROVIDER_IDS

        assert set(call_args) == set(ZONE_PROVIDER_IDS)
        assert len(call_args) == len(ZONE_PROVIDER_IDS)
        # Account-only phases should NOT be fetched for zone scope
        assert "http_request_redirect" not in call_args
        assert "ddos_l4" not in call_args
        assert "magic_transit" not in call_args

    def test_get_all_phase_rules_parallel_results_correct(self, mock_cf_client):
        """Parallel fetching should produce the same results as sequential."""

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" in result
        assert len(result) == 2
        assert result["http_request_dynamic_redirect"][0]["ref"] == "r1"
        assert result["http_request_cache_settings"][0]["ref"] == "c1"

    def test_get_all_phase_rules_account_empty_filter_returns_empty(self, mock_cf_client):
        """Account scope with only zone-level phases in filter should return empty."""
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_phase_rules(scope, provider_ids=["http_request_dynamic_redirect"])
        assert result == {}
        assert result.failed_phases == []
        mock_cf_client.rulesets.phases.get.assert_not_called()

    def test_get_all_phase_rules_zone_scope_excludes_account_only(self, mock_cf_client):
        """Zone scope should exclude account-only phases like bulk_redirect_rules."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        # Request an account-only phase for a zone scope — should be filtered out
        provider.get_all_phase_rules(
            _zs(),
            provider_ids=["http_request_redirect", "http_request_dynamic_redirect"],
        )
        assert call_args == ["http_request_dynamic_redirect"]

    def test_get_all_phase_rules_zone_scope_empty_filter_returns_empty(self, mock_cf_client):
        """Zone scope with only account-only phases in filter should return empty."""
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs(), provider_ids=["http_request_redirect"])
        assert result == {}
        assert result.failed_phases == []
        mock_cf_client.rulesets.phases.get.assert_not_called()

    def test_get_all_phase_rules_zone_includes_waf_phases(self, mock_cf_client):
        """Zone scope should include WAF phases (they work at both zone and account level)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        assert "http_request_firewall_custom" in call_args
        assert "http_request_firewall_managed" in call_args
        assert "http_ratelimit" in call_args
        assert "http_request_sbfm" in call_args
        assert "http_response_firewall_managed" in call_args

    def test_get_all_phase_rules_account_includes_waf_phases(self, mock_cf_client):
        """Account scope should include dual zone+account WAF phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        provider.get_all_phase_rules(scope)
        assert "http_request_firewall_custom" in call_args
        assert "http_request_firewall_managed" in call_args
        assert "http_ratelimit" in call_args
        # Zone-only new phases should NOT be in account scope
        assert "http_request_sbfm" not in call_args
        assert "http_response_firewall_managed" not in call_args

    def test_get_all_phase_rules_zone_scope_with_new_phase_filter(self, mock_cf_client):
        """Zone scope should allow filtering to new phases (sbfm, sensitive data)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.get_all_phase_rules(
            _zs(),
            provider_ids=[
                "http_request_sbfm",
                "http_response_firewall_managed",
            ],
        )
        assert set(call_args) == {
            "http_request_sbfm",
            "http_response_firewall_managed",
        }

    def test_get_all_phase_rules_account_scope_rejects_new_zone_only_phases(self, mock_cf_client):
        """Account scope should filter out new zone-only phases from explicit filter."""
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_phase_rules(
            scope,
            provider_ids=["http_request_sbfm", "http_response_firewall_managed"],
        )
        assert result == {}
        mock_cf_client.rulesets.phases.get.assert_not_called()


class TestCFApiResilience:
    """Tests for provider resilience against Cloudflare SDK/API changes."""

    def test_rules_with_extra_fields_preserved(self, mock_cf_client):
        """New fields returned by CF API are passed through as-is."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "risk_score": 0.75,
                    "deployment_id": "dep-123",
                }
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["risk_score"] == 0.75
        assert rules[0]["deployment_id"] == "dep-123"

    def test_ruleset_with_empty_rules_list(self, mock_cf_client):
        """CF returning empty rules list (not None) should give empty list."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_model_dump_with_extra_fields(self, mock_cf_client):
        """Pydantic model objects with new fields are correctly converted."""
        rule = MockRule(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "new_cf_field": "surprise",
                "risk_score": None,  # None excluded by exclude_none
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["new_cf_field"] == "surprise"
        assert "risk_score" not in rules[0]  # Excluded by exclude_none

    def test_model_dump_with_nested_structures(self, mock_cf_client):
        """Complex nested structures from SDK model objects are preserved."""
        rule = MockRule(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {"target_url": {"value": "https://example.com"}},
                    "status_code": 301,
                    "preserve_query_string": True,
                },
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        ap = rules[0]["action_parameters"]
        assert ap["from_value"]["target_url"]["value"] == "https://example.com"
        assert ap["status_code"] == 301
        assert ap["preserve_query_string"] is True

    def test_to_dict_fallback_preserves_all_fields(self, mock_cf_client):
        """SDK objects using to_dict fallback preserve all fields including new ones."""
        rule = MockRuleWithToDict(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "new_field": "value",
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["new_field"] == "value"

    def test_iterable_fallback_preserves_fields(self, mock_cf_client):
        """SDK objects using dict() fallback preserve all fields."""
        rule = MockRuleIterableOnly(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "unexpected": 42,
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["unexpected"] == 42

    def test_mixed_rule_types_in_single_phase(self, mock_cf_client):
        """CF returning a mix of dicts and model objects in one phase."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                MockRule({"ref": "r2", "expression": "false", "action": "redirect"}),
                MockRuleWithToDict({"ref": "r3", "expression": "x", "action": "redirect"}),
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 3
        assert all(isinstance(r, dict) for r in rules)
        assert [r["ref"] for r in rules] == ["r1", "r2", "r3"]

    def test_rules_without_ref_from_api(self, mock_cf_client):
        """CF can return rules without ref (e.g. managed rules). Provider passes them through."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                {"expression": "managed-rule", "action": "block"},  # No ref
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert "ref" not in rules[1]

    def test_get_all_ignores_phases_not_in_registry(self, mock_cf_client):
        """get_all_phase_rules only fetches phases from the registry (zone-level for zone scope)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(provider_id, **kwargs):
            call_args.append(provider_id)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        # Zone scope should only call zone-level registered phases
        from octorules.phases import ZONE_PROVIDER_IDS

        assert set(call_args) == set(ZONE_PROVIDER_IDS)

    def test_connection_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A network error on one phase should not prevent fetching other phases."""
        from cloudflare import APIConnectionError, NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                raise APIConnectionError(request=MagicMock())
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result

    def test_api_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A 500 error on one phase should not prevent fetching other phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                raise APIError("Server Error", request=MagicMock(), body=None)
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        # Redirect failed, but cache succeeded
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result

    def test_bad_request_on_unsupported_phase_returns_empty(self, mock_cf_client):
        """A 400 'unknown phase' error should return empty list, not propagate."""
        from cloudflare import BadRequestError

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_cf_client.rulesets.phases.get.side_effect = BadRequestError(
            message='unknown phase "http_request_sbfm"',
            response=mock_response,
            body=None,
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_phase_rules(_zs(), "http_request_sbfm")
        assert result == []

    def test_bad_request_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A 400 on one phase should not prevent fetching other phases."""
        from cloudflare import BadRequestError, NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_sbfm":
                mock_response = MagicMock()
                mock_response.status_code = 400
                raise BadRequestError(
                    message='unknown phase "http_request_sbfm"',
                    response=mock_response,
                    body=None,
                )
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_sbfm" not in result
        assert "http_request_cache_settings" in result
        assert "http_request_sbfm" not in result.failed_phases


class TestListZones:
    """Tests for CloudflareProvider.list_zones."""

    def test_list_zones_returns_names(self, mock_cf_client):
        """list_zones returns list of zone names."""
        zone1 = MagicMock()
        zone1.name = "example.com"
        zone2 = MagicMock()
        zone2.name = "other.com"
        mock_cf_client.zones.list.return_value = [zone1, zone2]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.list_zones()
        assert result == ["example.com", "other.com"]
        mock_cf_client.zones.list.assert_called_once()

    def test_list_zones_empty(self, mock_cf_client):
        """list_zones returns empty list when no zones accessible."""
        mock_cf_client.zones.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.list_zones()
        assert result == []

    def test_list_zones_auth_error_wraps(self, mock_cf_client):
        """AuthenticationError on list_zones is wrapped as ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.zones.list.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API token"):
            provider.list_zones()

    def test_list_zones_api_error_wraps(self, mock_cf_client):
        """APIError on list_zones is wrapped as ProviderError."""
        from cloudflare import APIError

        mock_cf_client.zones.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Server Error"):
            provider.list_zones()

    def test_list_zones_permission_denied_wraps(self, mock_cf_client):
        """PermissionDeniedError on list_zones is wrapped as ProviderAuthError."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.zones.list.side_effect = PermissionDeniedError(
            message="Forbidden", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Forbidden"):
            provider.list_zones()

    def test_list_zones_connection_error_wraps(self, mock_cf_client):
        """APIConnectionError on list_zones is wrapped as ProviderError."""
        from cloudflare import APIConnectionError

        mock_cf_client.zones.list.side_effect = APIConnectionError(request=MagicMock())
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError):
            provider.list_zones()


class TestResolveZoneId:
    """Tests for CloudflareProvider.resolve_zone_id."""

    def test_single_match(self, mock_cf_client):
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.resolve_zone_id("example.com")
        assert result == "aabbccdd" * 4
        mock_cf_client.zones.list.assert_called_once_with(name="example.com")

    def test_not_found(self, mock_cf_client):
        from octorules.config import ConfigError

        mock_cf_client.zones.list.return_value = []
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ConfigError, match="No zone found"):
            provider.resolve_zone_id("missing.com")

    def test_multiple_matches(self, mock_cf_client):
        from octorules.config import ConfigError

        zone1 = MagicMock()
        zone1.name = "example.com"
        zone1.id = "11111111" * 4
        zone2 = MagicMock()
        zone2.name = "example.com"
        zone2.id = "22222222" * 4
        mock_cf_client.zones.list.return_value = [zone1, zone2]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ConfigError, match="Multiple zones found"):
            provider.resolve_zone_id("example.com")

    def test_filters_by_exact_name(self, mock_cf_client):
        """Only exact name matches should be counted."""
        zone1 = MagicMock()
        zone1.name = "sub.example.com"
        zone1.id = "11111111" * 4
        zone2 = MagicMock()
        zone2.name = "example.com"
        zone2.id = "22222222" * 4
        mock_cf_client.zones.list.return_value = [zone1, zone2]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        result = provider.resolve_zone_id("example.com")
        assert result == "22222222" * 4

    def test_api_error_propagates(self, mock_cf_client):
        from cloudflare import APIError

        mock_cf_client.zones.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError):
            provider.resolve_zone_id("example.com")

    def test_stashes_account_info(self, mock_cf_client):
        """resolve_zone_id should stash account info from the zone response."""
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        zone.account.id = "acct-123"
        zone.account.name = "Doctena S.A."
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.account_id == "acct-123"
        assert provider.account_name == "Doctena S.A."

    def test_stashes_account_only_once(self, mock_cf_client):
        """Only the first resolution should stash account info."""
        zone1 = MagicMock()
        zone1.name = "a.com"
        zone1.id = "id-a"
        zone1.account.id = "acct-first"
        zone1.account.name = "First Account"
        zone2 = MagicMock()
        zone2.name = "b.com"
        zone2.id = "id-b"
        zone2.account.id = "acct-second"
        zone2.account.name = "Second Account"
        mock_cf_client.zones.list.side_effect = [[zone1], [zone2]]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("a.com")
        provider.resolve_zone_id("b.com")
        assert provider.account_id == "acct-first"
        assert provider.account_name == "First Account"

    def test_no_account_attribute(self, mock_cf_client):
        """Zone without account attribute should not crash."""
        zone = MagicMock(spec=["name", "id"])
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.account_id is None
        assert provider.account_name is None

    def test_stashes_zone_plan(self, mock_cf_client):
        """resolve_zone_id should stash the normalized plan tier."""
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        zone.plan.name = "Business Website"
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.zone_plans["example.com"] == "business"

    def test_stashes_zone_plan_free(self, mock_cf_client):
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        zone.plan.name = "Free Website"
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.zone_plans["example.com"] == "free"

    def test_stashes_zone_plan_enterprise(self, mock_cf_client):
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        zone.plan.name = "Enterprise"
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.zone_plans["example.com"] == "enterprise"

    def test_zone_plans_empty_initially(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        assert provider.zone_plans == {}

    def test_no_plan_attribute_does_not_crash(self, mock_cf_client):
        """Zone without plan attribute should not crash or populate zone_plans."""
        zone = MagicMock(spec=["name", "id"])
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert "example.com" not in provider.zone_plans


class TestConcurrentResolveZoneId:
    """Tests for concurrent resolve_zone_id shared state consistency."""

    def test_concurrent_resolution_populates_all_zone_plans(self, mock_cf_client):
        """Concurrent resolve_zone_id calls should populate zone_plans for all zones."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        zones = {}
        for name in ["a.com", "b.com", "c.com"]:
            zone = MagicMock()
            zone.name = name
            zone.id = f"id-{name}"
            zone.plan.name = "Enterprise"
            zone.account.id = "acct-1"
            zone.account.name = "Test Account"
            zones[name] = zone

        def mock_list(name):
            return [zones[name]]

        mock_cf_client.zones.list.side_effect = mock_list
        provider = CloudflareProvider(token="token", client=mock_cf_client)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(provider.resolve_zone_id, name): name for name in zones}
            results = {}
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

        # All zone IDs resolved correctly
        assert results == {"a.com": "id-a.com", "b.com": "id-b.com", "c.com": "id-c.com"}
        # All zone plans populated
        assert len(provider.zone_plans) == 3
        for name in zones:
            assert provider.zone_plans[name] == "enterprise"
        # Account info stashed from one of the resolutions
        assert provider.account_id == "acct-1"

    def test_lock_protects_shared_state(self, mock_cf_client):
        """The lock should serialize writes to _account_id and _zone_plans."""
        import threading

        provider = CloudflareProvider(token="token", client=mock_cf_client)
        assert isinstance(provider._lock, type(threading.Lock()))

    def test_high_contention_all_zone_plans_populated(self, mock_cf_client):
        """50 concurrent resolve_zone_id calls should all populate zone_plans."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        zone_names = [f"zone{i}.com" for i in range(50)]
        zones = {}
        for name in zone_names:
            zone = MagicMock()
            zone.name = name
            zone.id = f"id-{name}"
            zone.plan.name = "Enterprise"
            zone.account.id = "acct-1"
            zone.account.name = "Test Account"
            zones[name] = zone

        def mock_list(name):
            return [zones[name]]

        mock_cf_client.zones.list.side_effect = mock_list
        provider = CloudflareProvider(token="token", client=mock_cf_client)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(provider.resolve_zone_id, n): n for n in zone_names}
            results = {}
            for future in as_completed(futures):
                results[futures[future]] = future.result()

        assert len(results) == 50
        assert len(provider.zone_plans) == 50
        for name in zone_names:
            assert provider.zone_plans[name] == "enterprise"
        assert provider.account_id == "acct-1"


class TestNormalizePlanName:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("Free Website", "free"),
            ("Pro Website", "pro"),
            ("Business Website", "business"),
            ("Enterprise Website", "enterprise"),
            ("enterprise", "enterprise"),
            ("Free", "free"),
        ],
    )
    def test_normalize(self, raw, expected):
        assert _normalize_plan_name(raw) == expected

    def test_unknown_plan_name_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare.provider"):
            result = _normalize_plan_name("Unknown Plan XYZ")
        assert result == "unknown plan xyz"
        assert "Unknown Cloudflare plan name" in caplog.text
        assert "'Unknown Plan XYZ'" in caplog.text


class TestScopeApiKwargsCache:
    """Tests for Scope.api_kwargs caching."""

    def test_zone_scope_returns_same_dict(self):
        scope = Scope(zone_id="z1")
        first = scope.api_kwargs
        second = scope.api_kwargs
        assert first is second
        assert first == {"zone_id": "z1"}

    def test_account_scope_returns_same_dict(self):
        scope = Scope(account_id="a1")
        first = scope.api_kwargs
        second = scope.api_kwargs
        assert first is second
        assert first == {"account_id": "a1"}


class TestMaxWorkersInit:
    """Tests for max_workers in CloudflareProvider."""

    def test_default_max_workers_is_1(self, mock_cf_client):
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        assert provider.max_workers == 1

    def test_custom_max_workers(self, mock_cf_client):
        provider = CloudflareProvider(token="token", max_workers=8, client=mock_cf_client)
        assert provider.max_workers == 8

    def test_connection_pool_scaled_when_max_workers_gt_1(self):
        """When max_workers > 1 and no client given, http_client should be configured."""
        with patch("octorules_cloudflare.provider.cloudflare.Cloudflare") as mock_cf_cls:
            CloudflareProvider(token="fake-token", max_workers=4)
            call_kwargs = mock_cf_cls.call_args[1]
            assert "http_client" in call_kwargs

    def test_no_custom_pool_when_max_workers_1(self):
        """When max_workers=1, default pool is used (no http_client override)."""
        with patch("octorules_cloudflare.provider.cloudflare.Cloudflare") as mock_cf_cls:
            CloudflareProvider(token="fake-token", max_workers=1)
            call_kwargs = mock_cf_cls.call_args[1]
            assert "http_client" not in call_kwargs

    def test_phase_fetching_uses_max_workers(self, mock_cf_client):
        """get_all_phase_rules should respect max_workers for thread pool size."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider(token="token", max_workers=4, client=mock_cf_client)
        scope = Scope(zone_id="z1")
        # Fetch just 2 phases — workers should be min(4, 2) = 2
        result = provider.get_all_phase_rules(scope, provider_ids=["p1", "p2"])
        assert isinstance(result, PhaseRulesResult)


class TestProviderErrorScenarios:
    """Additional error scenario tests."""

    def test_put_phase_rules_empty_response_rules(self, mock_cf_client, caplog):
        """put_phase_rules with None response rules logs warning about count mismatch."""
        rules = [{"ref": "r1", "expression": "true", "action": "redirect"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 0
        assert "sent 1 rule(s) but response contains 0" in caplog.text

    def test_get_list_items_retry_exhaustion(self, mock_cf_client):
        """get_list_items should raise after all retries are exhausted."""
        from cloudflare import APIError

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError, match="Server Error"):
            provider.get_list_items(scope, "lst-1", _page_retries=1)
        # Should have been called 2 times (1 initial + 1 retry)
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 2

    def test_poll_bulk_operation_timeout(self, mock_cf_client):
        """poll_bulk_operation should raise ProviderError when status stays 'running'."""
        mock_cf_client.rules.lists.bulk_operations.get.return_value = MockRule(
            {"status": "running"}
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError, match="timed out after 0.01s"):
            provider.poll_bulk_operation(scope, "op-timeout", timeout=0.01)


class TestGetListItemsRetry:
    """Tests for get_list_items retry/backoff behavior."""

    @staticmethod
    def _mock_raw_items_response(items):
        import json

        body = {"result": items, "result_info": {}}
        raw = MagicMock()
        raw.http_response.text = json.dumps(body)
        return raw

    def test_auth_error_no_retry(self, mock_cf_client):
        """AuthenticationError propagates immediately without retrying."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = AuthenticationError(
            message="bad token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError):
            provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 1

    def test_permission_denied_no_retry(self, mock_cf_client):
        """PermissionDeniedError propagates immediately without retrying."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = PermissionDeniedError(
            message="forbidden", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError):
            provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 1

    def test_json_decode_error_retried_then_raises(self, mock_cf_client):
        """JSONDecodeError is retried (may be transient truncation), then raises."""
        raw = MagicMock()
        raw.http_response.text = "not json {"
        mock_cf_client.rules.lists.items.with_raw_response.list.return_value = raw
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError, match="Invalid JSON"):
                provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        # 1 initial + 2 retries = 3 attempts
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 3

    def test_json_decode_error_retried_then_succeeds(self, mock_cf_client):
        """JSONDecodeError on first attempt succeeds on retry."""
        bad_raw = MagicMock()
        bad_raw.http_response.text = "not json {"
        good_raw = self._mock_raw_items_response([{"ip": "1.1.1.1/32"}])
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = [
            bad_raw,
            good_raw,
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with patch("octorules_cloudflare.provider.time.sleep"):
            items = provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert len(items) == 1
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 2

    def test_api_connection_error_retried(self, mock_cf_client):
        """APIConnectionError is retried, then succeeds."""
        from cloudflare import APIConnectionError

        raw_ok = self._mock_raw_items_response([{"ip": "1.1.1.1/32"}])
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = [
            APIConnectionError(request=MagicMock()),
            raw_ok,
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with patch("octorules_cloudflare.provider.time.sleep") as mock_sleep:
            items = provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert len(items) == 1
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 2
        mock_sleep.assert_called_once()

    def test_retry_succeeds_on_second_attempt(self, mock_cf_client):
        """APIError on first attempt, success on second."""
        from cloudflare import APIError

        raw_ok = self._mock_raw_items_response([{"ip": "2.2.2.2/32"}])
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = [
            APIError("Server Error", request=MagicMock(), body=None),
            raw_ok,
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with patch("octorules_cloudflare.provider.time.sleep") as mock_sleep:
            items = provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert items == [{"ip": "2.2.2.2/32"}]
        mock_sleep.assert_called_once()

    @patch("octorules_cloudflare.provider.time.sleep")
    def test_backoff_uses_poll_backoff_schedule(self, mock_sleep, mock_cf_client):
        """Backoff delays use _POLL_BACKOFF schedule: 1s, 2s."""
        from cloudflare import APIError

        err = APIError("fail", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError):
            provider.get_list_items(Scope(account_id="a"), "lst-1", _page_retries=2)
        assert mock_sleep.call_count == 2
        # Uses _POLL_BACKOFF = (1.0, 2.0, 3.0, 5.0) indexed by attempt
        assert mock_sleep.call_args_list[0] == ((1.0,),)
        assert mock_sleep.call_args_list[1] == ((2.0,),)

    def test_default_page_retries_is_two(self, mock_cf_client):
        """Default _page_retries=2 means 3 total attempts."""
        from cloudflare import APIError

        err = APIError("fail", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError):
                provider.get_list_items(Scope(account_id="a"), "lst-1")
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 3


class TestFutureCancellationOnAuthError:
    """Tests that futures are cancelled when auth errors occur during parallel fetching."""

    @staticmethod
    def _make_mock_response(status_code: int = 401) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        return resp

    def test_get_all_phase_rules_cancels_futures_on_auth_error(self, mock_cf_client):
        """get_all_phase_rules should cancel all futures when ProviderAuthError is raised."""
        phases = [
            "http_request_dynamic_redirect",
            "http_request_origin",
            "http_request_firewall_custom",
        ]

        err = ProviderAuthError("Invalid API token")

        # Track which futures are created and whether cancel() is called
        mock_futures = []
        failing_future = MagicMock()
        failing_future.result.side_effect = err

        ok_future_1 = MagicMock()
        ok_future_1.result.return_value = [{"ref": "r1"}]

        ok_future_2 = MagicMock()
        ok_future_2.result.return_value = [{"ref": "r2"}]

        mock_futures = [failing_future, ok_future_1, ok_future_2]

        # Build a mock executor that maps submit calls to our mock futures
        submit_count = iter(range(len(mock_futures)))

        def mock_submit(fn, *args, **kwargs):
            idx = next(submit_count)
            return mock_futures[idx]

        mock_executor = MagicMock()
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)
        mock_executor.submit.side_effect = mock_submit

        with (
            patch("octorules_cloudflare.provider.ThreadPoolExecutor", return_value=mock_executor),
            patch(
                "octorules_cloudflare.provider.as_completed",
                return_value=iter([failing_future, ok_future_1, ok_future_2]),
            ),
        ):
            provider = CloudflareProvider(token="token", client=mock_cf_client)
            with pytest.raises(ProviderAuthError):
                provider.get_all_phase_rules(_zs(), provider_ids=phases)

        # All futures should have had cancel() called
        for f in mock_futures:
            f.cancel.assert_called_once()

    def test_get_all_phase_rules_cancels_futures_on_permission_denied(self, mock_cf_client):
        """get_all_phase_rules should cancel all futures when ProviderAuthError
        propagates from a future (not the per-phase catch in get_phase_rules)."""
        phases = [
            "http_request_dynamic_redirect",
            "http_request_origin",
        ]

        err = ProviderAuthError("Token lacks permission")

        failing_future = MagicMock()
        failing_future.result.side_effect = err

        ok_future = MagicMock()
        ok_future.result.return_value = []

        mock_futures = [failing_future, ok_future]
        submit_count = iter(range(len(mock_futures)))

        def mock_submit(fn, *args, **kwargs):
            return mock_futures[next(submit_count)]

        mock_executor = MagicMock()
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)
        mock_executor.submit.side_effect = mock_submit

        with (
            patch("octorules_cloudflare.provider.ThreadPoolExecutor", return_value=mock_executor),
            patch(
                "octorules_cloudflare.provider.as_completed",
                return_value=iter([failing_future, ok_future]),
            ),
        ):
            provider = CloudflareProvider(token="token", client=mock_cf_client)
            with pytest.raises(ProviderAuthError):
                provider.get_all_phase_rules(_zs(), provider_ids=phases)

        for f in mock_futures:
            f.cancel.assert_called_once()

    def test_get_all_custom_rulesets_cancels_futures_on_auth_error(self, mock_cf_client):
        """get_all_custom_rulesets should cancel all futures when ProviderAuthError is raised."""
        # list_custom_rulesets must return metadata so get_all_custom_rulesets submits futures
        mock_cf_client.rulesets.list.return_value = [
            MockRule({"id": "rs1", "kind": "custom", "name": "A", "phase": "p"}),
            MockRule({"id": "rs2", "kind": "custom", "name": "B", "phase": "p"}),
            MockRule({"id": "rs3", "kind": "custom", "name": "C", "phase": "p"}),
        ]

        err = ProviderAuthError("Invalid API token")

        failing_future = MagicMock()
        failing_future.result.side_effect = err

        ok_future_1 = MagicMock()
        ok_future_1.result.return_value = [{"ref": "r1"}]

        ok_future_2 = MagicMock()
        ok_future_2.result.return_value = [{"ref": "r2"}]

        mock_futures = [failing_future, ok_future_1, ok_future_2]
        submit_count = iter(range(len(mock_futures)))

        def mock_submit(fn, *args, **kwargs):
            return mock_futures[next(submit_count)]

        mock_executor = MagicMock()
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)
        mock_executor.submit.side_effect = mock_submit

        with (
            patch("octorules_cloudflare.provider.ThreadPoolExecutor", return_value=mock_executor),
            patch(
                "octorules_cloudflare.provider.as_completed",
                return_value=iter([failing_future, ok_future_1, ok_future_2]),
            ),
        ):
            provider = CloudflareProvider(token="token", client=mock_cf_client)
            scope = Scope(account_id="acct-123")
            with pytest.raises(ProviderAuthError):
                provider.get_all_custom_rulesets(scope)

        for f in mock_futures:
            f.cancel.assert_called_once()

    def test_get_all_lists_cancels_futures_on_auth_error(self, mock_cf_client):
        """get_all_lists should cancel all futures when ProviderAuthError is raised."""
        # list_lists must return metadata so get_all_lists submits futures
        mock_cf_client.rules.lists.list.return_value = [
            MockRule({"id": "lst-1", "name": "list_a", "kind": "ip", "description": "A"}),
            MockRule({"id": "lst-2", "name": "list_b", "kind": "ip", "description": "B"}),
            MockRule({"id": "lst-3", "name": "list_c", "kind": "ip", "description": "C"}),
        ]

        err = ProviderAuthError("Invalid API token")

        failing_future = MagicMock()
        failing_future.result.side_effect = err

        ok_future_1 = MagicMock()
        ok_future_1.result.return_value = [{"ip": "1.1.1.1/32"}]

        ok_future_2 = MagicMock()
        ok_future_2.result.return_value = [{"ip": "2.2.2.2/32"}]

        mock_futures = [failing_future, ok_future_1, ok_future_2]
        submit_count = iter(range(len(mock_futures)))

        def mock_submit(fn, *args, **kwargs):
            return mock_futures[next(submit_count)]

        mock_executor = MagicMock()
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)
        mock_executor.submit.side_effect = mock_submit

        with (
            patch("octorules_cloudflare.provider.ThreadPoolExecutor", return_value=mock_executor),
            patch(
                "octorules_cloudflare.provider.as_completed",
                return_value=iter([failing_future, ok_future_1, ok_future_2]),
            ),
        ):
            provider = CloudflareProvider(token="token", client=mock_cf_client)
            scope = Scope(account_id="acct-123")
            with pytest.raises(ProviderAuthError):
                provider.get_all_lists(scope)

        for f in mock_futures:
            f.cancel.assert_called_once()


class TestSupports:
    def test_supports_all_features(self):
        assert "custom_rulesets" in CloudflareProvider.SUPPORTS
        assert "lists" in CloudflareProvider.SUPPORTS
        assert "page_shield" in CloudflareProvider.SUPPORTS
        assert "zone_discovery" in CloudflareProvider.SUPPORTS

    def test_provider_supports_helper(self):
        from octorules.provider.base import (
            SUPPORTS_CUSTOM_RULESETS,
            SUPPORTS_LISTS,
            SUPPORTS_PAGE_SHIELD,
            SUPPORTS_ZONE_DISCOVERY,
            provider_supports,
        )

        prov = CloudflareProvider.__new__(CloudflareProvider)
        assert provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert provider_supports(prov, SUPPORTS_LISTS)
        assert provider_supports(prov, SUPPORTS_PAGE_SHIELD)
        assert provider_supports(prov, SUPPORTS_ZONE_DISCOVERY)


class TestMalformedProviderResponse:
    """Stability tests: provider handles API responses with missing fields."""

    def test_get_phase_rules_missing_id_in_response(self, mock_cf_client):
        """Provider handles rules with missing 'id' field in API response."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"expression": "true", "action": "block"},  # No id, no ref
                {"id": "rule-2", "ref": "r2", "expression": "false", "action": "skip"},
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_firewall_custom")
        # Should not crash (no KeyError) — returns both rules as dicts
        assert len(rules) == 2
        assert "id" not in rules[0]
        assert "ref" not in rules[0]
        assert rules[0]["expression"] == "true"
        assert rules[1]["id"] == "rule-2"

    def test_get_phase_rules_completely_empty_rule_dict(self, mock_cf_client):
        """Provider handles a rule that converts to an empty dict."""
        # An empty dict is a valid dict, so _to_dict passes it through
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {},  # Completely empty rule
                {"ref": "r1", "expression": "true", "action": "block"},
            ]
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_firewall_custom")
        assert len(rules) == 2
        assert rules[0] == {}
        assert rules[1]["ref"] == "r1"

    def test_get_all_lists_missing_name_in_response(self, mock_cf_client):
        """Provider handles list entries with missing 'name' field gracefully."""
        import json

        # Mock list_lists to return entries where _to_dict gives
        # dicts with missing fields — list_lists uses .get() so it fills
        # defaults, but the upstream SDK object might be strange.
        # Simulate: one list with a name, one without.
        list_with_name = MagicMock()
        list_with_name.model_dump.return_value = {
            "id": "lst-1",
            "name": "my_list",
            "kind": "ip",
            "description": "A list",
        }
        list_without_name = MagicMock()
        list_without_name.model_dump.return_value = {
            "id": "lst-2",
            "kind": "hostname",
            # "name" is missing entirely
        }
        mock_cf_client.rules.lists.list.return_value = [list_with_name, list_without_name]

        # Mock get_list_items for both lists
        def _mock_raw(list_id, **kwargs):
            body = {"result": [{"ip": "1.2.3.4"}], "result_info": {}}
            raw = MagicMock()
            raw.http_response.text = json.dumps(body)
            return raw

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = _mock_raw

        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_lists(scope)
        # Should not crash — the list without a name gets name=""
        assert "my_list" in result
        assert "" in result  # The nameless list uses empty string as key
        assert result["my_list"]["id"] == "lst-1"
        assert result[""]["id"] == "lst-2"

    def test_list_lists_unconvertible_raises(self, mock_cf_client):
        """list_lists raises ProviderError for unconvertible SDK objects."""

        class Unconvertible:
            pass

        mock_cf_client.rules.lists.list.return_value = [Unconvertible()]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError, match="Cannot convert Unconvertible"):
            provider.list_lists(scope)

    def test_get_phase_rules_model_dump_returns_none_values(self, mock_cf_client):
        """Rules where model_dump returns None values are handled (exclude_none)."""
        rule = MockRule(
            {
                "id": None,
                "ref": None,
                "expression": "true",
                "action": "block",
                "description": None,
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_firewall_custom")
        assert len(rules) == 1
        # model_dump(exclude_none=True) strips None values
        assert "id" not in rules[0]
        assert "ref" not in rules[0]
        assert rules[0]["expression"] == "true"


class TestFetchParallelConcurrency:
    """Tests for _fetch_parallel with actual ThreadPoolExecutor concurrency (max_workers > 1)."""

    def test_partial_failure_some_succeed_some_fail(self):
        """Some items succeed, some raise ProviderError -- verify results + failed keys."""
        from octorules_cloudflare.provider import _fetch_parallel

        def submit_fn(executor, item):
            def work(name):
                if name == "bad":
                    raise ProviderError(f"Transient error for {name}")
                return f"result-{name}"

            return executor.submit(work, item)

        results, failed = _fetch_parallel(
            ["good1", "bad", "good2"],
            submit_fn=submit_fn,
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test-item",
            scope_label="test-scope",
            max_workers=3,
        )
        assert results == {"good1": "result-good1", "good2": "result-good2"}
        assert failed == ["bad"]

    def test_timeout_error_lands_in_failed(self):
        """concurrent.futures.TimeoutError should land the key in the failed list."""
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        from octorules_cloudflare.provider import _fetch_parallel

        def submit_fn(executor, item):
            def work(name):
                if name == "slow":
                    raise FuturesTimeoutError("timed out")
                return f"result-{name}"

            return executor.submit(work, item)

        results, failed = _fetch_parallel(
            ["fast", "slow", "also-fast"],
            submit_fn=submit_fn,
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test-item",
            scope_label="test-scope",
            max_workers=3,
        )
        assert results == {"fast": "result-fast", "also-fast": "result-also-fast"}
        assert "slow" in failed

    def test_builtins_timeout_error_lands_in_failed_with_warning(self, caplog):
        """builtins.TimeoutError is a parent of FuturesTimeoutError on 3.11+.

        Since ``concurrent.futures.TimeoutError`` is a subclass of the builtin
        ``TimeoutError``, raising ``builtins.TimeoutError`` inside a worker is
        caught by the ``except FuturesTimeoutError`` clause.  Verify it lands
        in *failed* and generates the "Timed out" warning.
        """
        from octorules_cloudflare.provider import _fetch_parallel

        def submit_fn(executor, item):
            def work(name):
                if name == "slow":
                    raise TimeoutError("socket timed out")  # builtins.TimeoutError
                return f"result-{name}"

            return executor.submit(work, item)

        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            results, failed = _fetch_parallel(
                ["fast", "slow"],
                submit_fn=submit_fn,
                key_fn=lambda item: item,
                result_fn=lambda item, value: (item, value),
                label="test-item",
                scope_label="test-scope",
                max_workers=2,
            )
        assert results == {"fast": "result-fast"}
        assert "slow" in failed
        assert "Timed out" in caplog.text
        assert "slow" in caplog.text

    def test_timeout_error_generates_warning_log(self, caplog):
        """FuturesTimeoutError generates a WARNING log with key name and 'Timed out'."""
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        from octorules_cloudflare.provider import _fetch_parallel

        def submit_fn(executor, item):
            def work(name):
                if name == "slow":
                    raise FuturesTimeoutError("timed out")
                return f"result-{name}"

            return executor.submit(work, item)

        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            results, failed = _fetch_parallel(
                ["fast", "slow", "also-fast"],
                submit_fn=submit_fn,
                key_fn=lambda item: item,
                result_fn=lambda item, value: (item, value),
                label="test-item",
                scope_label="test-scope",
                max_workers=3,
            )
        assert results == {"fast": "result-fast", "also-fast": "result-also-fast"}
        assert "slow" in failed
        assert "Timed out" in caplog.text
        assert "slow" in caplog.text
        assert "test-scope" in caplog.text

    def test_all_succeed_with_max_workers_gt_1(self):
        """All items succeed under actual concurrency -- verify correct results."""
        from octorules_cloudflare.provider import _fetch_parallel

        items = [f"item-{i}" for i in range(10)]

        def submit_fn(executor, item):
            return executor.submit(lambda x: x.upper(), item)

        results, failed = _fetch_parallel(
            items,
            submit_fn=submit_fn,
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test-item",
            scope_label="test-scope",
            max_workers=4,
        )
        assert len(results) == 10
        for item in items:
            assert results[item] == item.upper()
        assert failed == []

    def test_auth_error_propagates_and_cancels_remaining(self):
        """ProviderAuthError from one item propagates and cancels remaining futures."""
        import threading
        import time

        from octorules_cloudflare.provider import _fetch_parallel

        barrier = threading.Barrier(3, timeout=5)

        def submit_fn(executor, item):
            def work(name):
                if name == "auth-fail":
                    barrier.wait()
                    raise ProviderAuthError("Invalid token")
                else:
                    barrier.wait()
                    time.sleep(0.5)
                    return f"result-{name}"

            return executor.submit(work, item)

        with pytest.raises(ProviderAuthError, match="Invalid token"):
            _fetch_parallel(
                ["auth-fail", "slow", "other"],
                submit_fn=submit_fn,
                key_fn=lambda item: item,
                result_fn=lambda item, value: (item, value),
                label="test-item",
                scope_label="test-scope",
                max_workers=3,
            )

    def test_mixed_success_and_failure_with_concurrency(self):
        """Mixed results with max_workers=2 -- verify correct results under concurrency."""
        import threading

        from octorules_cloudflare.provider import _fetch_parallel

        call_threads: dict = {}
        lock = threading.Lock()

        def submit_fn(executor, item):
            def work(name):
                with lock:
                    call_threads[name] = threading.current_thread().ident
                if name.startswith("fail-"):
                    raise ProviderError(f"Failed: {name}")
                return f"ok-{name}"

            return executor.submit(work, item)

        items = ["a", "fail-b", "c", "fail-d", "e"]
        results, failed = _fetch_parallel(
            items,
            submit_fn=submit_fn,
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test-item",
            scope_label="test-scope",
            max_workers=2,
        )
        assert results == {"a": "ok-a", "c": "ok-c", "e": "ok-e"}
        assert sorted(failed) == ["fail-b", "fail-d"]
        # Verify all items were actually executed
        assert set(call_threads.keys()) == set(items)

    def test_result_fn_returning_none_skips_entry(self):
        """result_fn returning None should skip adding to results dict."""
        from octorules_cloudflare.provider import _fetch_parallel

        def submit_fn(executor, item):
            return executor.submit(lambda x: x, item)

        def result_fn(item, value):
            if item == "skip-me":
                return None
            return (item, value)

        results, failed = _fetch_parallel(
            ["keep", "skip-me", "also-keep"],
            submit_fn=submit_fn,
            key_fn=lambda item: item,
            result_fn=result_fn,
            label="test-item",
            scope_label="test-scope",
            max_workers=3,
        )
        assert results == {"keep": "keep", "also-keep": "also-keep"}
        assert "skip-me" not in results
        assert failed == []

    def test_single_item_with_high_max_workers(self):
        """Single item with high max_workers should still work correctly."""
        from octorules_cloudflare.provider import _fetch_parallel

        results, failed = _fetch_parallel(
            ["only-one"],
            submit_fn=lambda ex, item: ex.submit(lambda x: f"done-{x}", item),
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test-item",
            scope_label="test-scope",
            max_workers=8,
        )
        assert results == {"only-one": "done-only-one"}
        assert failed == []

    def test_workers_capped_to_item_count(self):
        """max_workers should be capped to len(items) -- no more threads than items."""
        from unittest.mock import patch as _patch

        from octorules_cloudflare.provider import _fetch_parallel

        with _patch("octorules_cloudflare.provider.ThreadPoolExecutor") as mock_tpe:
            mock_executor = MagicMock()
            mock_executor.__enter__ = MagicMock(return_value=mock_executor)
            mock_executor.__exit__ = MagicMock(return_value=False)
            mock_tpe.return_value = mock_executor

            future = MagicMock()
            future.result.return_value = "val"
            mock_executor.submit.return_value = future

            with _patch("octorules_cloudflare.provider.as_completed", return_value=iter([future])):
                _fetch_parallel(
                    ["only-one"],
                    submit_fn=lambda ex, item: ex.submit(lambda: "val"),
                    key_fn=lambda item: item,
                    result_fn=lambda item, value: (item, value),
                    label="test",
                    scope_label="scope",
                    max_workers=10,
                )
            # min(10, 1) = 1
            mock_tpe.assert_called_once_with(max_workers=1)

    def test_provider_get_all_phase_rules_with_max_workers_gt_1(self, mock_cf_client):
        """Integration: get_all_phase_rules with max_workers=4 produces correct results."""
        from cloudflare import NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", max_workers=4, client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" in result
        assert result["http_request_dynamic_redirect"][0]["ref"] == "r1"
        assert result["http_request_cache_settings"][0]["ref"] == "c1"
        assert result.failed_phases == []

    def test_provider_get_all_phase_rules_partial_failure_max_workers_gt_1(
        self, mock_cf_client, caplog
    ):
        """Integration: partial failure with max_workers=4 tracks failed phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(provider_id, **kwargs):
            if provider_id == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if provider_id == "http_request_cache_settings":
                raise APIError("Server Error", request=MagicMock(), body=None)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider(token="token", max_workers=4, client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules_cloudflare"):
            result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "http_request_cache_settings" in result.failed_phases
        assert "Failed to fetch phase" in caplog.text

    def test_provider_get_all_phase_rules_auth_error_max_workers_gt_1(self, mock_cf_client):
        """Integration: auth error with max_workers=4 propagates immediately."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.phases.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", max_workers=4, client=mock_cf_client)
        with pytest.raises(ProviderAuthError):
            provider.get_all_phase_rules(_zs())


class TestErrorMapping:
    """Tests for _wrap_provider_errors: CF SDK exception -> octorules exception mapping."""

    def test_authentication_error_maps_to_provider_auth_error(self, mock_cf_client):
        """cloudflare.AuthenticationError maps to ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.phases.get.side_effect = AuthenticationError(
            message="Invalid API Token", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Invalid API Token"):
            provider.get_phase_rules(_zs(), "http_request_firewall_custom")

    def test_permission_denied_maps_to_provider_auth_error_on_list_zones(self, mock_cf_client):
        """cloudflare.PermissionDeniedError maps to ProviderAuthError on list_zones."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.zones.list.side_effect = PermissionDeniedError(
            message="Insufficient permissions", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError, match="Insufficient permissions"):
            provider.list_zones()

    def test_api_error_maps_to_provider_error(self, mock_cf_client):
        """cloudflare.APIError maps to ProviderError."""
        from cloudflare import APIError

        mock_cf_client.rulesets.phases.update.side_effect = APIError(
            "Rate limit exceeded", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Rate limit exceeded"):
            provider.put_phase_rules(_zs(), "http_request_firewall_custom", [])

    def test_api_connection_error_maps_to_provider_error(self, mock_cf_client):
        """cloudflare.APIConnectionError maps to ProviderError."""
        from cloudflare import APIConnectionError

        mock_cf_client.zones.list.side_effect = APIConnectionError(request=MagicMock())
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError):
            provider.list_zones()

    def test_error_message_preserved_auth(self, mock_cf_client):
        """Error message from AuthenticationError is preserved in ProviderAuthError."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.zones.list.side_effect = AuthenticationError(
            message="Token expired at 2026-03-24", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError) as exc_info:
            provider.list_zones()
        assert "Token expired at 2026-03-24" in str(exc_info.value)

    def test_error_message_preserved_api_error(self, mock_cf_client):
        """Error message from APIError is preserved in ProviderError."""
        from cloudflare import APIError

        mock_cf_client.zones.list.side_effect = APIError(
            "Internal Server Error (code: 10000)", request=MagicMock(), body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError) as exc_info:
            provider.resolve_zone_id("example.com")
        assert "Internal Server Error (code: 10000)" in str(exc_info.value)

    def test_error_message_preserved_permission_denied(self, mock_cf_client):
        """Error message from PermissionDeniedError is preserved in ProviderAuthError."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.zones.list.side_effect = PermissionDeniedError(
            message="Zone read permission required", response=mock_response, body=None
        )
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError) as exc_info:
            provider.list_zones()
        assert "Zone read permission required" in str(exc_info.value)

    def test_error_message_preserved_connection_error(self, mock_cf_client):
        """Error message from APIConnectionError is preserved in ProviderError."""
        from cloudflare import APIConnectionError

        mock_cf_client.zones.list.side_effect = APIConnectionError(request=MagicMock())
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError) as exc_info:
            provider.list_zones()
        # APIConnectionError message should be in the wrapped error
        assert str(exc_info.value)  # Not empty

    def test_original_exception_chained(self, mock_cf_client):
        """Wrapped ProviderError should chain the original CF exception as __cause__."""
        from cloudflare import APIError

        original = APIError("Original CF error", request=MagicMock(), body=None)
        mock_cf_client.zones.list.side_effect = original
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError) as exc_info:
            provider.list_zones()
        assert exc_info.value.__cause__ is original

    def test_original_auth_exception_chained(self, mock_cf_client):
        """Wrapped ProviderAuthError should chain the original CF exception as __cause__."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        original = AuthenticationError(message="Bad token", response=mock_response, body=None)
        mock_cf_client.zones.list.side_effect = original
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderAuthError) as exc_info:
            provider.list_zones()
        assert exc_info.value.__cause__ is original

    def test_already_wrapped_provider_error_not_double_wrapped(self, mock_cf_client):
        """ProviderError raised inside a wrapped method should not be double-wrapped."""
        # get_list_items raises ProviderError on invalid JSON. The @_wrap_provider_errors
        # should re-raise it as-is, not wrap it again.
        raw = MagicMock()
        raw.http_response.text = "not-json"
        mock_cf_client.rules.lists.items.with_raw_response.list.return_value = raw
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        with pytest.raises(ProviderError, match="Invalid JSON"):
            provider.get_list_items(Scope(account_id="a"), "lst-1")

    def test_all_cf_exceptions_on_resolve_zone_id(self, mock_cf_client):
        """All four CF exception types should be correctly mapped on resolve_zone_id."""
        from cloudflare import (
            APIConnectionError,
            APIError,
            AuthenticationError,
            PermissionDeniedError,
        )

        provider = CloudflareProvider(token="token", client=mock_cf_client)

        # AuthenticationError -> ProviderAuthError
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.zones.list.side_effect = AuthenticationError(
            message="auth fail", response=mock_response, body=None
        )
        with pytest.raises(ProviderAuthError, match="auth fail"):
            provider.resolve_zone_id("a.com")

        # PermissionDeniedError -> ProviderAuthError
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.zones.list.side_effect = PermissionDeniedError(
            message="perm fail", response=mock_response, body=None
        )
        with pytest.raises(ProviderAuthError, match="perm fail"):
            provider.resolve_zone_id("b.com")

        # APIError -> ProviderError
        mock_cf_client.zones.list.side_effect = APIError("api fail", request=MagicMock(), body=None)
        with pytest.raises(ProviderError, match="api fail"):
            provider.resolve_zone_id("c.com")

        # APIConnectionError -> ProviderError
        mock_cf_client.zones.list.side_effect = APIConnectionError(request=MagicMock())
        with pytest.raises(ProviderError):
            provider.resolve_zone_id("d.com")


class TestGetListItemsRetryExhaustion:
    """Tests for get_list_items retry exhaustion -- all retries fail."""

    @staticmethod
    def _mock_raw_items_response(items):
        import json

        body = {"result": items, "result_info": {}}
        raw = MagicMock()
        raw.http_response.text = json.dumps(body)
        return raw

    def test_all_retries_fail_api_error(self, mock_cf_client):
        """All retries fail with APIError -- should raise ProviderError after exhaustion."""
        from cloudflare import APIError

        err = APIError("Server Error", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError, match="Server Error"):
                provider.get_list_items(scope, "lst-1", _page_retries=2)
        # 1 initial + 2 retries = 3 total
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 3

    def test_all_retries_fail_connection_error(self, mock_cf_client):
        """All retries fail with APIConnectionError -- should raise ProviderError."""
        from cloudflare import APIConnectionError

        err = APIConnectionError(request=MagicMock())
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError):
                provider.get_list_items(scope, "lst-1", _page_retries=3)
        # 1 initial + 3 retries = 4 total
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 4

    def test_retry_exhaustion_on_second_page(self, mock_cf_client):
        """Retry exhaustion on page 2 should raise ProviderError."""
        from cloudflare import APIError

        page1 = self._mock_raw_items_response([{"ip": "1.1.1.1/32"}])
        # Add cursor to page1 so pagination continues
        import json

        body = json.loads(page1.http_response.text)
        body["result_info"]["cursors"] = {"after": "page2-cursor"}
        page1.http_response.text = json.dumps(body)

        err = APIError("Page 2 Server Error", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = [
            page1,  # Page 1 succeeds
            err,  # Page 2 attempt 1 fails
            err,  # Page 2 attempt 2 (retry) fails
        ]
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError, match="Page 2 Server Error"):
                provider.get_list_items(scope, "lst-1", _page_retries=1)
        # 1 for page 1 success + 2 for page 2 (initial + 1 retry)
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 3

    def test_retry_exhaustion_preserves_original_error(self, mock_cf_client):
        """After retry exhaustion, the raised error should be the original CF exception."""
        from cloudflare import APIError

        original_err = APIError("Specific CF Error 42", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = original_err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with patch("octorules_cloudflare.provider.time.sleep"):
            with pytest.raises(ProviderError) as exc_info:
                provider.get_list_items(scope, "lst-1", _page_retries=1)
        # The wrapper re-raises the CF exception, which is then caught by
        # @_wrap_provider_errors and wrapped as ProviderError. The __cause__
        # should be the original CF exception.
        assert exc_info.value.__cause__ is original_err

    def test_zero_retries_fails_immediately(self, mock_cf_client):
        """_page_retries=0 means no retries -- fail on first attempt."""
        from cloudflare import APIError

        err = APIError("Immediate fail", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(ProviderError, match="Immediate fail"):
            provider.get_list_items(scope, "lst-1", _page_retries=0)
        # Only 1 attempt, no retries
        assert mock_cf_client.rules.lists.items.with_raw_response.list.call_count == 1

    def test_retry_logs_warnings(self, mock_cf_client, caplog):
        """Each retry attempt should log a warning message."""
        from cloudflare import APIError

        err = APIError("Transient error", request=MagicMock(), body=None)
        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = err
        provider = CloudflareProvider(token="token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with (
            caplog.at_level(logging.WARNING, logger="octorules_cloudflare"),
            patch("octorules_cloudflare.provider.time.sleep"),
        ):
            with pytest.raises(ProviderError):
                provider.get_list_items(scope, "lst-1", _page_retries=2)
        # Should have 2 retry warnings (attempts 1 and 2 of retries, not the last)
        retry_warnings = [r for r in caplog.records if "Retrying page fetch" in r.message]
        assert len(retry_warnings) == 2
        assert "attempt 1/3" in retry_warnings[0].message
        assert "attempt 2/3" in retry_warnings[1].message
