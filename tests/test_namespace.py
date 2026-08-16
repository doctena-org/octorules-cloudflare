"""Test Cloudflare namespace registration and zone format normalization."""

# Import octorules_cloudflare to trigger namespace registration
from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES

import octorules_cloudflare  # noqa: F401


class TestCloudflareNamespace:
    """Test Cloudflare namespace registration."""

    def test_namespace_registered(self) -> None:
        """Cloudflare namespace exists in PROVIDER_NAMESPACES."""
        assert "cloudflare" in PROVIDER_NAMESPACES

    def test_namespace_mapping(self) -> None:
        """Cloudflare namespace mapping contains expected keys."""
        ns = PROVIDER_NAMESPACES["cloudflare"]
        assert isinstance(ns, dict)
        assert len(ns) == 32  # 23 phases + 3 non-phase + 6 settings

        # Expected mapping (nested key -> canonical flat key)
        expected = {
            # Phases (bare identity mapping)
            "redirect_rules": "cloudflare.redirect_rules",
            "url_rewrite_rules": "cloudflare.url_rewrite_rules",
            "request_header_rules": "cloudflare.request_header_rules",
            "response_header_rules": "cloudflare.response_header_rules",
            "config_rules": "cloudflare.config_rules",
            "origin_rules": "cloudflare.origin_rules",
            "cache_rules": "cloudflare.cache_rules",
            "compression_rules": "cloudflare.compression_rules",
            "custom_error_rules": "cloudflare.custom_error_rules",
            "waf_custom_rules": "cloudflare.waf_custom_rules",
            "waf_managed_rules": "cloudflare.waf_managed_rules",
            "rate_limiting_rules": "cloudflare.rate_limiting_rules",
            "bot_fight_rules": "cloudflare.bot_fight_rules",
            "sensitive_data_detection": "cloudflare.sensitive_data_detection",
            "http_ddos_rules": "cloudflare.http_ddos_rules",
            "bulk_redirect_rules": "cloudflare.bulk_redirect_rules",
            "log_custom_fields": "cloudflare.log_custom_fields",
            "network_ddos_rules": "cloudflare.network_ddos_rules",
            "network_firewall_rules": "cloudflare.network_firewall_rules",
            "network_firewall_managed": "cloudflare.network_firewall_managed",
            "network_firewall_ratelimit": "cloudflare.network_firewall_ratelimit",
            "network_firewall_ids": "cloudflare.network_firewall_ids",
            "url_normalization": "cloudflare.url_normalization",
            # Non-phase sections
            "custom_rulesets": "cloudflare.custom_rulesets",
            "lists": "cloudflare.lists",
            "page_shield_policies": "cloudflare.page_shield_policies",
            # Settings (drop cloudflare_ prefix)
            "bot_management": "cloudflare.bot_management",
            "zone_security": "cloudflare.zone_security",
            "zone_tls": "cloudflare.zone_tls",
            "leaked_credential_check": "cloudflare.leaked_credential_check",
            "content_scanning": "cloudflare.content_scanning",
            # Exception: url_normalization_settings (because url_normalization is a phase)
            "url_normalization_settings": "cloudflare.url_normalization_settings",
        }

        assert ns == expected, f"Mismatch in namespace mapping:\nExpected: {expected}\nGot: {ns}"

    def test_normalize_zone_format_nested(self) -> None:
        """Nested zone format normalizes to flat keys."""
        nested = {
            "cloudflare": {
                "waf_custom_rules": [
                    {
                        "ref": "test-rule",
                        "expression": "true",
                        "action": "block",
                    }
                ],
                "bot_management": {"fight_mode": True},
                "url_normalization_settings": {"scope": "incoming", "type": "cloudflare"},
            }
        }

        normalized = normalize_zone_format(nested)

        # Should flatten to canonical keys
        assert "cloudflare.waf_custom_rules" in normalized
        assert normalized["cloudflare.waf_custom_rules"][0]["ref"] == "test-rule"
        assert "cloudflare.bot_management" in normalized
        assert normalized["cloudflare.bot_management"]["fight_mode"] is True
        assert "cloudflare.url_normalization_settings" in normalized
        assert normalized["cloudflare.url_normalization_settings"]["scope"] == "incoming"

    def test_normalize_zone_format_nested_with_lists(self) -> None:
        """Nested zone format with lists and custom_rulesets."""
        nested = {
            "cloudflare": {
                "lists": [
                    {
                        "name": "test_list",
                        "kind": "ip",
                        "items": ["10.0.0.0/8"],
                    }
                ],
                "page_shield_policies": [
                    {
                        "description": "Test CSP",
                        "action": "allow",
                        "expression": "true",
                        "enabled": True,
                        "value": "script-src 'self'",
                    }
                ],
            }
        }

        normalized = normalize_zone_format(nested)

        # Flat keys should be present
        assert "lists" in normalized
        assert normalized["lists"][0]["name"] == "test_list"
        assert "cloudflare.page_shield_policies" in normalized
        assert normalized["cloudflare.page_shield_policies"][0]["description"] == "Test CSP"
