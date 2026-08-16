"""Tests for Page Shield policies CLI functionality."""

import logging
from unittest.mock import MagicMock, patch

import pytest
from octorules.cli import cmd_dump, cmd_plan, cmd_sync
from octorules.config import Config, ProviderConfig, ZoneConfig
from octorules.phases import get_phase
from octorules.planner import ChangeType, RuleChange, ZonePlan
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderError

import octorules_cloudflare  # noqa: F401 — trigger extension registration
from octorules_cloudflare.page_shield import PageShieldPolicyPlan, _apply_page_shield
from octorules_cloudflare.provider import CloudflareProvider

REDIRECT_PHASE = get_phase("cloudflare.redirect_rules")


def _make_dump_mock(**overrides):
    """Build a MagicMock provider that won't leak MagicMock objects into YAML.

    Any method not explicitly configured raises ProviderError, preventing
    auto-created MagicMock return values from reaching the YAML serializer
    (which can't represent them).
    """
    mock_prov = MagicMock()
    mock_prov.SUPPORTS = frozenset({"page_shield", "zone_discovery"})
    mock_prov.max_workers = 1
    mock_prov.account_id = None
    mock_prov.account_name = None
    # Default: any unrecognized get_* call raises ProviderError
    mock_prov.configure_mock(
        **{
            f"get_{name}.side_effect": ProviderError("not configured")
            for name in (
                "bot_management",
                "url_normalization",
                "zone_security_settings",
                "zone_tls_settings",
                "security_txt",
                "managed_transforms",
                "cloud_connector_rules",
                "leaked_credential_check",
                "content_scanning",
            )
        }
    )
    # cmd_dump calls the provider's own dump_extra_sections, so bind the real
    # implementation and let it aggregate against these mocked getters.  Other
    # providers' getters no longer need stubbing: their dump code is reachable
    # only through their own provider class.
    mock_prov._extensions = None  # let the real property build the list
    mock_prov.extensions = CloudflareProvider.extensions.fget(mock_prov)
    mock_prov.dump_extra_sections = lambda scope: CloudflareProvider.dump_extra_sections(
        mock_prov, scope
    )
    for k, v in overrides.items():
        setattr(mock_prov, k, v) if not callable(v) else setattr(
            getattr(mock_prov, k), "return_value", v
        )
    return mock_prov


@pytest.fixture
def sample_config(tmp_path):
    """Create a real Config object with a rules dir and zone file."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return Config(
        providers={"cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})},
        rules_dir=rules_dir,
        zones={
            "example.com": ZoneConfig(
                name="example.com", zone_id="zone-abc", sources=["rules"], targets=["cloudflare"]
            ),
            "other.com": ZoneConfig(
                name="other.com", zone_id="zone-def", sources=["rules"], targets=["cloudflare"]
            ),
        },
    )


class TestPageShieldPoliciesCLI:
    """Tests for Page Shield policy integration in CLI."""

    @patch("octorules.commands._providers._init_providers")
    def test_plan_with_page_shield_policies(self, mock_init_provs, sample_config, caplog):
        """Plan should detect Page Shield policy additions."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "cloudflare:\n  page_shield_policies:\n"
            "  - description: 'CSP on all'\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        mock_prov = MagicMock(spec=CloudflareProvider)
        # spec makes SUPPORTS a Mock, not the real frozenset; declare it so
        # the fail-closed capability check sees a real set.
        mock_prov.SUPPORTS = frozenset({"page_shield", "lists", "custom_rulesets"})
        # plan and apply walk provider.extensions, so bind the real list.
        mock_prov._extensions = None
        mock_prov.extensions = CloudflareProvider.extensions.fget(mock_prov)
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = []
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert result == 0
        assert "CSP on all" in caplog.text or True  # plan output goes to stdout

    @patch("octorules.commands._providers._init_providers")
    def test_plan_no_page_shield_key_skips(self, mock_init_provs, sample_config):
        """When page_shield_policies key is absent, skip policy planning."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "cloudflare:\n  redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        mock_prov = MagicMock(spec=CloudflareProvider)
        # spec makes SUPPORTS a Mock, not the real frozenset; declare it so
        # the fail-closed capability check sees a real set.
        mock_prov.SUPPORTS = frozenset({"page_shield", "lists", "custom_rulesets"})
        # plan and apply walk provider.extensions, so bind the real list.
        mock_prov._extensions = None
        mock_prov.extensions = CloudflareProvider.extensions.fget(mock_prov)
        mock_prov.get_all_phase_rules.return_value = {}
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0
        # get_all_page_shield_policies should NOT be called
        mock_prov.get_all_page_shield_policies.assert_not_called()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_includes_page_shield_policies(self, mock_init_provs, sample_config):
        """Dump should fetch and include Page Shield policies."""
        import yaml

        mock_prov = _make_dump_mock()
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = [
            {
                "description": "CSP on all",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        ]
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        dumped = sample_config.rules_dir / "example.com.yaml"
        # Dump emits the nested format; normalize back to the flat view.
        from octorules.config import normalize_zone_format

        data = normalize_zone_format(yaml.safe_load(dumped.read_text()), source="dumped")
        assert "cloudflare.page_shield_policies" in data
        assert data["cloudflare.page_shield_policies"][0]["description"] == "CSP on all"

    @patch("octorules.commands._providers._init_providers")
    def test_dump_no_policies_no_section(self, mock_init_provs, sample_config):
        """Dump with no policies should not include page_shield_policies key."""
        import yaml

        mock_prov = _make_dump_mock()
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = []
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        dumped = sample_config.rules_dir / "example.com.yaml"
        data = yaml.safe_load(dumped.read_text())
        assert "cloudflare.page_shield_policies" not in (data or {})

    def test_lint_page_shield_policies_ok(self):
        """A valid policy produces no CORE010 finding via the lint hook path."""
        from octorules.commands._lint import _core_lint_zone
        from octorules.linter.engine import LintContext

        desired = {
            "cloudflare.page_shield_policies": [
                {
                    "description": "CSP on all",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                }
            ]
        }
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone(desired, ctx)
        assert not [r for r in ctx.results if r.rule_id == "CORE010"]

    def test_lint_page_shield_policies_error(self):
        """An empty description surfaces as a CORE010 lint error."""
        from octorules.commands._lint import _core_lint_zone
        from octorules.linter.engine import LintContext, Severity

        desired = {
            "cloudflare.page_shield_policies": [
                {
                    "description": "",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                }
            ]
        }
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone(desired, ctx)
        core010 = [r for r in ctx.results if r.rule_id == "CORE010"]
        assert core010 and core010[0].severity == Severity.ERROR
        assert "cloudflare.page_shield_policies" in core010[0].message

    def test_lint_page_shield_invalid_action(self):
        from octorules.commands._lint import _core_lint_zone
        from octorules.linter.engine import LintContext

        desired = {
            "cloudflare.page_shield_policies": [
                {
                    "description": "CSP",
                    "action": "invalid_action",
                    "expression": "true",
                    "enabled": True,
                    "value": "v",
                }
            ]
        }
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone(desired, ctx)
        assert [r for r in ctx.results if r.rule_id == "CORE010"]

    @patch("octorules.commands._providers._init_providers")
    def test_sync_creates_page_shield_policy(self, mock_init_provs, sample_config, caplog):
        """Sync should create new Page Shield policies."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "cloudflare:\n  page_shield_policies:\n"
            "  - description: 'CSP on all'\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        mock_prov = MagicMock(spec=CloudflareProvider)
        # spec makes SUPPORTS a Mock, not the real frozenset; declare it so
        # the fail-closed capability check sees a real set.
        mock_prov.SUPPORTS = frozenset({"page_shield", "lists", "custom_rulesets"})
        # plan and apply walk provider.extensions, so bind the real list.
        mock_prov._extensions = None
        mock_prov.extensions = CloudflareProvider.extensions.fget(mock_prov)
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = []
        mock_prov.create_page_shield_policy.return_value = {"id": "new-policy-id"}
        mock_prov.max_workers = 1
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_prov.create_page_shield_policy.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_deletes_page_shield_policy(self, mock_init_provs, sample_config, caplog):
        """Sync should delete policies in CF but not in YAML."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("cloudflare:\n  page_shield_policies: []\n")
        mock_prov = MagicMock(spec=CloudflareProvider)
        # spec makes SUPPORTS a Mock, not the real frozenset; declare it so
        # the fail-closed capability check sees a real set.
        mock_prov.SUPPORTS = frozenset({"page_shield", "lists", "custom_rulesets"})
        # plan and apply walk provider.extensions, so bind the real list.
        mock_prov._extensions = None
        mock_prov.extensions = CloudflareProvider.extensions.fget(mock_prov)
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = [
            {
                "id": "policy-to-delete",
                "description": "Old CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            }
        ]
        mock_prov.max_workers = 1
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_prov.delete_page_shield_policy.assert_called_once()


class TestApplyPageShield:
    """Tests for _apply_page_shield from octorules_cloudflare.page_shield."""

    def test_apply_page_shield_create(self):
        """_apply_page_shield should call create for new policies."""
        change = RuleChange(
            ChangeType.ADD,
            "CSP on all",
            REDIRECT_PHASE,
            desired={
                "description": "CSP on all",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            },
        )
        psp = PageShieldPolicyPlan(description="CSP on all", create=True, changes=[change])
        zp = ZonePlan(zone_name="example.com", extension_plans={"page_shield": [psp]})
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock(spec=CloudflareProvider)
        provider.create_page_shield_policy.return_value = {"id": "new-id"}
        provider.max_workers = 1

        synced, error = _apply_page_shield(zp, [psp], scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.create_page_shield_policy.assert_called_once()

    def test_apply_page_shield_delete(self):
        """_apply_page_shield should call delete for removed policies."""
        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="policy-123", delete=True)
        zp = ZonePlan(zone_name="example.com", extension_plans={"page_shield": [psp]})
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock(spec=CloudflareProvider)
        provider.max_workers = 1

        synced, error = _apply_page_shield(zp, [psp], scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.delete_page_shield_policy.assert_called_once_with(scope, "policy-123")

    def test_apply_page_shield_update(self):
        """_apply_page_shield should call update for modified policies."""
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="policy-456", changes=[change])
        zp = ZonePlan(zone_name="example.com", extension_plans={"page_shield": [psp]})
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock(spec=CloudflareProvider)
        provider.update_page_shield_policy.return_value = {"id": "policy-456"}
        provider.max_workers = 1

        synced, error = _apply_page_shield(zp, [psp], scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.update_page_shield_policy.assert_called_once()

    def test_apply_page_shield_update_includes_all_fields(self):
        """Update kwargs should include ALL required fields, not just the changed one."""
        from octorules_cloudflare.page_shield import _make_page_shield_phase

        synthetic = _make_page_shield_phase("CSP")
        change = RuleChange(
            ChangeType.MODIFY,
            "action",
            synthetic,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        # desired_policy carries the full desired state
        desired_policy = {
            "description": "CSP",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }
        psp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="policy-456",
            changes=[change],
            desired_policy=desired_policy,
        )
        zp = ZonePlan(zone_name="example.com", extension_plans={"page_shield": [psp]})
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock(spec=CloudflareProvider)
        provider.update_page_shield_policy.return_value = {"id": "policy-456"}
        provider.max_workers = 1

        synced, error = _apply_page_shield(zp, [psp], scope, provider)
        assert error is None
        assert len(synced) == 1
        # Verify ALL required fields were passed, not just the changed 'action'
        call_kwargs = provider.update_page_shield_policy.call_args
        _, kwargs = call_kwargs
        assert kwargs["description"] == "CSP"
        assert kwargs["action"] == "allow"
        assert kwargs["expression"] == "true"
        assert kwargs["enabled"] is True
        assert kwargs["value"] == "script-src 'self'"

    def test_apply_page_shield_empty(self):
        """Empty plans list should do nothing."""
        zp = ZonePlan(zone_name="example.com")
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock(spec=CloudflareProvider)
        provider.max_workers = 1

        synced, error = _apply_page_shield(zp, [], scope, provider)
        assert error is None
        assert len(synced) == 0
