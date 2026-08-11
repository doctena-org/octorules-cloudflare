"""The mocks are held against the SDK they stand in for.

Provider tests mock the Cloudflare SDK with hand-written objects, so a fixture
can only be as accurate as someone's memory of the API. Both prior logging
incidents trace back to that. Capturing real traffic is not available (there is
no zone whose traffic can be public), but two things can be checked without it:

* the alias map the mock replays is still the SDK's, not a stale transcription
* fixture payloads parse into the SDK's own response models

Neither proves a fixture matches production. Both catch the drift that silent
divergence starts with.
"""

import importlib
import pkgutil

import pydantic
import pytest

from tests.mocks import RULESET_FIELD_ALIASES, MockRule, MockRuleset


def _sdk_ruleset_aliases() -> dict[str, str]:
    """Every python_name -> api_alias pair across the SDK's ruleset models."""
    import cloudflare.types.rulesets as rulesets

    found: dict[str, str] = {}
    for mod in pkgutil.walk_packages(rulesets.__path__, rulesets.__name__ + "."):
        try:
            m = importlib.import_module(mod.name)
        except Exception:  # a module that needs optional extras is not our concern
            continue
        for obj in vars(m).values():
            if isinstance(obj, type) and issubclass(obj, pydantic.BaseModel):
                for fname, field in obj.model_fields.items():
                    if field.alias and field.alias != fname:
                        found[fname] = field.alias
    return found


class TestAliasMapMatchesTheSDK:
    def test_no_alias_has_been_added_or_changed_upstream(self):
        """An SDK upgrade that adds an alias must not silently bypass the mock."""
        sdk = _sdk_ruleset_aliases()
        missing = {k: v for k, v in sdk.items() if RULESET_FIELD_ALIASES.get(k) != v}
        assert not missing, (
            "cloudflare.types.rulesets aliases the mock does not replay: "
            f"{missing}. Add them to RULESET_FIELD_ALIASES in tests/mocks.py."
        )

    def test_map_contains_no_aliases_the_sdk_dropped(self):
        sdk = _sdk_ruleset_aliases()
        stale = {k: v for k, v in RULESET_FIELD_ALIASES.items() if k not in sdk}
        assert not stale, f"RULESET_FIELD_ALIASES entries the SDK no longer has: {stale}"

    def test_the_map_is_not_empty(self):
        """A refactor that empties it would make every alias assertion vacuous."""
        assert RULESET_FIELD_ALIASES


class TestMockReplaysAliasing:
    """by_alias must actually change the output, or the flag is untested."""

    def test_by_alias_true_returns_api_names(self):
        rule = MockRule({"action": "set_cache_settings", "max-age": 300})
        assert rule.model_dump(by_alias=True) == {
            "action": "set_cache_settings",
            "max-age": 300,
        }

    def test_by_alias_false_returns_python_names(self):
        rule = MockRule({"action": "set_cache_settings", "max-age": 300})
        assert rule.model_dump(by_alias=False) == {
            "action": "set_cache_settings",
            "max_age": 300,
        }

    def test_the_two_forms_differ_on_aliased_data(self):
        """The regression guard: a mock ignoring by_alias returns the same dict."""
        rule = MockRule({"list": "blocked", "from": 400})
        assert rule.model_dump(by_alias=True) != rule.model_dump(by_alias=False)

    def test_nested_aliases_are_rewritten(self):
        """status_code_range.from is the shape that caused the 0.11.1 no-op MODIFY."""
        rule = MockRule({"edge_ttl": {"status_code_ttl": [{"status_code_range": {"from": 400}}]}})
        dumped = rule.model_dump(by_alias=False)
        assert dumped["edge_ttl"]["status_code_ttl"][0]["status_code_range"] == {"from_": 400}

    def test_unaliased_fields_are_untouched(self):
        rule = MockRule({"ref": "r1", "expression": "true", "enabled": True})
        assert rule.model_dump(by_alias=False) == rule.model_dump(by_alias=True)

    def test_exclude_none_still_applies_on_both_paths(self):
        rule = MockRule({"ref": "r1", "max-age": None})
        assert rule.model_dump(by_alias=True, exclude_none=True) == {"ref": "r1"}
        assert rule.model_dump(by_alias=False, exclude_none=True) == {"ref": "r1"}


class TestFixturesParseIntoSDKModels:
    """Representative fixture payloads validate against the real response models.

    The models are permissive (``extra='allow'``), so this catches a missing or
    mistyped required field, not a misspelled optional one. That is a real
    bound, and stated rather than implied: passing here does not mean a fixture
    matches production.
    """

    @staticmethod
    def _phase_response(rules):
        return {
            "id": "ruleset-id",
            "kind": "zone",
            "last_updated": "2026-08-11T00:00:00Z",
            "name": "default",
            "phase": "http_request_firewall_custom",
            "rules": rules,
            "version": "1",
        }

    def test_a_block_rule_fixture_validates(self):
        from cloudflare.types.rulesets import PhaseGetResponse

        payload = self._phase_response(
            [
                {
                    "id": "rule-1",
                    "version": "1",
                    "last_updated": "2026-08-11T00:00:00Z",
                    "action": "block",
                    "expression": "ip.src eq 1.2.3.4",
                    "description": "block one address",
                }
            ]
        )
        model = PhaseGetResponse.model_validate(payload)
        assert model.rules and model.rules[0].action == "block"

    def test_missing_a_required_field_is_rejected(self):
        """Proves the check has teeth rather than accepting anything."""
        from cloudflare.types.rulesets import PhaseGetResponse

        payload = self._phase_response([])
        del payload["version"]
        with pytest.raises(pydantic.ValidationError):
            PhaseGetResponse.model_validate(payload)

    def test_mock_output_round_trips_into_the_model(self):
        """What the mock hands the provider is a shape the SDK would accept."""
        from cloudflare.types.rulesets import PhaseGetResponse

        rule = MockRule(
            {
                "id": "rule-1",
                "version": "1",
                "last_updated": "2026-08-11T00:00:00Z",
                "action": "block",
                "expression": "true",
            }
        )
        payload = self._phase_response([rule.model_dump(by_alias=True)])
        model = PhaseGetResponse.model_validate(payload)
        assert model.rules[0].id == "rule-1"


class TestAliasedFieldsSurviveTheReadPath:
    """A rule with aliased fields comes back with API names, not Python ones.

    This is the 0.11.1 regression test, and it did not exist. _to_dict passes
    by_alias=True so that the read path yields the canonical API names the
    desired config is written in; dumping without it yields Python names that
    never compare equal, so affected rules showed a no-op MODIFY in every plan.

    Two things had to be true for a test to catch that, and neither was: the
    mock must honour by_alias, and some fixture must actually carry an aliased
    field. Every fixture used plain names, so the whole class of bug was
    invisible to a suite of 1,800 tests.
    """

    @staticmethod
    def _provider_with(rule_data, mock_cf_client):
        from octorules_cloudflare.provider import CloudflareProvider

        ruleset = MockRuleset(rules=[MockRule(rule_data)])
        mock_cf_client.rulesets.phases.get.return_value = ruleset
        return CloudflareProvider(token="t", client=mock_cf_client)

    def test_hyphenated_cache_field_keeps_its_api_name(self, mock_cf_client):
        from octorules.provider.base import Scope

        provider = self._provider_with(
            {"ref": "r1", "action": "set_cache_settings", "max-age": 300}, mock_cf_client
        )
        rules = provider.get_phase_rules(Scope(zone_id="z1"), "cloudflare.waf_custom_rules")
        assert "max-age" in rules[0], (
            "read path lost the API field name; a desired config written with "
            "'max-age' will now diff against 'max_age' on every plan"
        )
        assert "max_age" not in rules[0]

    def test_reserved_word_field_keeps_its_api_name(self, mock_cf_client):
        from octorules.provider.base import Scope

        provider = self._provider_with(
            {"ref": "r1", "action": "block", "list": "blocked_ips"}, mock_cf_client
        )
        rules = provider.get_phase_rules(Scope(zone_id="z1"), "cloudflare.waf_custom_rules")
        assert "list" in rules[0]
        assert "rule_list" not in rules[0]

    def test_nested_status_code_range_keeps_from(self, mock_cf_client):
        """The exact shape from the 0.11.1 report."""
        from octorules.provider.base import Scope

        provider = self._provider_with(
            {
                "ref": "r1",
                "action": "set_cache_settings",
                "edge_ttl": {"status_code_ttl": [{"status_code_range": {"from": 400}}]},
            },
            mock_cf_client,
        )
        rules = provider.get_phase_rules(Scope(zone_id="z1"), "cloudflare.waf_custom_rules")
        rng = rules[0]["edge_ttl"]["status_code_ttl"][0]["status_code_range"]
        assert rng == {"from": 400}, f"expected the API name 'from', got {rng}"
