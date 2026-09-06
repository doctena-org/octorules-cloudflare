"""Ruleset responses must work whether the SDK hands back a model or a dict.

cloudflare 5.7.0 retyped the ruleset *write* responses from a model class to
``TypeAlias = Union[Ruleset, Optional[object]]``. ``object`` matches anything,
so the SDK's ``construct_type`` stops selecting ``Ruleset`` and returns the raw
``dict``. Attribute access on the response then raises ``AttributeError`` after
the PUT has already reached Cloudflare: the write lands, the deploy fails, and
the operator is told nothing about which of the two happened.

The provider tests could not catch that on their own, because every mock in
``tests/mocks.py`` exposes ``.rules`` as an attribute and so can only ever
reproduce the model shape. These tests pin both shapes at once.
"""

import pytest
from octorules.provider.base import Scope

from octorules_cloudflare import CloudflareProvider
from octorules_cloudflare.provider import _resp_field

from .mocks import MockRuleset

RULES = [{"ref": "r1", "expression": "true", "action": "block"}]


def _zs() -> Scope:
    return Scope(zone_id="zone-123")


def _model(rules):
    """The pre-5.7.0 shape: a model exposing attributes."""
    return MockRuleset(rules=list(rules))


def _raw(rules):
    """The 5.7.0 shape: construct_type falls through to the raw dict."""
    return {"id": "rs-1", "name": "cs", "rules": list(rules)}


SHAPES = pytest.mark.parametrize("shape", [_model, _raw], ids=["model", "dict"])


class TestResponseShapeCompat:
    @SHAPES
    def test_put_phase_rules_counts_rules(self, mock_cf_client, shape):
        mock_cf_client.rulesets.phases.update.return_value = shape(RULES)
        provider = CloudflareProvider(token="t", client=mock_cf_client)
        assert provider.put_phase_rules(_zs(), "http_request_firewall_custom", RULES) == 1

    @SHAPES
    def test_put_custom_ruleset_counts_rules(self, mock_cf_client, shape):
        mock_cf_client.rulesets.update.return_value = shape(RULES)
        provider = CloudflareProvider(token="t", client=mock_cf_client)
        assert provider.put_custom_ruleset(_zs(), "rs-1", RULES) == 1

    @SHAPES
    def test_create_custom_ruleset_reads_id_and_name(self, mock_cf_client, shape):
        created = shape([])
        if not isinstance(created, dict):
            created.id, created.name = "rs-1", "cs"
        mock_cf_client.rulesets.create.return_value = created
        provider = CloudflareProvider(token="t", client=mock_cf_client)
        assert provider.create_custom_ruleset(_zs(), "cs", "http_request_firewall_custom", 0) == {
            "id": "rs-1",
            "name": "cs",
        }

    @SHAPES
    def test_get_phase_rules_reads_rules(self, mock_cf_client, shape):
        mock_cf_client.rulesets.phases.get.return_value = shape(RULES)
        provider = CloudflareProvider(token="t", client=mock_cf_client)
        assert provider.get_phase_rules(_zs(), "http_request_firewall_custom") == RULES

    @SHAPES
    def test_get_custom_ruleset_reads_rules(self, mock_cf_client, shape):
        mock_cf_client.rulesets.get.return_value = shape(RULES)
        provider = CloudflareProvider(token="t", client=mock_cf_client)
        assert provider.get_custom_ruleset(_zs(), "rs-1") == RULES


class TestRespField:
    def test_reads_model_attribute(self):
        assert _resp_field(MockRuleset(rules=[1]), "rules", []) == [1]

    def test_reads_dict_key(self):
        assert _resp_field({"rules": [1]}, "rules", []) == [1]

    def test_none_response_yields_default(self):
        """``Optional[object]`` in the union means None is a reachable response."""
        assert _resp_field(None, "rules", []) == []

    def test_missing_field_yields_default(self):
        assert _resp_field({}, "rules", []) == []
        assert _resp_field(object(), "rules", []) == []

    def test_null_field_yields_default(self):
        """Cloudflare returns a null ``rules`` for an empty ruleset."""
        assert _resp_field({"rules": None}, "rules", []) == []
        assert _resp_field(MockRuleset(rules=None), "rules", []) == []
