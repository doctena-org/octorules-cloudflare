"""Shared mock classes for provider tests."""

# Python attribute name -> Cloudflare API field name, for every aliased field in
# the SDK's ruleset models. Extracted from cloudflare.types.rulesets rather than
# transcribed, and asserted still-current by test_mock_fidelity.py, so the mock
# cannot drift away from the SDK it stands in for.
#
# This exists because the aliases are exactly where _to_dict's by_alias=True
# earns its keep: dumping without them yields Python names that never match the
# API names in the desired config, which is what made cache rules show a
# perpetual no-op MODIFY in every plan (fixed in 0.11.1). A mock that ignores
# by_alias cannot reproduce that bug class at all.
RULESET_FIELD_ALIASES: dict[str, str] = {
    "from_": "from",
    "max_age": "max-age",
    "must_revalidate": "must-revalidate",
    "must_understand": "must-understand",
    "no_cache": "no-cache",
    "no_store": "no-store",
    "no_transform": "no-transform",
    "proxy_revalidate": "proxy-revalidate",
    "rule_list": "list",
    "s_maxage": "s-maxage",
    "stale_if_error": "stale-if-error",
    "stale_while_revalidate": "stale-while-revalidate",
}

# API field name -> Python attribute name.
_ALIAS_TO_PYTHON: dict[str, str] = {v: k for k, v in RULESET_FIELD_ALIASES.items()}


def _unalias(value):
    """Recursively rewrite API field names to the SDK's Python attribute names.

    What ``model_dump(by_alias=False)`` returns on a real SDK object.
    """
    if isinstance(value, dict):
        return {_ALIAS_TO_PYTHON.get(k, k): _unalias(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unalias(v) for v in value]
    return value


class MockRuleset:
    def __init__(self, rules=None):
        self.rules = rules


class MockRule:
    """Stands in for an SDK rule model, including its aliasing behaviour.

    Fixture data is written with API field names, matching what Cloudflare
    returns. ``by_alias=True`` therefore hands it back unchanged, and
    ``by_alias=False`` rewrites aliased fields to the SDK's Python attribute
    names — the same asymmetry a real model has. Ignoring the flag would make
    every by_alias bug invisible to these tests.
    """

    def __init__(self, data: dict):
        self._data = data

    def model_dump(self, by_alias=False, exclude_none=False):
        data = dict(self._data) if by_alias else _unalias(self._data)
        if exclude_none:
            return {k: v for k, v in data.items() if v is not None}
        return data


class MockRuleWithToDict:
    """Mock rule that only has to_dict (no model_dump)."""

    def __init__(self, data: dict):
        self._data = data

    def to_dict(self):
        return dict(self._data)


class MockRuleIterableOnly:
    """Mock rule that is iterable (has __iter__) but no model_dump or to_dict."""

    def __init__(self, data: dict):
        self._data = data

    def __iter__(self):
        return iter(self._data.items())
