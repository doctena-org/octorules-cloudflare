"""Shared fixtures for the Cloudflare linter test suite.

Assertion helpers (``assert_lint``, ``assert_no_lint``) live in
``octorules.testing.lint``; this conftest only owns the CF-specific
linter registration and the per-test parse-cache reset.
"""

import pytest

from octorules_cloudflare.linter import register_cloudflare_linter
from octorules_cloudflare.linter.expression_bridge import _clear_parse_cache

# Ensure Cloudflare linter rules and non-phase keys are registered before
# any test in this directory runs.
register_cloudflare_linter()


@pytest.fixture(autouse=True)
def _clear_expression_cache():
    """Clear the expression parse cache before each test.

    Prevents stale cached results from interfering with tests that
    monkeypatch wirefilter internals.
    """
    _clear_parse_cache()
    yield
    _clear_parse_cache()
