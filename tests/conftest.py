"""Shared fixtures for octorules-cloudflare tests."""

from unittest.mock import MagicMock

import pytest
from cloudflare import Cloudflare


@pytest.fixture
def mock_cf_client():
    """Create a mock Cloudflare client.

    ``spec=Cloudflare`` constrains the top-level client surface so a
    renamed SDK attribute (e.g. ``rulesets`` → ``waf_rulesets``) fails
    tests immediately instead of silently auto-mocking a new attribute.
    The sub-resources (``.rulesets``, ``.rulesets.phases``) remain
    un-specced for flexibility — provider code accesses methods on them
    but renames there are far rarer than on the client itself.
    """
    client = MagicMock(spec=Cloudflare)
    client.rulesets = MagicMock()
    client.rulesets.phases = MagicMock()
    return client
