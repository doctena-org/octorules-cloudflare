"""Shared fixtures for octorules-cloudflare tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_cf_client():
    """Create a mock Cloudflare client."""
    client = MagicMock()
    client.rulesets = MagicMock()
    client.rulesets.phases = MagicMock()
    return client
