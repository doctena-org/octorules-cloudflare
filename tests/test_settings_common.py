"""Tests for the shared settings helpers (partition + read-back verify)."""

import logging

from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderError

from octorules_cloudflare._settings_common import (
    partition_unsupported,
    verify_settings_applied,
    warn_unsupported,
)

_LOGGER = "octorules_cloudflare._settings_common"


def _scope() -> Scope:
    return Scope(zone_id="zone123", label="example.com")


class TestPartitionUnsupported:
    def test_absent_field_is_unsupported(self):
        managed, unsupported = partition_unsupported(
            {"enable_js": False}, {"fight_mode": False, "enable_js": True}
        )
        assert managed == {"enable_js": True}
        assert unsupported == ["fight_mode"]

    def test_empty_current_keeps_everything_managed(self):
        managed, unsupported = partition_unsupported({}, {"fight_mode": False})
        assert managed == {"fight_mode": False}
        assert unsupported == []

    def test_all_supported(self):
        desired = {"a": 1, "b": 2}
        managed, unsupported = partition_unsupported({"a": 0, "b": 0}, desired)
        assert managed == desired
        assert unsupported == []


class TestVerifySettingsApplied:
    def test_all_values_taken(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            failed = verify_settings_applied(
                lambda scope: {"enable_js": True, "fight_mode": False},
                _scope(),
                {"enable_js": True},
                "cloudflare_bot_management",
            )
        assert failed == []
        assert caplog.text == ""

    def test_value_did_not_take(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            failed = verify_settings_applied(
                lambda scope: {"security_level": "medium"},
                _scope(),
                {"security_level": "under_attack"},
                "cloudflare_zone_security",
            )
        assert failed == ["security_level"]
        assert "security_level" in caplog.text
        assert "reads back as 'medium'" in caplog.text
        assert "example.com" in caplog.text

    def test_field_absent_after_write(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            failed = verify_settings_applied(
                lambda scope: {"enable_js": True},
                _scope(),
                {"fight_mode": True},
                "cloudflare_bot_management",
            )
        assert failed == ["fight_mode"]
        assert "reads back as absent" in caplog.text

    def test_read_back_failure_is_swallowed(self, caplog):
        def boom(scope):
            raise ProviderError("read-back failed")

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            failed = verify_settings_applied(
                boom, _scope(), {"enable_js": True}, "cloudflare_bot_management"
            )
        assert failed == []
        assert "skipping verification" in caplog.text

    def test_multiple_failures_reported_sorted(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            failed = verify_settings_applied(
                lambda scope: {"a": 1, "b": 1},
                _scope(),
                {"b": 2, "a": 2},
                "section",
            )
        assert failed == ["a", "b"]


class TestWarnUnsupported:
    def test_warns_per_field_with_zone_label(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            warn_unsupported("cloudflare_bot_management", _scope(), ["a_field", "b_field"])
        assert caplog.text.count("not exposed on zone example.com") == 2
        assert "a_field" in caplog.text
        assert "b_field" in caplog.text

    def test_no_warning_for_empty_list(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            warn_unsupported("cloudflare_bot_management", _scope(), [])
        assert caplog.text == ""
