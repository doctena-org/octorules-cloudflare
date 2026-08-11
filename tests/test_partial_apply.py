"""Multi-call settings applies attempt every operation and report the split.

The settings APIs are one HTTP request per field or per object with no
transaction around them. Before this, a loop that raised part-way through left
the zone in a state neither the plan nor the error message described:
``update_zone_security_settings`` stopped at the first failing setting, and
``sync_content_scanning_expressions`` deleted before creating, so one failing
delete meant the zone lost expressions and gained none.

Note that ``update_bot_management`` and ``update_url_normalization`` are single
API calls and cannot partially apply, so they are deliberately not covered here.
"""

from typing import ClassVar
from unittest.mock import MagicMock

import pytest
from cloudflare import AuthenticationError
from octorules.provider.exceptions import ProviderError

from octorules_cloudflare._settings_common import apply_each


class _Scope:
    label = "example.com"
    zone_id = "zone-1"
    api_kwargs: ClassVar[dict[str, str]] = {"zone_id": "zone-1"}


def _boom(msg="nope"):
    def _call():
        raise RuntimeError(msg)

    return _call


def _ok(sink, name):
    def _call():
        sink.append(name)

    return _call


class TestApplyEach:
    def test_every_operation_runs_even_after_a_failure(self):
        """A failing operation must not skip the ones queued behind it."""
        done = []
        ops = [
            ("a", _ok(done, "a")),
            ("b", _boom("b failed")),
            ("c", _ok(done, "c")),
        ]
        with pytest.raises(ProviderError):
            apply_each(ops, section="cloudflare.test", scope=_Scope())
        assert done == ["a", "c"]

    def test_error_names_what_applied_and_what_failed(self):
        """The message has to distinguish the two, or recovery is guesswork."""
        ops = [("a", _ok([], "a")), ("b", _boom("b failed"))]
        with pytest.raises(ProviderError) as exc:
            apply_each(ops, section="cloudflare.zone_security", scope=_Scope())
        msg = str(exc.value)
        assert "cloudflare.zone_security" in msg
        assert "example.com" in msg
        assert "Applied: a" in msg
        assert "b failed" in msg
        assert "1 of 2" in msg

    def test_all_succeeding_raises_nothing(self):
        done = []
        apply_each(
            [("a", _ok(done, "a")), ("b", _ok(done, "b"))],
            section="cloudflare.test",
            scope=_Scope(),
        )
        assert done == ["a", "b"]

    def test_empty_operations_is_a_no_op(self):
        apply_each([], section="cloudflare.test", scope=_Scope())

    def test_auth_error_aborts_immediately(self):
        """Every later call would fail the same way; the caller needs the auth error."""
        done = []

        def _auth_fail():
            raise AuthenticationError("bad token", response=MagicMock(), body=None)

        ops = [("a", _ok(done, "a")), ("b", _auth_fail), ("c", _ok(done, "c"))]
        with pytest.raises(AuthenticationError):
            apply_each(ops, section="cloudflare.test", scope=_Scope())
        assert done == ["a"]  # 'c' never attempted


class TestZoneSecurityPartialApply:
    def test_all_settings_attempted_when_one_fails(self, mock_cf_client):
        """A plan-gated setting in the middle must not block the rest."""
        from octorules_cloudflare.provider import CloudflareProvider

        provider = CloudflareProvider(api_token="t", client=mock_cf_client)
        attempted = []

        def _edit(setting_id, zone_id=None, value=None):
            attempted.append(setting_id)
            if setting_id == "challenge_ttl":
                raise RuntimeError("plan does not allow challenge_ttl")
            return MagicMock()

        mock_cf_client.zones.settings.edit.side_effect = _edit

        with pytest.raises(ProviderError) as exc:
            provider.update_zone_security_settings(
                _Scope(),
                # YAML keys, not API setting ids: challenge_passage -> challenge_ttl
                {
                    "security_level": "high",
                    "challenge_passage": 60,
                    "browser_integrity_check": True,
                },
            )

        assert len(attempted) == 3, "later settings were skipped after the failure"
        assert "challenge_passage" in str(exc.value)


class TestContentScanningOrdering:
    def test_creates_run_before_deletes(self, mock_cf_client):
        """Create-before-delete leaves a superset on failure, never a gap."""
        from octorules_cloudflare.provider import CloudflareProvider

        provider = CloudflareProvider(api_token="t", client=mock_cf_client)
        order = []

        existing = MagicMock()
        existing.model_dump.return_value = {"id": "p1", "payload": "old"}
        mock_cf_client.content_scanning.payloads.list.return_value = [existing]
        mock_cf_client.content_scanning.payloads.create.side_effect = lambda **kw: order.append(
            "create"
        )
        mock_cf_client.content_scanning.payloads.delete.side_effect = lambda *a, **kw: order.append(
            "delete"
        )

        provider.sync_content_scanning_expressions(
            _Scope(), current=[{"payload": "old"}], desired=[{"payload": "new"}]
        )

        assert order == ["create", "delete"]

    def test_failing_delete_does_not_suppress_creates(self, mock_cf_client):
        """The original bug: one stuck delete meant no expression was ever created."""
        from octorules_cloudflare.provider import CloudflareProvider

        provider = CloudflareProvider(api_token="t", client=mock_cf_client)
        created = []

        existing = MagicMock()
        existing.model_dump.return_value = {"id": "p1", "payload": "old"}
        mock_cf_client.content_scanning.payloads.list.return_value = [existing]
        mock_cf_client.content_scanning.payloads.create.side_effect = lambda **kw: created.append(
            kw
        )
        mock_cf_client.content_scanning.payloads.delete.side_effect = RuntimeError("in use")

        with pytest.raises(ProviderError):
            provider.sync_content_scanning_expressions(
                _Scope(), current=[{"payload": "old"}], desired=[{"payload": "new"}]
            )

        assert created, "the create was suppressed by the failing delete"


class TestLeakedCredentialsPartialApply:
    def test_deletes_come_last_and_all_are_attempted(self, mock_cf_client):
        from octorules_cloudflare.provider import CloudflareProvider

        provider = CloudflareProvider(api_token="t", client=mock_cf_client)
        order = []

        det = MagicMock()
        det.model_dump.return_value = {"id": "d1", "username": "gone", "password": "p"}
        mock_cf_client.leaked_credential_checks.detections.list.return_value = [det]
        mock_cf_client.leaked_credential_checks.detections.create.side_effect = lambda **kw: (
            order.append("create")
        )
        mock_cf_client.leaked_credential_checks.detections.delete.side_effect = lambda *a, **kw: (
            order.append("delete")
        )

        provider.sync_leaked_credential_detections(
            _Scope(),
            current=[{"username": "gone", "password": "p"}],
            desired=[{"username": "kept", "password": "q"}],
        )

        assert order == ["create", "delete"]
