"""Tests for Page Shield policy plan formatting."""

import io
import json

import pytest
from octorules.formatter import (
    build_report_data,
    format_plan_html,
    format_plan_json,
    format_plan_markdown,
    format_zone_plan,
    print_plan,
)
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

from octorules_cloudflare.page_shield import PageShieldFormatter, PageShieldPolicyPlan

REDIRECT_PHASE = get_phase("redirect_rules")


def _format_text(zp):
    return format_zone_plan(zp, use_color=False)


def _format_md(zp):
    return format_plan_markdown([zp])


def _format_html(zp):
    return format_plan_html([zp])


# (formatter, expected_substrings) per output format. Keeps the parametrized
# tests below compact while still asserting per-format markers (table tags,
# ```diff fences, HTML-encoded diff glyphs).
_CREATE_FORMATS = {
    "text": (_format_text, ["page_shield: CSP on all", "+ create policy"]),
    "markdown": (_format_md, ["page_shield:CSP on all", "create policy"]),
    "html": (
        _format_html,
        ["page_shield: CSP on all", "<table>", "Create", "create policy"],
    ),
}

_DELETE_FORMATS = {
    "text": (_format_text, ["page_shield: Old CSP", "- delete policy"]),
    "markdown": (_format_md, ["page_shield:Old CSP", "delete policy"]),
    "html": (_format_html, ["Delete", "delete policy", "Summary: Deletes=1"]),
}

_MODIFY_FORMATS = {
    "text": (_format_text, ["page_shield: CSP on all", "modify: CSP on all", "action"]),
    "markdown": (
        _format_md,
        ["page_shield:CSP on all", "```diff", "- action: 'log'", "+ action: 'allow'"],
    ),
    "html": (
        _format_html,
        ["Update", "<pre>- action: log</pre>", "<pre>+ action: allow</pre>"],
    ),
}


class TestPageShieldPolicyFormatting:
    """Tests for Page Shield policy plan formatting across all output formats."""

    @pytest.mark.parametrize("fmt_name", list(_CREATE_FORMATS.keys()))
    def test_format_create_policy(self, fmt_name):
        formatter, expected = _CREATE_FORMATS[fmt_name]
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        output = formatter(zp)
        for substr in expected:
            assert substr in output, f"{fmt_name}: missing {substr!r}"

    @pytest.mark.parametrize("fmt_name", list(_DELETE_FORMATS.keys()))
    def test_format_delete_policy(self, fmt_name):
        formatter, expected = _DELETE_FORMATS[fmt_name]
        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="p1", delete=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        output = formatter(zp)
        for substr in expected:
            assert substr in output, f"{fmt_name}: missing {substr!r}"

    @pytest.mark.parametrize("fmt_name", list(_MODIFY_FORMATS.keys()))
    def test_format_modify_policy(self, fmt_name):
        formatter, expected = _MODIFY_FORMATS[fmt_name]
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP on all",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP on all", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        output = formatter(zp)
        for substr in expected:
            assert substr in output, f"{fmt_name}: missing {substr!r}"

    def test_text_format_total_changes(self):
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        assert "1 change(s)" in format_zone_plan(zp, use_color=False)

    def test_format_page_shield_policy_plan_via_formatter(self):
        """PageShieldFormatter.format_text should produce text output for plans."""
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        fmt = PageShieldFormatter()
        lines = fmt.format_text([psp], use_color=False)
        assert any("page_shield: CSP" in line for line in lines)
        assert any("create policy" in line for line in lines)

    def test_json_format_includes_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        output = json.loads(format_plan_json([zp]))
        assert output["total_changes"] == 1
        zone = output["zones"][0]
        assert "page_shield_policy_plans" in zone
        assert zone["page_shield_policy_plans"][0]["description"] == "CSP on all"
        assert zone["page_shield_policy_plans"][0]["create"] is True

    def test_json_format_no_key_when_empty(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp])
        output = json.loads(format_plan_json([zp]))
        assert "page_shield_policy_plans" not in output["zones"][0]

    def test_json_format_modify_has_changes(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        output = json.loads(format_plan_json([zp]))
        psp_data = output["zones"][0]["page_shield_policy_plans"][0]
        assert psp_data["changes"][0]["type"] == "modify"
        assert "current" in psp_data["changes"][0]
        assert "desired" in psp_data["changes"][0]

    def test_report_includes_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        psp_phases = [p for p in zone["phases"] if p["phase"].startswith("page_shield:")]
        assert len(psp_phases) == 1
        assert psp_phases[0]["phase"] == "page_shield:CSP on all"
        assert psp_phases[0]["status"] == "drifted"
        assert psp_phases[0]["adds"] == 1

    def test_report_in_sync_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP stable", policy_id="p1", changes=[])
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        psp_phases = [p for p in zone["phases"] if p["phase"].startswith("page_shield:")]
        assert len(psp_phases) == 1
        assert psp_phases[0]["status"] == "in_sync"

    def test_print_plan_text_with_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        zp = ZonePlan(zone_name="test.com", extension_plans={"page_shield": [psp]})
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="text")
        output = buf.getvalue()
        assert "page_shield: CSP" in output
