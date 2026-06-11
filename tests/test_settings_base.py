"""Tests for the shared flat-settings data model and formatter base."""

from octorules_cloudflare._bot_management import BotManagementPlan
from octorules_cloudflare._content_scanning import ContentScanningFormatter
from octorules_cloudflare._settings_base import (
    SettingsChange,
    SettingsPlan,
)


class TestSettingsPlanDefaults:
    def test_empty_plan(self):
        plan = SettingsPlan()
        assert plan.changes == []
        assert plan.unsupported == []
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_no_op_changes_do_not_count(self):
        plan = SettingsPlan(
            changes=[
                SettingsChange(field="a", current=1, desired=1),
                SettingsChange(field="b", current=1, desired=2),
            ]
        )
        assert plan.has_changes
        assert plan.total_changes == 1


class TestFormatterPlanTypeGating:
    def test_foreign_plan_type_is_ignored(self):
        # Each formatter is parameterised with its own Plan subclass;
        # plans of a sibling extension must not render through it.
        foreign = BotManagementPlan(
            changes=[SettingsChange(field="fight_mode", current=False, desired=True)]
        )
        fmt = ContentScanningFormatter()
        assert fmt.format_text([foreign], use_color=False) == []
        assert fmt.format_json([foreign]) == []
        assert fmt.format_report([foreign], False, []) is False
