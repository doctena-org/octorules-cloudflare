"""Tests for the Cloudflare lint plugin — registration and rule ID integrity."""

from octorules.linter.plugin import get_registered_plugins
from octorules.linter.rules.registry import RULE_REGISTRY

from octorules_cloudflare.linter._plugin import CF_RULE_IDS
from octorules_cloudflare.linter._rules import CF_RULE_METAS


class TestPluginRegistration:
    def test_plugin_is_registered(self):
        plugins = get_registered_plugins()
        names = [p.name for p in plugins]
        assert "cloudflare" in names

    def test_plugin_rule_ids_match_metas(self):
        """CF_RULE_IDS (union of all validator RULE_IDS) must equal the set of
        RuleMeta definitions in _rules.py.  Catches missing or stale metas."""
        meta_ids = frozenset(r.rule_id for r in CF_RULE_METAS)
        assert CF_RULE_IDS == meta_ids, (
            f"Mismatch between CF_RULE_IDS and CF_RULE_METAS.\n"
            f"  In CF_RULE_IDS but missing RuleMeta: {CF_RULE_IDS - meta_ids}\n"
            f"  In CF_RULE_METAS but not in CF_RULE_IDS: {meta_ids - CF_RULE_IDS}"
        )

    def test_all_cf_rules_in_registry(self):
        for rule_id in CF_RULE_IDS:
            assert rule_id in RULE_REGISTRY, f"{rule_id} not in global registry"

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in CF_RULE_METAS]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {dupes}"

    def test_all_rule_ids_start_with_cf(self):
        for meta in CF_RULE_METAS:
            assert meta.rule_id.startswith("CF"), f"{meta.rule_id} doesn't start with CF"

    def test_idempotent_registration(self):
        """Calling register_cloudflare_linter() again should be a no-op."""
        from octorules_cloudflare.linter import register_cloudflare_linter

        count_before = len(get_registered_plugins())
        register_cloudflare_linter()
        assert len(get_registered_plugins()) == count_before
