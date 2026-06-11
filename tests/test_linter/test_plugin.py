"""Tests for the Cloudflare lint plugin — registration and rule ID integrity."""

from octorules.linter.plugin import get_registered_plugins
from octorules.linter.rules.registry import RULE_REGISTRY

from octorules_cloudflare.linter._plugin import CF_RULE_IDS
from octorules_cloudflare.linter._rules import CF_RULE_METAS
from octorules_cloudflare.linter.schemas.actions import ACTION_SCHEMAS


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

    def test_rule_count(self):
        """Guard against silent rule add/remove (mirrors Azure/Bunny). Bump
        deliberately when intentionally adding or removing a rule."""
        assert len(CF_RULE_METAS) == 155, (
            f"Expected 155 CF rule metas, got {len(CF_RULE_METAS)}. "
            "If you added or removed a rule, update this count intentionally."
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

    def test_linter_schemas_match_sdk_models(self):
        """Linter action schemas must match the Cloudflare SDK ActionParameters models.

        If the SDK adds a new field (Cloudflare API change), this test fails,
        forcing a conscious decision: add the field to the linter schema or
        register it as an API-only field to strip.
        """
        from cloudflare.types.rulesets.block_rule import (
            ActionParameters as BlockAP,
        )
        from cloudflare.types.rulesets.compress_response_rule import (
            ActionParameters as CompressAP,
        )
        from cloudflare.types.rulesets.execute_rule import (
            ActionParameters as ExecAP,
        )
        from cloudflare.types.rulesets.log_custom_field_rule import (
            ActionParameters as LogAP,
        )
        from cloudflare.types.rulesets.redirect_rule import (
            ActionParameters as RedirectAP,
        )
        from cloudflare.types.rulesets.rewrite_rule import (
            ActionParameters as RewriteAP,
        )
        from cloudflare.types.rulesets.route_rule import (
            ActionParameters as RouteAP,
        )
        from cloudflare.types.rulesets.score_rule import (
            ActionParameters as ScoreAP,
        )
        from cloudflare.types.rulesets.serve_error_rule import (
            ActionParameters as ServeErrorAP,
        )
        from cloudflare.types.rulesets.set_cache_settings_rule import (
            ActionParameters as CacheAP,
        )
        from cloudflare.types.rulesets.set_config_rule import (
            ActionParameters as SetConfigAP,
        )
        from cloudflare.types.rulesets.skip_rule import (
            ActionParameters as SkipAP,
        )

        sdk_map = {
            "set_config": SetConfigAP,
            "execute": ExecAP,
            "skip": SkipAP,
            "set_cache_settings": CacheAP,
            "rewrite": RewriteAP,
            "compress_response": CompressAP,
            "serve_error": ServeErrorAP,
            "log_custom_field": LogAP,
            "block": BlockAP,
            "redirect": RedirectAP,
            "route": RouteAP,
            "score": ScoreAP,
        }

        for action_name, schema in ACTION_SCHEMAS.items():
            if not schema.allowed_parameter_keys:
                continue
            sdk_cls = sdk_map.get(action_name)
            if sdk_cls is None:
                continue
            sdk_keys = set(sdk_cls.model_fields.keys())
            linter_keys = schema.allowed_parameter_keys

            in_linter_not_sdk = linter_keys - sdk_keys
            in_sdk_not_linter = sdk_keys - linter_keys

            assert not in_linter_not_sdk, (
                f"{action_name}: linter allows keys not in SDK: {sorted(in_linter_not_sdk)}"
            )
            assert not in_sdk_not_linter, (
                f"{action_name}: SDK has keys not in linter schema "
                f"(add to schema or register_api_fields('action_parameters', ...)): "
                f"{sorted(in_sdk_not_linter)}"
            )
