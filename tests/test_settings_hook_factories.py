"""Direct cover for the hook factories every settings extension is built from.

``_prefetch_*`` and ``_dump_*`` are not written per feature — all five come from
``make_prefetch_hook`` / ``make_dump_hook`` in ``_settings_common``. Until now
those factories had no tests of their own; they were exercised only through five
hand-written copies in the per-feature suites, one per extension.

That is the wrong way round. A bug in a factory failed five times, which is
noise rather than signal, while the factory's own edge cases were covered only
as far as whichever feature happened to exercise them. What genuinely varies per
feature is the *wiring* — which section key and which provider getter each hook
was built with — and that is asserted here as one parametrized case per feature
rather than as five separate suites.

The per-feature ``TestPrefetchHook`` / ``TestDumpExtension`` classes are now
redundant with this file. They are deliberately left in place: deleting roughly
22 tests is where coverage loss hides, and the safe order is to land equivalent
cover first, confirm by mutation that it catches what the copies caught, and
remove them afterwards.
"""

from unittest.mock import MagicMock

import pytest
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_cloudflare._settings_common import make_dump_hook, make_prefetch_hook
from octorules_cloudflare.provider import CloudflareProvider

SECTION = "cloudflare.test_section"
GETTER = "get_test_settings"


def _scope(zone_id="zone-1"):
    from octorules.provider.base import Scope

    return Scope(zone_id=zone_id, label="example.com")


def _provider(**kw):
    p = MagicMock(spec=CloudflareProvider)
    getter = MagicMock(**kw)
    setattr(p, GETTER, getter)
    return p, getter


class TestPrefetchHookFactory:
    def test_returns_none_without_a_zone(self):
        """Account-scoped work has no zone settings to fetch."""
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, _ = _provider(return_value={})
        assert hook({SECTION: {"a": 1}}, _scope(zone_id=""), provider) is None

    def test_returns_none_when_the_section_is_absent(self):
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, getter = _provider(return_value={})
        assert hook({}, _scope(), provider) is None
        getter.assert_not_called()

    def test_returns_current_and_desired(self):
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, _ = _provider(return_value={"a": "live"})
        result = hook({SECTION: {"a": "wanted"}}, _scope(), provider)
        assert result == ({"a": "live"}, {"a": "wanted"})

    def test_auth_error_propagates_when_the_section_was_declared(self):
        """The user asked for this section, so a permission gap is their problem."""
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, _ = _provider(side_effect=ProviderAuthError("forbidden"))
        with pytest.raises(ProviderAuthError):
            hook({SECTION: {"a": 1}}, _scope(), provider)

    def test_provider_error_degrades_to_an_empty_current(self):
        """A failed read must not abort the plan; it yields an unknown-state diff."""
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, _ = _provider(side_effect=ProviderError("API down"))
        current, desired = hook({SECTION: {"a": 1}}, _scope(), provider)
        assert current == {}
        assert desired == {"a": 1}

    @pytest.mark.parametrize(
        "message", ["product has not been enabled", "not enabled on this zone"]
    )
    def test_product_not_enabled_is_skipped_entirely(self, message):
        """Distinct from a failed read: the feature is off, so there is nothing to plan."""
        hook = make_prefetch_hook(SECTION, GETTER)
        provider, _ = _provider(side_effect=ProviderError(message))
        assert hook({SECTION: {"a": 1}}, _scope(), provider) is None


class TestDumpHookFactory:
    def test_returns_none_without_a_zone(self):
        hook = make_dump_hook(SECTION, GETTER)
        provider, _ = _provider(return_value={"a": 1})
        assert hook(_scope(zone_id=""), provider) is None

    def test_wraps_settings_under_the_section_key(self):
        hook = make_dump_hook(SECTION, GETTER)
        provider, _ = _provider(return_value={"a": 1})
        assert hook(_scope(), provider) == {SECTION: {"a": 1}}

    def test_empty_settings_produce_no_section(self):
        """An empty dict must not emit a bare key into dumped YAML."""
        hook = make_dump_hook(SECTION, GETTER)
        provider, _ = _provider(return_value={})
        assert hook(_scope(), provider) is None

    def test_auth_error_is_skipped_rather_than_raised(self):
        """dump is best-effort: a section the token cannot read is omitted."""
        hook = make_dump_hook(SECTION, GETTER)
        provider, _ = _provider(side_effect=ProviderAuthError("forbidden"))
        assert hook(_scope(), provider) is None

    def test_provider_error_is_skipped(self):
        hook = make_dump_hook(SECTION, GETTER)
        provider, _ = _provider(side_effect=ProviderError("API down"))
        assert hook(_scope(), provider) is None


# (section key, provider getter) each feature's hooks must be wired with. This is
# the part that genuinely differs per extension; a wrong pair here is a real bug
# that no amount of factory testing would catch.
WIRING = [
    ("bot_management", "cloudflare.bot_management", "get_bot_management"),
    ("zone_security", "cloudflare.zone_security", "get_zone_security_settings"),
    (
        "url_normalization",
        "cloudflare.url_normalization_settings",
        "get_url_normalization",
    ),
    ("content_scanning", "cloudflare.content_scanning", "get_content_scanning"),
    (
        "leaked_credentials",
        "cloudflare.leaked_credential_check",
        "get_leaked_credential_check",
    ),
    ("zone_tls", "cloudflare.zone_tls", "get_zone_tls_settings"),
    ("security_txt", "cloudflare.security_txt", "get_security_txt"),
]


class TestPerFeatureWiring:
    """Each feature's prefetch hook reads the right section via the right getter."""

    @pytest.mark.parametrize(("module", "section", "getter"), WIRING)
    def test_prefetch_hook_reads_its_own_section(self, module, section, getter):
        import importlib

        mod = importlib.import_module(f"octorules_cloudflare._{module}")
        hook = getattr(mod, f"_prefetch_{module}")

        provider = MagicMock(spec=CloudflareProvider)
        getattr(provider, getter).return_value = {"probe": "live"}

        # The declared section is the one that must be picked up ...
        result = hook({section: {"probe": "wanted"}}, _scope(), provider)
        assert result == ({"probe": "live"}, {"probe": "wanted"}), (
            f"_prefetch_{module} did not read section {section!r} via {getter!r}"
        )

        # ... and a neighbour's section must not be.
        assert hook({"cloudflare.some_other_section": {"probe": 1}}, _scope(), provider) is None
