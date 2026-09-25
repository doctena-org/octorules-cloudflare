"""Importing the provider builds the Cloudflare SDK's pydantic models eagerly."""

import os
import subprocess
import sys

_PROBE = (
    "import octorules_cloudflare\n"
    "from cloudflare.types.rulesets import PhaseGetResponse, RulesetGetResponse\n"
    "print(PhaseGetResponse.__pydantic_complete__, RulesetGetResponse.__pydantic_complete__)\n"
)


def _probe(**env_overrides: str) -> str:
    # A fresh interpreter: the SDK reads the setting once, when it is first imported.
    env = {k: v for k, v in os.environ.items() if k != "DEFER_PYDANTIC_BUILD"}
    env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, "-c", _PROBE], env=env, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def test_sdk_models_are_built_at_import():
    # A deferred build runs on first use, and pydantic's rebuild is not
    # thread-safe: parallel fetches raised PydanticUserError.
    assert _probe() == "True True"


def test_explicit_defer_setting_is_kept():
    assert _probe(DEFER_PYDANTIC_BUILD="true") == "False False"
