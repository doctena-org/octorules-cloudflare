#!/usr/bin/env python3
"""Regenerate schemas.json from wirefilter + overlay.toml.

Reads the authoritative field/function list from octorules_wirefilter.get_schema_info()
and merges with Python-only metadata from overlay.toml to produce schemas.json — the
frozen fallback used when wirefilter is not installed.

Usage:
    python scripts/sync_schemas.py           # regenerate schemas.json
    python scripts/sync_schemas.py --check   # compare only, exit 1 if different
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
from pathlib import Path

try:
    _wf_version = importlib.metadata.version("octorules-wirefilter")
    from octorules_wirefilter import get_schema_info
except ImportError:
    print(
        "ERROR: octorules_wirefilter is not installed.\n"
        "Install it with: pip install octorules-wirefilter\n"
        "Or build from source: cd ../octorules-wirefilter && maturin develop",
        file=sys.stderr,
    )
    sys.exit(1)

from octorules_cloudflare.linter.schemas._registry import merge_wirefilter_overlay

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "octorules_cloudflare" / "linter" / "schemas"
SCHEMAS_JSON = SCHEMAS_DIR / "schemas.json"


def build_schema() -> dict:
    """Build the merged schema data from wirefilter + overlay."""
    merged = merge_wirefilter_overlay(get_schema_info())
    return {"_generated_with": f"octorules-wirefilter {_wf_version}", **merged}


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync schemas.json from wirefilter")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare generated output to committed schemas.json, exit 1 if different",
    )
    args = parser.parse_args()

    new_data = build_schema()
    new_json = json.dumps(new_data, indent=2) + "\n"

    if args.check:
        if SCHEMAS_JSON.exists():
            current = SCHEMAS_JSON.read_text()
        else:
            current = ""

        if new_json == current:
            print(f"OK: schemas.json is in sync with wirefilter {_wf_version}.")
            sys.exit(0)
        else:
            # Check for version mismatch
            try:
                current_data = json.loads(current) if current else {}
                current_ver = current_data.get("_generated_with", "unknown")
            except json.JSONDecodeError:
                current_ver = "unknown"

            print("DIFF: schemas.json is out of sync.", file=sys.stderr)
            print(
                f"  Committed: {current_ver}",
                file=sys.stderr,
            )
            print(f"  Installed: octorules-wirefilter {_wf_version}", file=sys.stderr)
            print(
                "Run 'python scripts/sync_schemas.py' to regenerate.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        SCHEMAS_JSON.write_text(new_json)
        print(f"Updated {SCHEMAS_JSON}")
        print(f"Generated with wirefilter {_wf_version}")


if __name__ == "__main__":
    main()
