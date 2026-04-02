"""Expression bridge — wirefilter FFI integration with graceful fallback.

When the optional octorules-wirefilter package is installed, this module
delegates expression parsing to the actual wirefilter engine (same parser
Cloudflare uses). When not installed, falls back to a best-effort regex
parser that extracts fields, operators, and values from expressions.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field, replace

log = logging.getLogger(__name__)

# Try to import the optional wirefilter FFI bindings
try:
    from octorules_wirefilter import parse_expression as _wf_parse

    WIREFILTER_AVAILABLE = True
except ImportError:
    WIREFILTER_AVAILABLE = False


@dataclass(frozen=True)
class ExpressionInfo:
    """Extracted information from a parsed expression."""

    raw: str
    fields_used: list[str] = field(default_factory=list)
    functions_used: list[str] = field(default_factory=list)
    operators_used: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    regex_literals: list[str] = field(default_factory=list)
    ip_literals: list[str] = field(default_factory=list)
    int_literals: list[int] = field(default_factory=list)
    has_regex: bool = False
    depth_exceeded: bool = False
    parse_error: str = ""
    """Empty on success.  On wirefilter parse failure, contains the error
    message (e.g. ``"unknown field `bogus`"``).  On FFI crash, contains
    ``"ExceptionType: message"`` and the linter fields are regex-extracted."""
    parse_error_type: str = ""
    """Classifies the parse result source:

    - ``""`` — success (wirefilter or regex, no error).
    - ``"wirefilter_parse"`` — wirefilter rejected the expression (semantic
      error); fields are regex-extracted as fallback.
    - ``"wirefilter_crash"`` — FFI call raised an exception; fields are
      regex-extracted as fallback.
    - ``"regex_fallback"`` — wirefilter not installed; fields are
      regex-extracted (no error, best-effort mode).
    """


# --- Regex patterns for best-effort expression analysis ---

# Known CF fields pattern (dotted names like http.request.uri.path)
_FIELD_PATTERN = re.compile(r"\b((?:http|ip|ssl|cf|raw)\.[a-z][a-z0-9_.]*[a-z0-9])\b")

# Known operators (not function-style — these don't use parenthesized arguments)
_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
        "contains",
        "matches",
        "in",
        "not",
        "and",
        "or",
        "xor",
        "==",
        "!=",
        "~",
        "wildcard",
        "strict_wildcard",
        "bitwise_and",
    }
)

# Tokens that are both CF operators and look like function calls (take parenthesized args).
# These should be classified as functions when followed by '(' .
_OPERATOR_FUNCTIONS = frozenset({"starts_with", "ends_with"})

# Function call pattern
_FUNCTION_PATTERN = re.compile(r"\b([a-z_][a-z0-9_]*)\s*\(")

# String literal (double-quoted, excludes raw strings)
_STRING_LITERAL_PATTERN = re.compile(r'(?<!r)(?<!#)"((?:[^"\\]|\\.)*)"')

# Regex literal (CF uses ~"pattern" or matches "pattern")
# Supports both regular quoted strings and raw strings (r"...", r#"..."#).
_REGEX_LITERAL_PATTERN = re.compile(
    r"(?:"
    r'~\s*"((?:[^"\\]|\\.)*)"'  # ~"pattern"
    r'|~\s*r"([^"]*)"'  # ~r"pattern"
    r"|~\s*r#\"([^\"]*)\"#"  # ~r#"pattern"#
    r'|matches\s+"((?:[^"\\]|\\.)*)"'  # matches "pattern"
    r'|matches\s*r"([^"]*)"'  # matches r"pattern"
    r"|matches\s*r#\"([^\"]*)\"#"  # matches r#"pattern"#
    r")"
)

# Raw string literal — captures r"..." and r#"..."# content for exclusion
# from _STRING_LITERAL_PATTERN matches.
_RAW_STRING_PATTERN = re.compile(r'r"([^"]*)"|r#"([^"]*)"#')

# Integer literal
_INT_LITERAL_PATTERN = re.compile(r"\b(\d+)\b")

# IP literal — IPv4 with optional CIDR
_IPV4_LITERAL_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")

# IPv6 candidate — hex digits and colons, must contain at least one ':'
# followed by optional CIDR.  Validated with ipaddress module after extraction.
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9_.])([0-9a-fA-F]*:[0-9a-fA-F:]*(?:/\d{1,3})?)(?![a-zA-Z0-9_.])"
)

# Set/list literal: { "val1" "val2" }
_SET_LITERAL_PATTERN = re.compile(r"\{([^}]*)\}")

# Cache for parsed expressions — avoids repeated FFI calls across linter passes.
# Keyed on (normalized_expr, expect_parse_error, wirefilter_available).
# Bounded to prevent unbounded growth in long-running processes.
_PARSE_CACHE_MAX_SIZE = 2048
_parse_cache: dict[tuple[str, bool, bool], ExpressionInfo] = {}


def _clear_parse_cache() -> None:
    """Clear the expression parse cache.

    Intended for tests that monkeypatch wirefilter internals.
    """
    _parse_cache.clear()


def parse_expression(
    expr: str,
    phase: str | None = None,
    *,
    expect_parse_error: bool = False,
) -> ExpressionInfo:
    """Parse a Cloudflare ruleset expression and extract components.

    Results are cached so the same expression is parsed at most once per
    ``expect_parse_error`` mode.

    Uses wirefilter FFI when available, falls back to regex analysis.
    The *phase* parameter is accepted for API compatibility but currently
    unused — all expressions are parsed against the default wirefilter
    scheme where ``http.request.uri.path`` is a field.  Cloudflare's
    transform-phase function-call syntax (where ``http.request.uri.path``
    is callable) is not used in practice and would require a scheme that
    registers the name as both field and function, which wirefilter
    doesn't support.

    Set *expect_parse_error* when the expression is known to be a value
    expression (e.g. ``regex_replace(...)`` in action_parameters) that
    wirefilter cannot parse.  Fallback to regex is logged at INFO instead
    of WARNING.
    """
    from octorules.expression import normalize_expression

    expr = normalize_expression(expr)

    cache_key = (expr, expect_parse_error, WIREFILTER_AVAILABLE)
    cached = _parse_cache.get(cache_key)
    if cached is not None:
        return cached

    # Cloudflare accepts standalone 'true'/'false' as valid expressions
    # but wirefilter does not — handle them directly.
    if expr.strip("() ").lower() in ("true", "false"):
        result = ExpressionInfo(raw=expr)
    elif WIREFILTER_AVAILABLE:
        result = _parse_with_wirefilter(expr, expect_parse_error=expect_parse_error)
    else:
        result = replace(_parse_with_regex(expr), parse_error_type="regex_fallback")

    if len(_parse_cache) >= _PARSE_CACHE_MAX_SIZE:
        _parse_cache.clear()
    _parse_cache[cache_key] = result
    return result


def _parse_with_wirefilter(expr: str, *, expect_parse_error: bool = False) -> ExpressionInfo:
    """Parse using the wirefilter FFI bindings (default scheme).

    On parse failure, falls back to regex extraction so the linter's
    semantic rules (CF307, CF300, etc.) still fire on the expression.
    The wirefilter parse error is preserved in ``parse_error``.

    Why fall back instead of returning empty results?  Wirefilter rejects
    some expressions that are semantically wrong but syntactically
    extractable — e.g. ``http.host gt 5`` (type mismatch) or
    ``bogus_fn(http.host)`` (unknown function).  If we returned empty
    lists, the AST linter would have no fields/operators to inspect and
    rules like CF307 and CF300 would silently skip.  By running regex
    extraction on the rejected expression we give the linter enough
    material to produce its own diagnostics, while ``parse_error`` still
    records the authoritative wirefilter rejection.
    """
    try:
        result = _wf_parse(expr)
        if isinstance(result, dict):
            if "error" in result:
                # Wirefilter rejected the expression — fall back to regex
                # so the linter still gets fields/operators to analyze.
                # See docstring above for rationale.
                err = result["error"]
                if expect_parse_error:
                    log.debug("Wirefilter cannot parse value expression: %s", err)
                else:
                    log.debug("Wirefilter parse error, falling back to regex: %s", err)
                info = _parse_with_regex(expr)
                return replace(
                    info,
                    parse_error=result["error"],
                    parse_error_type="wirefilter_parse",
                )
            regex_literals = result.get("regex_literals", [])
            return ExpressionInfo(
                raw=expr,
                fields_used=result.get("fields", []),
                functions_used=result.get("functions", []),
                operators_used=result.get("operators", []),
                string_literals=result.get("string_literals", []),
                regex_literals=regex_literals,
                ip_literals=result.get("ip_literals", []),
                int_literals=result.get("int_literals", []),
                has_regex=bool(regex_literals),
                depth_exceeded=result.get("depth_exceeded", False),
            )
    except (RuntimeError, TypeError, ValueError, OSError) as e:
        # FFI call crashed — fall back to regex extraction.
        log.warning("Wirefilter FFI crashed, falling back to regex: %s", e, exc_info=True)
        info = _parse_with_regex(expr)
        return replace(
            info,
            parse_error=f"{type(e).__name__}: {e}",
            parse_error_type="wirefilter_crash",
        )
    return ExpressionInfo(raw=expr)


def _parse_with_regex(expr: str) -> ExpressionInfo:
    """Best-effort regex-based expression analysis (fallback)."""
    # Build all data into local variables, then construct a single frozen instance.

    # Extract fields
    fields_used = list(dict.fromkeys(_FIELD_PATTERN.findall(expr)))

    # Extract function calls (anything followed by '(')
    raw_funcs = _FUNCTION_PATTERN.findall(expr)
    # Filter out pure operators, but keep operator-functions (starts_with, ends_with)
    functions_used = list(dict.fromkeys(f for f in raw_funcs if f not in _OPERATORS))

    # Extract operators used
    operators_used: list[str] = []
    all_ops = _OPERATORS | _OPERATOR_FUNCTIONS
    for op in all_ops:
        if op == "strict_wildcard":
            # Two-word operator: match "strict wildcard" in expression text
            if re.search(r"\bstrict\s+wildcard\b", expr):
                operators_used.append(op)
        elif op in ("and", "or", "not", "xor") or op in _OPERATOR_FUNCTIONS:
            if re.search(rf"\b{op}\b", expr):
                operators_used.append(op)
        elif op in expr:
            operators_used.append(op)

    # Extract regex literals (regular and raw string formats)
    regex_literals: list[str] = []
    for match in _REGEX_LITERAL_PATTERN.finditer(expr):
        # Groups: 1=~"", 2=~r"", 3=~r#""#, 4=matches"", 5=matches r"", 6=matches r#""#
        val = (
            match.group(1)
            or match.group(2)
            or match.group(3)
            or match.group(4)
            or match.group(5)
            or match.group(6)
        )
        if val:
            regex_literals.append(val)
    has_regex = bool(regex_literals) or "matches" in expr or "~" in expr

    # Collect raw string contents to exclude from string_literals
    raw_string_contents: set[str] = set()
    for match in _RAW_STRING_PATTERN.finditer(expr):
        val = match.group(1) or match.group(2)
        if val:
            raw_string_contents.add(val)

    # Extract string literals (excluding regex literals and raw string contents)
    string_literals: list[str] = []
    for match in _STRING_LITERAL_PATTERN.finditer(expr):
        val = match.group(1)
        if val and val not in regex_literals and val not in raw_string_contents:
            string_literals.append(val)

    # Extract IP literals (IPv4 + IPv6)
    ip_literals: list[str] = _IPV4_LITERAL_PATTERN.findall(expr)
    for candidate in _IPV6_CANDIDATE_PATTERN.findall(expr):
        # Validate candidate is a real IPv6 address/network
        try:
            ipaddress.ip_address(candidate)
            ip_literals.append(candidate)
            continue
        except ValueError:
            pass
        # Try as network (e.g. 2001:db8::/32)
        try:
            ipaddress.ip_network(candidate, strict=False)
            ip_literals.append(candidate)
        except ValueError:
            pass

    # Extract integer literals
    int_literals: list[int] = []
    for match in _INT_LITERAL_PATTERN.finditer(expr):
        try:
            int_literals.append(int(match.group(1)))
        except ValueError:
            pass

    return ExpressionInfo(
        raw=expr,
        fields_used=fields_used,
        functions_used=functions_used,
        operators_used=operators_used,
        string_literals=string_literals,
        regex_literals=regex_literals,
        ip_literals=ip_literals,
        int_literals=int_literals,
        has_regex=has_regex,
    )
