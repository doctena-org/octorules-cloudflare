# Stage 2d: List Validation

Validates the `lists` section for structural correctness and item validity. Checks list metadata (name, kind) and validates individual items based on the list kind (IP, ASN, hostname, redirect).

## Category Q — List Validation (11 rules)

### CF470 — Missing or duplicate list name

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when:
- A list entry is missing the `name` field.
- Two lists share the same `name`.

```yaml
lists:
  - kind: ip
    items: []
    # missing name
```

Fix: Give each list a unique, non-empty `name`.

### CF471 — Missing or invalid list kind

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a list entry is missing the `kind` field or has an unrecognized kind value. Valid kinds: `ip`, `asn`, `hostname`, `redirect`.

```yaml
lists:
  - name: my_list
    kind: bogus     # not a valid kind
    items: []
```

Fix: Use a valid kind value.

### CF472 — List item missing required field

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a list item is missing the required field for its kind:
- **IP lists**: each item must have an `ip` field.
- **ASN lists**: each item must have an `asn` field.
- **Hostname lists**: each item must have a `hostname` field.
- **Redirect lists**: each item must have a `redirect` field.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - comment: "oops"    # missing ip field
```

Fix: Add the required field for the list kind.

### CF473 — Invalid IP address in IP list

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when an `ip` field value is not a valid IPv4/IPv6 address or CIDR range.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - ip: "not-an-ip"
```

Fix: Use a valid IP address (e.g., `1.2.3.4`) or CIDR range (e.g., `10.0.0.0/8`, `2001:db8::/32`).

### CF474 — Invalid ASN value in ASN list

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when an `asn` field value is not an integer, or is outside the valid range (0–4294967295).

```yaml
lists:
  - name: my_asns
    kind: asn
    items:
      - asn: "not-int"    # must be integer
      - asn: -1            # out of range
```

Fix: Use a valid ASN integer between 0 and 4294967295.

### CF475 — Duplicate items within list

| Severity | Category |
|----------|----------|
| WARNING | list |

Triggers when a list contains duplicate items. Checks the identifying value for each kind:
- **IP lists**: duplicate `ip` values.
- **ASN lists**: duplicate `asn` values.
- **Hostname lists**: duplicate `url_hostname` values within `hostname` objects.
- **Redirect lists**: duplicate `source_url` values within `redirect` objects.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - ip: "1.2.3.4"
      - ip: "1.2.3.4"     # duplicate
```

Fix: Remove the duplicate entry.

### CF476 — List exceeds maximum item count

**Severity:** WARNING

A list has more than 10,000 items. Cloudflare limits the number of items per list.

**Fix:** Split the list into multiple lists, or remove unused entries.

### CF477 — IP address has host bits set

| Severity | Category |
|----------|----------|
| WARNING | list |

Triggers when an IP list item has host bits set. For example, `10.0.0.1/24` should be `10.0.0.0/24`.

```yaml
lists:
  - name: blocked
    kind: ip
    items:
      - ip: "10.0.0.1/24"       # host bits set — did you mean 10.0.0.0/24?
```

Fix: Use the network address with host bits zeroed.

### CF478 — Overlapping IP/CIDR entries in list

| Severity | Category |
|----------|----------|
| WARNING | list |

Triggers when an IP list contains overlapping CIDR ranges where one is a subnet of the other.

```yaml
lists:
  - name: blocked
    kind: ip
    items:
      - ip: "10.0.0.0/8"
      - ip: "10.1.0.0/16"       # redundant — already covered by 10.0.0.0/8
```

Fix: Remove the narrower entry (it's already covered by the broader one) or consolidate into a single range.

### CF479 — Redirect source_url contains a query string

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a redirect list item's `source_url` (the matching URL) contains a query string. Cloudflare rejects such a Bulk Redirect at deploy time with API error 10053 (`matching url cannot have a query string`). Query-string matching is controlled by the separate `preserve_query_string` parameter, not by putting `?...` in the source URL.

```yaml
lists:
  - name: doctena_legacy_301
    kind: redirect
    items:
      - redirect:
          source_url: "example.com/old?ref=email"   # rejected — query string in matching URL
          target_url: "https://example.com/new"
          status_code: 301
```

Fix: Drop the query string from `source_url` (match on the path only) and, if you need query behaviour preserved on the redirect, set `preserve_query_string: true`.

### CF480 — Invalid list name

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a list `name` violates Cloudflare's naming rules: it must match `^[a-z0-9_]+$` (only lowercase letters, digits, and underscore) and be at most 50 characters. Cloudflare rejects list creation otherwise.

```yaml
lists:
  - name: My-Block-List        # rejected — uppercase and hyphen
    kind: ip
    items:
      - ip: "203.0.113.0/24"
```

Fix: Use a name like `my_block_list` — lowercase, digits, and underscore only, ≤50 characters.
