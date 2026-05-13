# Stage 4: Cross-Rule Analysis

Analyzes relationships between rules within each phase. Rules inside
`custom_rulesets` entries are also included (CF102, CF103, CF104).

## Category P — Cross-Rule / Ruleset-Level (6 rules)

### CF100 — Duplicate expression across rules

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when two rules in the same phase have identical expressions (after whitespace normalization).

Fix: Remove the duplicate rule, or differentiate the expressions if the rules serve different purposes.

### CF101 — Unreachable rule after terminating action

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when a rule follows an always-true rule (`expression: "true"`) with a terminating action (`block`, `challenge`, `js_challenge`, `managed_challenge`, `redirect`). The subsequent rule will never execute.

```yaml
waf_custom_rules:
  - ref: block-all
    expression: "true"
    action: block
  - ref: log-bots             # unreachable
    expression: 'cf.bot_management.score lt 30'
    action: log
```

Fix: Reorder rules so the catch-all comes last, or remove the unreachable rule.

### CF102 — Unresolved list reference

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when an expression references a list via `$list_name` syntax but the list is not defined in the `lists` section of the rules file. Does not flag managed list references (`$cf.*`) — those are checked by CF103.

```yaml
lists:
  - name: known_ips
    kind: ip
    items: [...]

waf_custom_rules:
  - ref: block-unknown
    expression: 'ip.src in $unknown_list'    # $unknown_list not in lists section
```

Fix: Add the referenced list to the `lists` section, or fix the list name.

```yaml
lists:
  - name: unknown_list
    kind: ip
    items: [...]
```

### CF103 — Unknown managed list name

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when an expression references a managed list via `$cf.*` syntax that is not a known Cloudflare managed list.

```yaml
waf_custom_rules:
  - ref: block-anon
    expression: 'ip.src in $cf.invalid_list'
```

Fix: Use a valid managed list name. Known managed lists: `$cf.anonymizer`, `$cf.botnetcc`, `$cf.malware`, `$cf.open_proxies`, `$cf.vpn`. If Cloudflare has added a new managed list not yet in this set, please open an issue.

### CF104 — List type / field type mismatch

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when a rule expression references a list via `$list_name` or a managed list via `$cf.*` but the wirefilter field used with the list is incompatible with the list's `kind`. For example, using `ip.src in $my_asns` where `my_asns` is an ASN list — `ip.src` expects an IP list.

Also validates Cloudflare managed lists (`$cf.anonymizer`, `$cf.botnetcc`, `$cf.malware`, `$cf.open_proxies`, `$cf.vpn`) — all of which are `ip` kind.

Compatible field/kind mappings:
- **IP lists** (`kind: ip`): `ip.src`
- **ASN lists** (`kind: asn`): `ip.src.asnum`, `ip.geoip.asnum`
- **Hostname lists** (`kind: hostname`): `http.request.full_uri`, `http.host`
- **Redirect lists** (`kind: redirect`): `http.request.full_uri`

```yaml
lists:
  - name: my_asns
    kind: asn
    items: [...]

waf_custom_rules:
  - ref: block-asns
    expression: 'ip.src in $my_asns'    # ip.src expects IP list, not ASN
  - ref: block-anon
    expression: 'ip.src.asnum in $cf.anonymizer'  # asnum expects ASN, $cf.anonymizer is IP
```

Fix: Use the correct field for the list kind (e.g., `ip.src.asnum in $my_asns`), or change the list kind.

### CF105 — Duplicate execute of managed ruleset within phase

| Severity | Category |
|----------|----------|
| ERROR | cross_rule |

Triggers when two or more rules in the same phase have `action: execute` with the same `action_parameters.id` (managed ruleset UUID). Cloudflare's API rejects this at deploy time with error 20014: *"more than one rule is trying to execute the same managed ruleset"*. Lint catches the violation before sync fails.

```yaml
waf_managed_rules:
  - ref: rule-a
    action: execute
    action_parameters:
      id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa    # same id
      overrides:
        categories:
          - category: wordpress
            enabled: false
    expression: "true"

  - ref: rule-b
    action: execute
    action_parameters:
      id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa    # ← duplicate
      overrides:
        enabled: false
        categories:
          - category: wordpress
            enabled: true
    expression: '(http.host eq "example.com")'
```

Cloudflare permits one `execute` per managed-ruleset id per phase entrypoint, regardless of how the overrides differ.

Fix: collapse to a single `execute` entry and vary behaviour via `action_parameters.overrides.categories[]` or `action_parameters.overrides.rules[]`. Conditional logic that depends on the request itself (host, path, etc.) is not expressible at the execute layer — restructure into custom rules upstream or use per-rule overrides.

One finding is emitted per offending rule so that `# octorules:disable=CF105` directives can target individual refs if the configuration must remain in a transient state during a refactor.
