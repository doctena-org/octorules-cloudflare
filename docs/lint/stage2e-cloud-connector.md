# Stage 2e: Cloud Connector Rule Checks

Validates `cloud_connector_rules` entries for structural correctness and expression quality. Runs after per-phase checks with a dedicated module since Cloud Connector rules have a different structure (no `ref` field; `description` is the identity key; `provider`/`parameters` instead of an action).

Also checks CF015/CF016 (always-true/always-false) on rule expressions and delegates full expression analysis (E, F, G, O rules) and request-phase field restrictions (CF019/CF020) to the AST and phase linters.

## Category U — Cloud Connector Rules (6 rules)

### CF490 — Missing required field

| Severity | Category |
|----------|----------|
| ERROR | cloud_connector |

Triggers when a rule is missing one of the 3 required fields: `description`, `expression`, `provider`.

```yaml
cloudflare:
  cloud_connector_rules:
  - expression: 'starts_with(http.request.uri.path, "/assets/")'
    provider: cloudflare_r2
```

Fix: Add all required fields.

### CF491 — Invalid provider

| Severity | Category |
|----------|----------|
| ERROR | cloud_connector |

Triggers when `provider` is not one of `aws_s3`, `azure_storage`, `cloudflare_r2`, `gcp_storage`.

```yaml
cloudflare:
  cloud_connector_rules:
  - description: Serve assets
    expression: 'starts_with(http.request.uri.path, "/assets/")'
    provider: digitalocean
```

Fix: Use one of the four supported providers.

### CF492 — Invalid field type

| Severity | Category |
|----------|----------|
| ERROR | cloud_connector |

Triggers when:
- `description` or `expression` is not a non-empty string
- `enabled` is not a boolean
- `parameters` is not a mapping, or `parameters.host` is not a non-empty string
- A rule entry is not a mapping

Fix: Use the correct type for each field.

### CF493 — Duplicate description

| Severity | Category |
|----------|----------|
| WARNING | cloud_connector |

Triggers when two rules share the same `description`. Descriptions are identity keys — duplicates cause ambiguous matching between YAML and Cloudflare.

Fix: Give each rule a unique description.

### CF494 — Unknown field

| Severity | Category |
|----------|----------|
| ERROR | cloud_connector |

Triggers when a rule carries a key other than `description`, `enabled`, `expression`, `parameters`, `provider`, or when `parameters` carries a key other than `host`. A `ref` key gets a dedicated hint — Cloud Connector rules are identified by description, not ref.

Fix: Remove the unknown key.

### CF495 — Duplicate expression

| Severity | Category |
|----------|----------|
| WARNING | cloud_connector |

Triggers when two **enabled** rules share the same expression (after whitespace normalization) — a likely copy/paste error. A pair where either rule is disabled does not trigger; keeping a disabled copy around for a staged swap is a legitimate shape.

```yaml
cloudflare:
  cloud_connector_rules:
  - description: Serve assets
    expression: 'starts_with(http.request.uri.path, "/assets/")'
    provider: cloudflare_r2
    parameters:
      host: assets.account-a.r2.cloudflarestorage.com
  - description: Serve media
    expression: 'starts_with(http.request.uri.path, "/assets/")'
    provider: aws_s3
    parameters:
      host: media.s3.eu-central-1.amazonaws.com
```

Fix: Give each enabled rule a distinct expression.
