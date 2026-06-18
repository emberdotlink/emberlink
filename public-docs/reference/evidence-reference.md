# Evidence Reference

Emberlink's current evidence surface has two layers:

- **Receipts**: signed, portable artifacts
- **Audit**: local daemon-side event history and verification

They are related, but they are not the same thing.

## Receipts

Use receipts when you need the artifact that proves what happened.

### List receipts

```bash
ember receipt list
ember receipt list --persona <persona-id>
ember receipt list --json
```

### Show one receipt

```bash
ember receipt show <receipt-or-grant-id>
ember receipt show <receipt-or-grant-id> --format md
```

`show` accepts either:

- a receipt id
- a terminal grant id that resolves to its receipt

### Export a receipt

```bash
ember receipt export <receipt-id>
ember receipt export --latest --format md
```

The `--latest --format md` path is the current public-friendly artifact export
for "show me what just happened".

### Verify a receipt

```bash
ember receipt verify <receipt-id>
ember receipt verify --file <path>
ember receipt verify --tree <path> --offline
```

Important truth:

- id-mode verification can use daemon-backed local lookup
- file/tree verification is intentionally daemon-free
- offline modes exist so exported artifacts can still be checked later

### Tree and rollup views

```bash
ember receipt tree --grant <grant-id>
ember receipt tree --grant <grant-id> --export <path>
ember receipt rollup --since 24h
```

These are more advanced evidence views:

- `tree` walks delegated grant/receipt structure
- `rollup` aggregates construct-invocation sub-receipts by `materialization_id`

## Audit

Use audit when you need local daemon history or chain verification.

### Show recent audit entries

```bash
ember audit show --limit 20
ember audit show --agent <agent-id> --limit 50
```

`audit show` is a recent-entries view. It is not an event-id lookup.

### Export recent audit entries

```bash
ember audit export --format json
ember audit export --format csv --limit 100
```

### Query the unified receipts view

```bash
ember audit query
ember audit query --since 24h
ember audit query --actor <persona-id> --kind grant
```

Current truth: `audit query` is the receipt-oriented query surface, not the
same thing as `audit show`.

### Explain one audit event

```bash
ember audit explain <event-id>
```

Important honesty boundary:

- the event row is historical evidence
- the grant/policy sections are current-state explanation
- this is not pure historical replay

### Verify the audit chain

```bash
ember audit verify
ember audit verify --tail 1000
```

`audit verify` is the authoritative audit-chain integrity check.

## Recommended operator loop

For the common case:

1. perform a brokered action
2. run `ember receipt list`
3. export the latest receipt if you need a shareable artifact
4. run `ember audit show --limit 20` for recent local history
5. run `ember audit verify` if you are investigating evidence integrity
