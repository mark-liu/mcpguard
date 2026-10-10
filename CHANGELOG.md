# Changelog

## 0.4.2 - 2026-10-10

### Changed

- **Behaviour change:** the PostToolUse hook no longer scores `tool_input`, and
  partial redaction no longer rescans it. The model's own arguments are not an
  injection vector; a search for "exfiltrate" used to suppress its own result.
- `enc-003` needs a run of 4+ numeric char codes, so a bare `String.fromCharCode(`
  no longer fires. `om-001` and `om-004` need a quoted output target
  (`respond only with 'X'`, `respond (with|by|using) [only|saying] 'X'`). Colon and bare-word
  forms (`respond with the word X`, `respond with: X`, `Respond only with the
  following text: X`) are no longer matched; accepted false-positive trade.
  `enc-003` accepts hex codes (`0x69`). Pattern ids are unchanged.
- `audit --stats` excludes canary (`mcp__canary__*`) and tagged events by default
  and names the excluded tags; `--include-test` counts them. `--last` and the
  listing show a row's tag. Partial URL redactions are reported apart from
  full blocks, and unparseable log lines are counted.

### Added

- `MCPGUARD_AUDIT_TAG` is recorded as `tag` on each audit event (e.g. `replay`).

### Fixed

- The audit reader no longer fuses a torn last row of `.1` with the first live row.
  Rows fused by the pre-0.4.0 two-write append stay unreadable and are counted.

## 0.4.1 - 2026-10-10

### Fixed

- `ch-002` counts once per line instead of once per JSON string. Slack search
  returns every hit in one CSV string, so the 0.4.0 per-item cap never applied
  and N alert hits scored N x 0.5.
- `ch-002` no longer matches emoji shortcodes (`Critical:ghost:`, how Slack
  search renders a Grafana IRM integration name) or camelCase keys
  (`isCritical:`).
- The false-positive corpus feeds Slack search as one CSV string, the shape
  the hook receives.

## 0.4.0 - 2026-10-03

### Changed

- **Behaviour change:** the stdio proxy now enforces block verdicts by default.
  `action: warn` redacts the tool result (URL-only hits are blanked in place),
  `action: block` answers with a JSON-RPC error. Set `scan.enforce: false` to
  restore log-and-warn only; detections still reach the audit log.
- Only `tools/call` responses are altered; `tools/list` and `initialize` are
  scanned and logged but never changed. An unseen response id fails closed.
- The `ch-002` severity-label rule now counts once per result item instead of
  once per payload, so repeats inside one attacker string still sum.

### Added

- Every hook and proxy scan, pass included, is written to the audit log, with
  size rotation and `mcpguard audit --stats`.
- False-positive corpus test for common chat and search boilerplate.

### Fixed

- Proxy: whitespace-prefixed JSON and batch arrays no longer bypass scanning.
- Proxy: JSON-RPC `error` responses are scanned and retire their pending id.
- Proxy: requests are recorded before they reach the child, so a fast reply is
  classified correctly; requests over 1 MiB are tracked too.
- Proxy: pending ids are evicted by age, never while younger than five minutes.
- Audit log: rotation and append run under an advisory file lock.
- The redaction notice names the scanner that produced it (proxy or PostToolUse).
