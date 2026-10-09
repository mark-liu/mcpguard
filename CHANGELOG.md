# Changelog

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
