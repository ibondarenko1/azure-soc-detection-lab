# Screenshots

Visual evidence for these detections. Full unredacted captures are staged in `_raw/` (git-ignored); the cropped copies here (browser chrome removed) are the ones referenced by the docs.

## Captured (v1)

| File | Shows |
|------|-------|
| `01-telemetry-schema.png` | Advanced hunting, live `sc200-ws` schema + query editor/history |
| `02-detection-rules-overview.png` | Detection Rules, 5 `[SC200]` rules, Enabled, with MITRE tactics/techniques |
| `05-incidents-queue-populated.png` | Alert queue, the `[SC200]` detections fired (Mass deletion High, RBAC, Failed-ops, NSG) |
| `06-inc-03-overview.png` | RBAC role assignment alert detail |
| `06-inc-04-overview.png` | Mass resource deletion (High) alert detail, caller + delete counts 8/5 over threshold |

## Redaction note (review before publishing)

The crop removes the browser URL bar (which carried the tenant ID). One item remains visible in the alert-detail shots (`06-inc-03`, `06-inc-04`):

- [ ] **Caller email** `ievgen@<redacted-tenant>` appears in the Query-results "Caller" column. It is your own address/domain, blur it if you prefer the repo not to surface it.

No subscription IDs are visible in the captured frames (`DeletedResources` is truncated to `[""]`).

## Optional / not in v1

Per-rule logic shots (`03-rule-0N`), per-incident shots for SC200-01/02/05 (`06-inc-01/02/05`), attack-story/timeline (`07`, `08`), and the investigation pivot (`09`) were not captured, the consolidated alert queue (`05`) and the two detail shots cover the story. Add them later if desired.
