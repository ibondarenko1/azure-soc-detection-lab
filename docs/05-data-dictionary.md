# Data dictionary

The telemetry these detections read, the fields they depend on, and what each rule
requires, so the detection logic is grounded in a known schema, not assumed.

## Tables in scope

| Table | Source | Status |
|-------|--------|--------|
| `AzureActivity` | Azure subscription Activity Log → Log Analytics | **in use**, detections 01 to 05 |
| `DeviceEvents` | Defender for Endpoint → Defender XDR connector → workspace | **in use**, DET-006 |
| `DeviceInfo` / `AlertEvidence` | Defender for Endpoint → Defender XDR connector → workspace | **in use**, endpoint hunts |
| `DeviceTvm*` | Defender Vulnerability Management (advanced hunting only) | **in use**, endpoint hunts (not streamed to the workspace) |
| `SigninLogs` | Entra ID sign-ins | gap, needed for T1078 / T1110 (see [coverage](../navigator)) |
| `StorageBlobLogs` | Storage data-plane | gap, needed for T1530 |

## `AzureActivity` fields used

| Field | Type | Meaning | Used by |
|-------|------|---------|---------|
| `TimeGenerated` | datetime | event time (windowing, `bin`) | all |
| `ActivityStatusValue` | string | `Success` / `Failure` / `Started` … | all |
| `Caller` | string | principal UPN / object id (→ Account entity) | all |
| `OperationNameValue` | string | ARM operation, e.g. `…/securityRules/write` | all |
| `ResourceId` | string | target resource ARM id | 02, 03, 04, 05 |
| `ResourceProviderValue` | string | e.g. `Microsoft.Network` | 05 |
| `Properties_d` | dynamic | operation properties (event category, etc.) | 03 (projected) |

## Required fields per detection

| Rule | Filters on | Aggregates | Entity |
|------|-----------|-----------|--------|
| DET-001 | `ActivityStatusValue == "Failure"` | `count() >= 8` by `Caller`, `bin(5m)` | Caller → Account |
| DET-002 | `OperationNameValue has securityRules`, `Success` |, | Caller → Account |
| DET-003 | `OperationNameValue has roleAssignments`, `Success` |, | Caller → Account |
| DET-004 | `OperationNameValue endswith "/delete"`, `Success` | `count() >= 5` by `Caller`, `bin(5m)` | Caller → Account |
| DET-005 | `OperationNameValue endswith "/write"`, `Success` |, | Caller → Account |
| DET-006 | `ActionType == "OpenProcessApiCall"`, `FileName =~ "lsass.exe"` | `count() >= 1` by `DeviceName`, `bin(5m)` | DeviceName → Host, InitiatingProcessAccountName → Account |

These same field names back the [unit-test fixtures](../tests/fixtures) and the
[Sigma conversions](../sigma) (mapped to the Sigma `azure/activitylogs` taxonomy).

## `DeviceEvents` fields used (DET-006 and endpoint hunts)

| Field | Type | Meaning | Used by |
|-------|------|---------|---------|
| `Timestamp` / `TimeGenerated` | datetime | event time | all endpoint |
| `ActionType` | string | event kind, e.g. `OpenProcessApiCall` | DET-006 |
| `FileName` | string | target process (e.g. `lsass.exe`) | DET-006 |
| `InitiatingProcessFileName` | string | the process taking the action | DET-006, hunts |
| `InitiatingProcessCommandLine` | string | command line (dump-pattern context) | LSASS hunt |
| `InitiatingProcessAccountName` | string | acting account (→ Account entity) | DET-006 |
| `DeviceName` / `DeviceId` | string | host (→ Host entity) / join key | DET-006, hunts |

The `DeviceTvm*` tables (`DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment`)
are read only in [Defender advanced hunting](../kql/hunting); they are not part of the Sentinel
workspace schema, which is why the TVM correlations are hunts and not deployed rules.
