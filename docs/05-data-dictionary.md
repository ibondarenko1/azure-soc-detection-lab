# Data dictionary

The telemetry these detections read, the fields they depend on, and what each rule
requires — so the detection logic is grounded in a known schema, not assumed.

## Tables in scope

| Table | Source | Status |
|-------|--------|--------|
| `AzureActivity` | Azure subscription Activity Log → Log Analytics | **in use** — all 5 detections |
| `SigninLogs` | Entra ID sign-ins | gap — needed for T1078 / T1110 (see [coverage](../navigator)) |
| `DeviceEvents` / `Device*` | Defender for Endpoint | available, not yet used |
| `StorageBlobLogs` | Storage data-plane | gap — needed for T1530 |

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
| SC200-01 | `ActivityStatusValue == "Failure"` | `count() >= 8` by `Caller`, `bin(5m)` | Caller → Account |
| SC200-02 | `OperationNameValue has securityRules`, `Success` | — | Caller → Account |
| SC200-03 | `OperationNameValue has roleAssignments`, `Success` | — | Caller → Account |
| SC200-04 | `OperationNameValue endswith "/delete"`, `Success` | `count() >= 5` by `Caller`, `bin(5m)` | Caller → Account |
| SC200-05 | `OperationNameValue endswith "/write"`, `Success` | — | Caller → Account |

These same field names back the [unit-test fixtures](../tests/fixtures) and the
[Sigma conversions](../sigma) (mapped to the Sigma `azure/activitylogs` taxonomy).
