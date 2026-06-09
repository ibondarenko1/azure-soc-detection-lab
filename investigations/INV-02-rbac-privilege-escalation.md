# INV-02, RBAC privilege escalation

> Investigation write-up for the incident raised by [DET-003](../detections/DET-003-rbac-role-assignment-changes.md). Fields marked _(fill)_ are completed from the live incident.

| | |
|---|---|
| **Incident ID** | #2 |
| **Detection** | DET-003, RBAC role assignment changes |
| **Severity** | Medium |
| **MITRE** | Privilege Escalation / Persistence → [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Status** | New |

## 1. Triage

- **What fired:** a new RBAC role assignment was created.
- **Caller (who granted):** `ievgen@<redacted-tenant>`
- **Principal granted / role / scope:** self → `Reader` → `rg-soc-sim` (plus Contributor → `sp-soc-sim`); both reverted within minutes
- **Source IP / time:** 2026-06-07 ~03:16 UTC; incident raised 03:29 UTC

![RBAC role assignment alert](../screenshots/06-inc-03-overview.png)

## 2. Scope

Was this an isolated grant or part of a sequence?

```kql
let actor = "<caller>";
let t0 = datetime(<incident-start>);
AzureActivity
| where TimeGenerated between ((t0 - 6h) .. (t0 + 6h))
| where Caller == actor
| where OperationNameValue has_any ("roleAssignments", "roleDefinitions", "elevateAccess")
| project TimeGenerated, OperationNameValue, ActivityStatusValue, _ResourceId
| order by TimeGenerated asc
```

- Role granted: _(fill, Reader in sim; flag if Owner/Contributor/UAA)_
- Other privilege operations by the caller: _(fill)_
- Is the caller an expected admin? _(fill)_

## 3. Assessment

- **Determination:** _(true positive simulation / benign)_
- **Risk:** a persistent grant survives credential resets; high-privilege roles = escalation + persistence.
- **Root cause:** benign simulated Reader assignment then removed (controlled benign action).

## 4. Response

For a real positive:
1. Remove the unauthorized role assignment.
2. Review all assignments made by the caller in the window.
3. Investigate the caller account for compromise; reset credentials, revoke sessions.
4. Consider PIM / just-in-time access to prevent standing grants.

## 5. Lessons / tuning

- Detection fires on `roleAssignments/write` as expected.
- Tuning follow-ups: see [DET-003 tuning notes](../detections/DET-003-rbac-role-assignment-changes.md#tuning-notes).
