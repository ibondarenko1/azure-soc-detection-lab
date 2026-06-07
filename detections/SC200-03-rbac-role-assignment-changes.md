# SC200-03 — RBAC role assignment changes

| | |
|---|---|
| **ID** | SC200-03 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Privilege Escalation / Persistence |
| **MITRE technique** | [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

## What it catches

Creation of an Azure **RBAC role assignment**. Granting a role (especially Owner/Contributor/User Access Administrator) to a new principal is a primary privilege-escalation and persistence mechanism in the cloud — it survives password resets and is easy to overlook. Every role grant is surfaced for review.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 30 minutes over a 1-hour lookback. Matches both role-assignment **writes** and **deletes** (any `roleAssignments` operation).

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Authorization/roleAssignments"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, Properties_d, ResourceId
```

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-03**. Summary: Subscription/RG → Access control (IAM) → **Add role assignment** → Reader → assign to a user/second account → then **Remove** it.

## Expected result

**Confirmed:** incident **#2** (Medium) raised 2026-06-07 ~03:29 UTC — `roleAssignments/write` (Reader) + delete on scope `rg-soc-sim`, caller `ievgen@summitrangeconsulting.com`.

## Evidence

![RBAC role assignment alert](../screenshots/06-inc-03-overview.png)

Full investigation: [INV-02](../investigations/INV-02-rbac-privilege-escalation.md).

## Tuning notes

- High-privilege roles (Owner, Contributor, User Access Administrator) should drive higher severity than Reader.
- Correlate the caller against expected admins; an assignment made by a non-admin principal is the strongest signal.
