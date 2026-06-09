# INV-05, Privilege grant followed by deployment (High)

> Investigation write-up for the incident raised by [DET-007](../detections/DET-007-rbac-grant-then-deploy.md). Live witness: one principal created a role assignment and then deployed a resource within the correlation window, and the multi-stage rule joined the two events.

| | |
|---|---|
| **Detection** | DET-007, Privilege grant followed by deployment (same principal) |
| **Severity** | High |
| **MITRE** | Privilege Escalation / Persistence → [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Caller / IP** | `ievgen@<redacted-tenant>` / `70.9.97.251` |
| **Window** | grant 07:54:25 UTC → deploy 08:02:42 UTC (8 min, within the 30-min window) |

## 1. Triage

- **What fired:** the same caller created an RBAC role assignment (`roleAssignments/write`) and then,
  within 30 minutes, deployed a watched resource (`Microsoft.Storage/storageAccounts/write`).
- **Why this and not DET-003 / DET-005:** each half is a single-stage signal those rules already
  raise. DET-007 is the **correlation**, escalation immediately followed by use, which neither atomic
  rule expresses. It is a deterministic time-bounded self-join, not a threshold.
- **Live witness query result:**
  ```
  Caller=ievgen@<redacted-tenant>  GrantIp=70.9.97.251
  GrantTime=2026-06-09T07:54:25Z   FirstDeploy=2026-06-09T08:02:42Z   DeployCount=1
  ```

## 2. How it was generated

A controlled chain by one principal: a Reader role assignment at the `sc200-lab` scope
(`roleAssignments/write`), then a storage account deployment (`storageAccounts/write`) about eight
minutes later. DET-007's join on `Caller` with `DeployTime between (GrantTime .. GrantTime + 30m)`
returned the correlated pair. An earlier attempt where the deploy preceded the grant correctly did
**not** correlate, confirming the directionality of the window.

## 3. Scope

- One caller, one source IP, one grant and one deploy. In production this pattern, a principal that
  grants itself or another access and immediately stands up infrastructure, is a likely escalation
  chain.

## 4. Assessment

- **Determination:** true positive (controlled). The correlation surfaced the escalation-then-action
  behaviour while suppressing the per-stage noise (each half alone is lower severity).

## 5. Response

1. Confirm the role granted and the resource deployed.
2. If unauthorized, disable the principal, remove the assignment, and delete the resource.
3. Review the principal's other recent activity from the same source IP.

## 6. Lessons / tuning

- `corrWindow` (30 min) is the sensitivity knob; widen for slower operators, narrow to cut
  admin-session noise.
- An automation principal allow-listed in `soc-automation-principals` / `soc-deploy-owners` is
  already suppressed upstream by DET-003 / DET-005.

## Cleanup

The controlled role assignment and the witness storage accounts were removed after capture.
