# SC200-01 — Failed Activity Log operations spike

| | |
|---|---|
| **ID** | SC200-01 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Discovery |
| **MITRE technique** | [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) |

## What it catches

A burst of **failed** Azure control-plane operations from a single caller in a short window. Attackers (and compromised principals) probe what they can touch, generating a spike of authorization failures before they find a permitted path. A sudden cluster of `Failure` operations is an early recon signal.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 15 minutes over a 1-hour lookback.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where ActivityStatusValue == "Failure"
| summarize FailureCount = count() by Caller, bin(TimeGenerated, 5m)
| where FailureCount >= 10
```

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-01**. Summary: from a low-privilege / second account, repeatedly attempt operations you are not authorized for (~10+ within one hour) — e.g. delete a resource or read a Key Vault secret you lack rights to.

## Expected result

**Confirmed:** incident **#4** (Medium) raised 2026-06-07 ~03:29 UTC — caller `ievgen@summitrangeconsulting.com`, 12 failed `publicIPAddresses/write` operations in one 5-minute bin.

## Evidence

This detection's alert appears in the consolidated [SC200 alert queue](../screenshots/05-incidents-queue-populated.png) (Discovery / T1087).

## Tuning notes

- Threshold (`>= 10` failures per 5-minute bin, per caller) clears normal transient failures (token refresh, eventual-consistency retries) while catching a deliberate probing burst.
- Common benign sources: automation principals hitting RBAC limits, IaC drift. Maintain an allow-list of known service principals before raising severity.
