# SC200-04 — Mass resource deletion

| | |
|---|---|
| **ID** | SC200-04 |
| **Severity** | **High** |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Impact |
| **MITRE technique** | [T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/) |

## What it catches

A single caller deleting **many resources in a short window** — the signature of destructive impact (ransomware-style wipe, disgruntled-insider teardown, or a compromised principal burning the environment). High severity because the action is irreversible and high-blast-radius.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 15 minutes over a 1-hour lookback.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue endswith "/delete"
| where ActivityStatusValue == "Success"
| summarize DeleteCount = count(), DeletedResources = make_set(ResourceId, 10) by Caller, bin(TimeGenerated, 5m)
| where DeleteCount >= 5
```

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-04**. Summary: create resource group `rg-sim-delete` with several cheap resources (e.g. 5× public IPs / empty NSGs) → select all → **Delete** in bulk (or delete the resource group).

## Expected result

**Confirmed:** incident **#3** (High) raised 2026-06-07 ~03:29 UTC — 5× `publicIPAddresses/delete` + resource-group delete on `rg-sim-delete`, caller `ievgen@summitrangeconsulting.com`.

## Evidence

![Mass resource deletion alert](../screenshots/06-inc-04-overview.png)

Query results in the alert show the caller and per-5-minute delete counts (8 and 5) crossing the threshold. Full investigation: [INV-01](../investigations/INV-01-mass-resource-deletion.md).

## Tuning notes

- Threshold (`>= 5` delete operations per 5-minute bin, per caller) balances catching real wipes against normal teardown of test environments.
- Exclude known IaC/automation principals that legitimately tear down ephemeral resources, or raise their threshold separately.
