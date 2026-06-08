# SC200-06, LSASS credential access

| | |
|---|---|
| **ID** | SC200-06 |
| **Severity** | **High** |
| **Rule type** | Scheduled analytics rule |
| **Status** | Authored, live witness pending (see below) |
| **Data source** | `DeviceEvents` (Defender for Endpoint, via Defender XDR connector) |
| **MITRE tactic** | Credential Access |
| **MITRE technique** | [T1003.001, OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |

## What it catches

A process opening a handle to **`lsass.exe`**, the memory that holds cached credentials and the
first thing an attacker reaches for after landing on a host (Mimikatz, comsvcs.dll minidump,
procdump, and friends). This is the endpoint counterpart to the AzureActivity control-plane
rules: same Detection-as-Code pipeline, different telemetry plane.

## Detection logic

Runs every 15 minutes over a 1-hour lookback. `DeviceEvents` reaches the workspace through the
Defender XDR connector. Known Defender components that legitimately touch LSASS are excluded so
the rule does not fire on the AV/EDR stack itself.

```kql
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "SenseIR.exe")
| summarize AccessCount = count(), Tools = make_set(InitiatingProcessFileName, 10)
    by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 5m)
| where AccessCount >= 1
```

## How to trigger (simulation)

On the onboarded host, a benign, self-reverted handle-open against LSASS (for example a
`procdump`-style read, run once and the dump file deleted immediately). The point is the
`OpenProcessApiCall` against `lsass.exe`, not a real credential theft.

## Expected result

**Pending live witness.** `Device*` telemetry began flowing when `soc-sensor-01` onboarded
(2026-06-07). The controlled trigger and its incident screenshot are added once the endpoint has
reported a full cycle. This card does not claim a firing that has not been captured yet, the same
honesty bar the other cards hold.

## Tuning notes

**Threshold rationale.** A single `OpenProcessApiCall` against LSASS from a non-Defender process
is already worth surfacing on a server that should have almost no LSASS access. On a busy
workstation fleet this would be noisier and would move to a per-process allowlist plus a count
threshold.

**Known false positives.** Backup agents, EDR/AV other than the Defender stack already excluded,
and some management tooling read LSASS legitimately. Extend the `InitiatingProcessFileName`
exclusion or pivot on `InitiatingProcessCommandLine` for the dump-specific argument patterns.

**Tightening trade-off.** Filtering to known dumping tools (`procdump`, `rundll32` with
`comsvcs.dll, MiniDump`, `taskmgr` create-dump) cuts noise but misses a custom or renamed
dumper; keeping the broad `OpenProcessApiCall` catch is the safer default on a low-access server.

**Evasion.** Direct syscalls or a signed-but-abused process can evade the API-call telemetry;
pair this with the companion hunt [`endpoint-lsass-access.kql`](../kql/hunting/endpoint-lsass-access.kql)
and with `AlertEvidence` correlation in [`endpoint-vulnerable-asset-under-alert.kql`](../kql/hunting/endpoint-vulnerable-asset-under-alert.kql).

**Validation.** ATT&CK [T1003.001](https://attack.mitre.org/techniques/T1003/001/), OS Credential
Dumping: LSASS Memory. Architecture and data flow: [docs/07](../docs/07-endpoint-vulnerability-management.md).
