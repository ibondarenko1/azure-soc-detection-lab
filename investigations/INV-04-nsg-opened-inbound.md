# INV-04, NSG rule change exposed inbound from Any (High)

> Investigation write-up for the incident raised by [DET-009](../detections/DET-009-nsg-opened-inbound-any.md). Live witness: a controlled change opened an NSG inbound from Any, and the content-level rule correlated the change event to the ARG-sourced posture.

| | |
|---|---|
| **Detection** | DET-009, NSG rule change exposed inbound from Any |
| **Severity** | High |
| **MITRE** | Defense Evasion → [T1562.007 Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) |
| **NSG** | `nsg-det9-witness` (rule `open-rdp`, Allow Inbound 3389 from `*`) |
| **Caller / IP** | `ievgen@<redacted-tenant>` / `70.9.97.251` |

## 1. Triage

- **What fired:** a successful `Microsoft.Network/networkSecurityGroups/securityRules/write` landed on an NSG that Azure Resource Graph reports as **open inbound from Any** on a management port (RDP/3389).
- **Why this and not DET-002:** DET-002 fires on any NSG change but cannot read the rule body from AzureActivity. DET-009 joins the change event to the `soc-open-mgmt-nsg-rules` watchlist (refreshed from ARG), so it fires only when the change actually left the NSG exposed, the high-fidelity signal.
- **Live witness query result:**
  ```
  Caller=ievgen@<redacted-tenant>  CallerIp=70.9.97.251
  NsgName=nsg-det9-witness  Operation=NETWORKSECURITYGROUPS/SECURITYRULES/WRITE
  ```

## 2. How it was generated

A controlled change created `nsg-det9-witness/open-rdp` (Allow Inbound, source `*`, port 3389). The
posture path then ran: Azure Resource Graph returned the open rule, the `nsg-posture-watchlist`
refresh wrote it to `soc-open-mgmt-nsg-rules`, and DET-009's query joined the AzureActivity change
event to that watchlist and returned the correlated row.

## 3. Scope

- Single NSG (`nsg-det9-witness`); one caller; one source IP.
- The rule was **not** attached to a production subnet (controlled test); in production the same
  pattern is an internet-exposed management port.

## 4. Assessment

- **Determination:** true positive (controlled). The detection correctly surfaced a change that
  resulted in inbound Allow-from-Any on a management port, which DET-002 alone could not confirm.

## 5. Response

1. Inspect the rule (it is in the watchlist row: NSG, rule name, source, ports).
2. If the exposure is unintended, revert the rule and investigate the caller and source IP.
3. Confirm no NIC/subnet is bound to the NSG while it is open.

## 6. Lessons / tuning

- The ARG posture watchlist brings the rule **content** AzureActivity does not carry into the
  workspace, turning DET-002's "something changed" into DET-009's "it is now open".
- Tune the ARG query to management ports or to exclude documented jump-host NSGs.

## Cleanup

The witness NSG (`nsg-det9-witness`) and the controlled rule were removed after capture; the
watchlist reset to its no-open-rules baseline.
