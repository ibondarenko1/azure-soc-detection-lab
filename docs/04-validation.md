# Validation, Atomic Red Team mapping + regression

Detections are validated against **standardized ATT&CK techniques**, not ad-hoc "I made it fire." Each rule maps to an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) technique, and the `az`-based triggers in [`simulations/trigger-playbook.md`](../simulations/trigger-playbook.md) are the atomic-aligned executions of those techniques (control-plane equivalents that need no agent on a host).

## Mapping

| Rule | ATT&CK | Atomic technique | Trigger (atomic-aligned) |
|------|--------|------------------|--------------------------|
| DET-002 NSG rule modified | T1562.007 | [Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) | create + delete an NSG inbound rule |
| DET-003 RBAC role assignment | T1098.003 | [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) | assign + remove an Azure RBAC role |
| DET-004 Mass resource deletion | T1485 | [Data Destruction](https://attack.mitre.org/techniques/T1485/) | bulk-delete ≥5 resources |
| DET-001 Failed-ops spike | T1087 / T1526 | Account / Cloud Service Discovery (**heuristic**, failed-permission probing, no exact 1:1 atomic) | ≥10 denied control-plane ops |
| DET-005 Non-owner deployment | T1098 | Account Manipulation (**loose**, resource-creation persistence, no exact atomic) | deploy a resource as a non-owner SP |

Honesty note: DET-001 and DET-005 are detection **heuristics** without a clean 1:1 atomic; that is documented rather than papered over.

## Regression

[`cicd/regression-test.py`](../cicd/regression-test.py) is the automated proof that the deployed rules still fire. For each covered rule it:

1. runs the atomic-aligned trigger (`az`),
2. polls the Microsoft Sentinel **incidents API** for a new incident matching the rule, within the rule's `queryFrequency` + an ingestion budget,
3. asserts the incident appeared, **exit non-zero on any miss** (so the pipeline catches a broken rule),

then cleans up the resources it creates.

**Least privilege by design.** Automated regression covers only the detections whose triggers need **Contributor on the workspace resource group**, `DET-002 (NSG)` and `DET-004 (mass deletion)`. The CI identity therefore needs **no role-assignment (User Access Administrator) and no subscription-scope rights**. `DET-003 (RBAC)`, `DET-001 (failed-ops)` and `DET-005 (non-owner)` would require a more privileged or second identity, so they are validated **manually** via the trigger-playbook rather than handing the pipeline standing privilege it doesn't need.

[`.github/workflows/detection-regression.yml`](../.github/workflows/detection-regression.yml) runs it on a weekly schedule and on manual dispatch (OIDC, read+contributor on `sc200-lab`), and logs exactly what it asserted and any miss, no silent pass.

### Run locally
```bash
az login
python cicd/regression-test.py            # triggers, asserts, cleans up
```
