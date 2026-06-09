# SOAR + AI playbook, Security Copilot mass-deletion triage

Extends the loop **detect → respond → AI-investigate** on the highest-severity detection
(DET-004). When a Mass-resource-deletion incident is created, a Sentinel **automation
rule** runs this **Logic App**, which invokes a **Microsoft Security Copilot promptbook**
([`DET-004 Mass Deletion Triage`](../../copilot/promptbooks/det-004-mass-deletion-triage.yaml))
and posts the AI investigation summary back as an **incident comment** (caller + deleted
resources, blast radius, prioritized containment, and a KQL hunt).

It runs **alongside** the deterministic [`mass-deletion-response`](../mass-deletion-response)
playbook (which posts fixed containment guidance): one is rules-based, this one is AI-assisted.

> **💲 Cost:** the Security Copilot step requires **provisioned capacity (≥ 1 SCU)**, billed
> **$4 / SCU / hour in whole-hour blocks (1-hour minimum)**. This setup provisions **1 SCU for a
> single ~1-hour window** to demo, then **deletes the capacity** (permanent, stops billing).
> Demo cost ≈ **$4**. Full runbook + teardown: [`../../docs/06-security-copilot.md`](../../docs/06-security-copilot.md).

**No secrets, no stored credentials.** The incident-comment write is a direct **HTTP call to
the ARM API** authenticated by the playbook's own **system-assigned managed identity** (granted
**Microsoft Sentinel Responder** on the workspace RG). The `azuresentinel` connection exists only
for the incident trigger; the `securitycopilot` connection authenticates to Security Copilot.

## Files
- `azuredeploy.json`, Logic App + `azuresentinel` (MI) + `securitycopilot` connections (ARM, no hardcoded IDs).
- `automation-rule.json`, automation rule body (placeholdered; binds the playbook to DET-004, `order=2`).

## Two designer-finalized bindings
The durable parts of the template (trigger, connections, managed-identity comment write) are
exact. Two Security-Copilot-connector specifics are confirmed in the Logic App designer because
their operation path/output schema is connector-version dependent (also noted in the template's
`metadata.designerBindings`):
1. **Copilot action**, bind `Run_Security_Copilot_promptbook` to the connector operation
   **"Submit a Security Copilot promptbook"** and select the `DET-004 Mass Deletion Triage` promptbook.
2. **Output field**, bind the promptbook **evaluation result/summary** output into
   `Post_Copilot_summary_as_comment` (template reads `body(...)?['summary']`).

## Deploy

```bash
# 1) playbook (Logic App + connections)
az deployment group create -g <RG> -n pb-copilot-triage \
  --template-file azuredeploy.json --query properties.outputs

# 2) authorize the securitycopilot connection (one-time OAuth consent) in the portal,
#    then grant the playbook MI rights to comment, and let Sentinel run playbooks
az role assignment create --assignee-object-id <playbookPrincipalId> --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" --scope /subscriptions/<SUB>/resourceGroups/<RG>
az role assignment create --assignee-object-id $(az ad sp show --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 --query id -o tsv) \
  --assignee-principal-type ServicePrincipal --role "Microsoft Sentinel Automation Contributor" \
  --scope /subscriptions/<SUB>/resourceGroups/<RG>

# 3) automation rule (substitute placeholders in automation-rule.json first)
az rest --method put --body @automation-rule.json \
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE>/providers/Microsoft.SecurityInsights/automationRules/$(python -c 'import uuid;print(uuid.uuid4())')?api-version=2025-09-01"
```

The `98785600-1bb7-4fb9-b9fa-19afe2c8a360` app is the fixed **Azure Security Insights** service
principal, it needs *Automation Contributor* so automation rules may run playbooks.

> The Logic App **deploys and the Sentinel trigger fires without any SCU**; only the Copilot
> action stays pending until capacity is provisioned. Rehearse the trigger + comment path for
> free, then provision 1 SCU only for the live capture.
