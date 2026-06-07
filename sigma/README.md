# Sigma conversions

The three cleanest AzureActivity detections, expressed in **[Sigma](https://sigmahq.io/)**, 
the vendor-neutral detection format. Same logic, portable to any SIEM (Splunk, Elastic,
QRadar, …) via `sigma convert`, not locked to Microsoft KQL.

| File | Source rule | ATT&CK | Notes |
|------|-------------|--------|-------|
| `SC200-02-nsg-rule-modified.yml` | SC200-02 | T1562.007 | simple selection |
| `SC200-03-rbac-role-assignment.yml` | SC200-03 | T1098.003 | simple selection |
| `SC200-04-mass-resource-deletion.yml` | SC200-04 | T1485 | **Sigma correlation** (`event_count` ≥ 5 / 5m by caller) |

The mass-deletion rule uses a Sigma **correlation** (base event + `event_count`), the
portable equivalent of the KQL `summarize … | where DeleteCount >= 5`.

## Validate / convert

```bash
pipx install sigma-cli && sigma plugin install azure
sigma check sigma/*.yml
sigma convert -t kusto -p azure_monitor sigma/SC200-02-nsg-rule-modified.yml   # back to KQL
sigma convert -t splunk sigma/SC200-02-nsg-rule-modified.yml                    # or SPL
```

Field names follow the Sigma `azure/activitylogs` taxonomy (`operationName`,
`properties.status`, `caller`); the chosen `azure` pipeline maps them to each backend.
