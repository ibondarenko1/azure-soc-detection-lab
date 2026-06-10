# Posture snapshots

Machine-readable posture baselines for the remediation loop in
[docs/10-posture-remediation.md](../docs/10-posture-remediation.md). The point of keeping the
numbers in JSON, not only in screenshots, is a reproducible before/after delta: re-run the
collector after remediation and diff two files.

## What gets collected

`collect-posture.ps1` reads the **Defender for Cloud** posture for the subscription over the ARM
`Microsoft.Security` provider (read-only GETs):

| Data | Endpoint |
|------|----------|
| Secure Score (overall) | `secureScores?api-version=2020-01-01` |
| Score controls (the recommendations behind the score) | `secureScores/ascScore/secureScoreControls?...&$expand=definition` |
| Plan pricing tiers (Free vs Standard) | `pricings?api-version=2024-01-01` |
| Assessment summary | `assessments?api-version=2020-01-01` |

The control breakdown is the useful part: per control it records points earned vs available and how
many resources are healthy vs unhealthy, so the gap is explicit.

This collector covers the **Defender for Cloud** Secure Score (Azure resource posture). The separate
**Microsoft 365 Secure Score** (identity, apps, data, device) lives behind Graph
`security/secureScores`, which the az CLI token is not consented for, so that score is captured from
the portal as a screenshot rather than pulled here. The two scores are different numbers measuring
different planes; the doc keeps them apart.

## Run it

```powershell
az login                       # to the tenant; az account show should resolve the subscription
cd posture
.\collect-posture.ps1          # writes snapshots/<UTC-date>-baseline.json
# after remediation has re-scored (24-72h):
.\collect-posture.ps1 -Label after
```

## Redaction

The snapshot carries no subscription id, tenant id, resource id, or UPN. Only the score, per-control
aggregate counts, and plan tiers. The script writes those fields and nothing else, so the output is
safe to commit. Check a new snapshot before committing anyway:

```powershell
Select-String -Path snapshots\*.json -Pattern '@|[0-9a-f]{8}-[0-9a-f]{4}'   # expect no matches
```

## Files

- `collect-posture.ps1` - the collector.
- `remediate-quickwins.ps1` - the Tier-1 safe remediations (security contact + alert notifications),
  ready to run; see the doc for the full ordered plan and the higher-blast-radius items.
- `snapshots/<date>-baseline.json` - the before baseline.
- `snapshots/<date>-after.json` - filled once the tenant re-scores after remediation.
