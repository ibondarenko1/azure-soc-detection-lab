# collect-posture.ps1
# Pulls the Defender for Cloud posture for the subscription via ARM REST and writes a
# redacted JSON snapshot used as the before/after baseline for docs/10-posture-remediation.md.
#
# What it reads (read-only GETs, same endpoints the audit tooling uses):
#   Secure Score          .../Microsoft.Security/secureScores?api-version=2020-01-01
#   Secure Score controls .../Microsoft.Security/secureScores/ascScore/secureScoreControls?...&$expand=definition
#   Pricing tiers         .../Microsoft.Security/pricings?api-version=2024-01-01
#   Assessments           .../Microsoft.Security/assessments?api-version=2020-01-01
#
# The control breakdown is the recommendation list behind the score: per control, the points
# earned vs available and how many resources are healthy vs unhealthy.
#
# Redaction: the output carries NO subscription id, tenant id, resource id, or UPN. Only the
# score, the per-control aggregate counts, and plan tiers. Safe to commit to a public repo.
#
# Prereq: az login to the tenant first (az account show should resolve to the right subscription).
# Usage:
#   .\collect-posture.ps1                 # writes snapshots/<UTC-date>-baseline.json
#   .\collect-posture.ps1 -Label after    # writes snapshots/<UTC-date>-after.json

[CmdletBinding()]
param(
    [string] $SubscriptionId = (az account show --query id -o tsv),
    [string] $Label = "baseline",
    [string] $OutDir = (Join-Path $PSScriptRoot "snapshots")
)

$ErrorActionPreference = "Stop"
$base = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security"

# Use a bearer token + Invoke-RestMethod rather than `az rest`: az.cmd re-parses the `&` in the
# query string under cmd.exe and drops the $expand parameter.
$token = az account get-access-token --resource "https://management.azure.com" --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $token" }
function Get-Arm($uri) { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }

# Secure Score (overall)
$score = (Get-Arm "$base/secureScores?api-version=2020-01-01").value |
    Where-Object { $_.name -eq "ascScore" } | Select-Object -First 1

# Per-control breakdown (the recommendations behind the score)
$controlsRaw = (Get-Arm "$base/secureScores/ascScore/secureScoreControls?api-version=2020-01-01&`$expand=definition").value
$controls = $controlsRaw | ForEach-Object {
    [ordered]@{
        control          = $_.properties.displayName
        current          = [math]::Round($_.properties.score.current, 2)
        max              = $_.properties.score.max
        percent          = [math]::Round($_.properties.score.percentage * 100, 0)
        unhealthy        = $_.properties.unhealthyResourceCount
        healthy          = $_.properties.healthyResourceCount
        notApplicable    = $_.properties.notApplicableResourceCount
    }
} | Sort-Object { $_.percent }

# Plan tiers
$pricings = (Get-Arm "$base/pricings?api-version=2024-01-01").value | ForEach-Object {
    [ordered]@{ plan = $_.name; tier = $_.properties.pricingTier }
}

# Assessments (kept for completeness; on a free-tier lab this is commonly empty and the
# control breakdown above is the recommendation source)
$assessments = (Get-Arm "$base/assessments?api-version=2020-01-01").value
$unhealthy = @($assessments | Where-Object { $_.properties.status.code -eq "Unhealthy" })

$snapshot = [ordered]@{
    label       = $Label
    capturedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    source      = "Microsoft Defender for Cloud (ARM Microsoft.Security), subscription redacted"
    secureScore = [ordered]@{
        current = [math]::Round($score.properties.score.current, 2)
        max     = $score.properties.score.max
        percent = [math]::Round($score.properties.score.percentage * 100, 2)
        weight  = $score.properties.weight
    }
    controls    = $controls
    plans       = [ordered]@{
        standard = @($pricings | Where-Object { $_.tier -eq "Standard" } | ForEach-Object { $_.plan })
        free     = @($pricings | Where-Object { $_.tier -eq "Free" } | ForEach-Object { $_.plan })
    }
    assessments = [ordered]@{ total = $assessments.Count; unhealthy = $unhealthy.Count }
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$outPath = Join-Path $OutDir "$date-$Label.json"
$snapshot | ConvertTo-Json -Depth 6 | Set-Content -Path $outPath -Encoding utf8

Write-Host "Secure Score: $($snapshot.secureScore.current)/$($snapshot.secureScore.max) ($($snapshot.secureScore.percent)%)"
Write-Host "Controls below 100%: $(@($controls | Where-Object { $_.percent -lt 100 }).Count)"
Write-Host "Snapshot written: $outPath"
