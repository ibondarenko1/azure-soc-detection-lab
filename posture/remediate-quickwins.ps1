# remediate-quickwins.ps1
# Tier-1 remediations: zero blast radius, additive, reversible. Sets a security contact and turns
# on high-severity alert notifications, which closes three Defender for Cloud recommendations:
#   - Subscriptions should have a contact email address for security issues
#   - Email notification for high severity alerts should be enabled
#   - Email notification to subscription owner for high severity alerts should be enabled
#
# Higher-blast-radius items (storage shared-key, VNet rules, encryption at host, enabling paid
# Defender plans) are NOT done here; see docs/10-posture-remediation.md for the ordered plan.
#
# Default is dry-run: it prints the call and changes nothing. Pass -Apply to execute.
# Prereq: az login to the tenant.

[CmdletBinding()]
param(
    [string] $SubscriptionId = (az account show --query id -o tsv),
    [string] $ContactEmail   = (az account show --query user.name -o tsv),
    [switch] $Apply
)

$ErrorActionPreference = "Stop"
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts/default?api-version=2020-01-01-preview"
$body = @{
    properties = @{
        emails              = $ContactEmail
        alertNotifications  = @{ state = "On"; minimalSeverity = "High" }
        notificationsByRole = @{ state = "On"; roles = @("Owner") }
    }
} | ConvertTo-Json -Depth 5

Write-Host "Security contact + high-severity alert notifications"
Write-Host "  contact: $ContactEmail"
Write-Host "  PUT $uri"

if (-not $Apply) {
    Write-Host ""
    Write-Host "DRY-RUN. Body that would be sent:"
    Write-Host $body
    Write-Host ""
    Write-Host "Re-run with -Apply to execute. Reverse later by deleting the securityContacts/default resource."
    return
}

$token = az account get-access-token --resource "https://management.azure.com" --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$resp = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $body
Write-Host "Applied. Contact resource state: $($resp.properties.alertNotifications.state) / role-notify: $($resp.properties.notificationsByRole.state)"
Write-Host "Secure Score reflects this on the next recalculation (24-72h). Re-run collect-posture.ps1 -Label after then."
