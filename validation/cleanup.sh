#!/usr/bin/env bash
# Tear down everything the harness created (tracked in .harness-state) and reset the watchlist.
set -uo pipefail
RG=sc200-lab
SUB=$(az account show --query id -o tsv)
STATE="$(dirname "$0")/.harness-state"
[ -f "$STATE" ] || { echo "no .harness-state, nothing to clean"; }
log(){ echo "[cleanup] $*"; }

if [ -f "$STATE" ]; then
  while IFS= read -r line; do
    kind="${line%%:*}"; val="${line#*:}"
    case "$kind" in
      sa)  az storage account delete -n "$val" -g $RG --yes -o none 2>/dev/null && log "deleted storage $val" ;;
      nsg) az network nsg delete -n "$val" -g $RG -o none 2>/dev/null && log "deleted nsg $val" ;;
      ra)  az rest --method delete --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Authorization/roleAssignments/$val?api-version=2022-04-01" -o none 2>/dev/null && log "removed role assignment $val" ;;
    esac
  done < "$STATE"
  rm -f "$STATE"
fi

# Reset the NSG-posture watchlist to its no-open-rules baseline.
WLURL="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/sc200-ws/providers/Microsoft.SecurityInsights/watchlists/soc-open-mgmt-nsg-rules?api-version=2023-11-01"
az rest --method delete --url "$WLURL" -o none 2>/dev/null
sleep 6
BODY='{"properties":{"displayName":"SOC open management NSG rules","source":"Local file","provider":"Custom","itemsSearchKey":"NsgName","contentType":"text/csv","rawContent":"NsgName,RuleName,SourcePrefix,Ports\nplaceholder-no-open-rules,,,"}}'
az rest --method put --url "$WLURL" --headers "Content-Type=application/json" --body "$BODY" -o none 2>/dev/null && log "watchlist reset to baseline"
log "done"
