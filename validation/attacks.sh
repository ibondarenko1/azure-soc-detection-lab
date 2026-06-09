#!/usr/bin/env bash
# Attack stream: malicious variants that map to each rule's FIRE case. Each must produce a detection.
set -uo pipefail
RG=sc200-lab; LOC=eastus
SUB=$(az account show --query id -o tsv)
OID=$(az ad signed-in-user show --query id -o tsv)
READER=acdd72a7-3385-48ef-bd42-f606fba81ae7
STATE="$(dirname "$0")/.harness-state"
ts=$(date +%H%M%S)
log(){ echo "[attack $(date -u +%H:%M:%S)] $*"; }
track(){ echo "$1" >> "$STATE"; }

# A1 - DET-004 fire: mass delete >=5 in 5 min (6 NSGs created then deleted).
for i in 1 2 3 4 5 6; do az network nsg create -g $RG -n "val-atk-nsg-$ts-$i" -l $LOC -o none; done
for i in 1 2 3 4 5 6; do az network nsg delete -g $RG -n "val-atk-nsg-$ts-$i" -o none; done
log "6 deletes in <5 min -> DET-004 must fire"

# A2 - DET-003 fire: a role grant by a non-automation caller (not in soc-automation-principals).
RA=$(python -c "import uuid;print(uuid.uuid4())")
az rest --method put \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Authorization/roleAssignments/$RA?api-version=2022-04-01" \
  --headers "Content-Type=application/json" \
  --body "{\"properties\":{\"roleDefinitionId\":\"/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/$READER\",\"principalId\":\"$OID\",\"principalType\":\"User\"}}" \
  -o none && track "ra:$RA"
log "role grant -> DET-003 must fire"

# A3 - DET-007 fire: a deploy AFTER the grant by the same principal, inside the 30-min window.
sleep 5
sa="valatksa$ts"
az storage account create -n "$sa" -g $RG -l $LOC --sku Standard_LRS --min-tls-version TLS1_2 \
  --allow-blob-public-access false -o none && track "sa:$sa"
log "deploy after grant -> DET-007 must fire (grant then deploy, same principal)"

# A4 - DET-002 + DET-009 fire: an NSG rule opening inbound from Any on a management port.
nsg="val-atk-open-$ts"
az network nsg create -g $RG -n "$nsg" -l $LOC -o none && track "nsg:$nsg"
az network nsg rule create -g $RG --nsg-name "$nsg" -n open-rdp --priority 100 --access Allow \
  --direction Inbound --protocol Tcp --source-address-prefixes '*' --destination-port-ranges 3389 -o none
log "NSG opened inbound Any -> DET-002 must fire; DET-009 fires after the ARG watchlist refresh (measure.py)"

echo "attack-batch-ts=$ts open-nsg=$nsg"
