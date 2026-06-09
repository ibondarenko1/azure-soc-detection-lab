#!/usr/bin/env bash
# Benign stream: legitimate actions that map to each rule's SILENT case. None should raise an
# incident. Run before attacks.sh so the benign deploy precedes any role grant (keeps DET-007 silent).
set -uo pipefail
RG=sc200-lab; LOC=eastus
STATE="$(dirname "$0")/.harness-state"
ts=$(date +%H%M%S)
log(){ echo "[benign $(date -u +%H:%M:%S)] $*"; }
track(){ echo "$1" >> "$STATE"; }

# B1 - DET-005 silent: an allow-listed owner (in soc-deploy-owners) deploys storage.
sa="valbnsa$ts"
az storage account create -n "$sa" -g $RG -l $LOC --sku Standard_LRS --min-tls-version TLS1_2 \
  --allow-blob-public-access false -o none && { track "sa:$sa"; log "owner deploy $sa -> DET-005 must stay silent"; }

# B1 also covers DET-007 silent: this deploy has NO preceding role grant by the same caller.
log "owner deploy has no preceding grant -> DET-007 must stay silent"

# B2 - DET-004 silent: sub-threshold deletes (3 < 5 in 5 min) using free NSGs.
for i in 1 2 3; do n="val-bn-nsg-$ts-$i"; az network nsg create -g $RG -n "$n" -l $LOC -o none && track "nsg:$n"; done
for i in 1 2 3; do az network nsg delete -g $RG -n "val-bn-nsg-$ts-$i" -o none; done
log "3 deletes in <5 min -> DET-004 must stay silent (threshold is >=5)"

echo "benign-batch-ts=$ts"
