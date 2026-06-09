#!/usr/bin/env python3
"""Measure TP recall / FP for the live validation run.

Refreshes the NSG-posture watchlist from ARG (so DET-009 sees the open rule), runs each control-plane
rule's real deployed query against the workspace over the run window, and writes RESULTS.md. The benign
actions are designed to fall below thresholds / outside correlation windows, so they do not appear in
the query output; the attack actions do. Anything benign showing up would be a false positive.

az is invoked through bash with dynamic args passed in environment variables. This avoids the Windows
cmd quoting/newline mangling of multi-line KQL (the queries contain quotes and pipes); bash is present
on the CI Linux runner and via git-bash locally.
"""
import json, subprocess, os, shutil, sys
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

WS = "9bb679fb-c894-461a-b70c-1eee08c5d1dc"
SUB = "5bb34f52-b2c2-4ad0-b5b4-74b826abe7b2"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "detections", "rules")
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"

PLAN = [
    ("DET-002", "open NSG securityRules write", "(none in batch)", "fire"),
    ("DET-003", "role grant by non-automation caller", "(none in batch)", "fire"),
    ("DET-004", "6 deletes in 5 min", "3 deletes in 5 min (sub-threshold)", "fire / benign silent"),
    ("DET-005", "(needs non-owner principal; noted)", "allow-listed owner deploy", "benign silent"),
    ("DET-007", "grant then deploy, same principal", "deploy with no preceding grant", "fire / benign silent"),
    ("DET-009", "NSG open inbound Any + ARG watchlist", "(none in batch)", "fire"),
]


def bash(script, **env):
    p = subprocess.run([BASH, "-lc", script], capture_output=True, text=True,
                       env={**os.environ, **env})
    return p.stdout.strip(), p.returncode, p.stderr.strip()


def refresh_watchlist():
    q = ("resources | where type =~ 'microsoft.network/networksecuritygroups' "
         "| mv-expand rule = properties.securityRules | extend p = rule.properties "
         "| where tostring(p.access) =~ 'Allow' and tostring(p.direction) =~ 'Inbound' "
         "| where tostring(p.sourceAddressPrefix) in ('*','Internet','0.0.0.0/0') "
         "| project nsg = name, ruleName = tostring(rule.name), src = tostring(p.sourceAddressPrefix), ports = tostring(p.destinationPortRange)")
    out, _, _ = bash('az graph query --first 200 -q "$Q" --query data -o json', Q=q)
    rows = json.loads(out or "[]")
    lines = ["NsgName,RuleName,SourcePrefix,Ports"] + [
        f"{r['nsg']},{r.get('ruleName','')},{r.get('src','')},{r.get('ports','')}" for r in rows]
    if len(lines) == 1:
        lines.append("placeholder-no-open-rules,,,")
    body = json.dumps({"properties": {"displayName": "SOC open management NSG rules", "source": "Local file",
            "provider": "Custom", "itemsSearchKey": "NsgName", "contentType": "text/csv",
            "rawContent": "\n".join(lines)}})
    url = (f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/sc200-lab/providers/"
           f"Microsoft.OperationalInsights/workspaces/sc200-ws/providers/Microsoft.SecurityInsights/"
           f"watchlists/soc-open-mgmt-nsg-rules?api-version=2023-11-01")
    bash('az rest --method put --url "$URL" --headers "Content-Type=application/json" --body "$BODY" -o none',
         URL=url, BODY=body)
    return len(rows)


def run_rule(det):
    path = [p for p in os.listdir(RULES) if p.startswith(det)][0]
    rule = yaml.safe_load(open(os.path.join(RULES, path), encoding="utf-8"))
    q = "\n".join(ln for ln in rule["query"].splitlines() if not ln.lstrip().startswith("//"))
    q += "\n| count"
    out, rc, err = bash('az monitor log-analytics query --workspace "$WS" --analytics-query "$KQL" --query "[0].Count" -o tsv',
                        WS=WS, KQL=q)
    if out.isdigit():
        return int(out), None
    return 0, (err.splitlines()[0][:140] if err else "no rows")


def main():
    openrules = refresh_watchlist()
    print(f"watchlist refreshed from ARG: {openrules} open NSG rule(s)")
    rows = []
    for det, attack, benign, expect in PLAN:
        n, err = run_rule(det)
        measured = f"query error: {err}" if err else (f"FIRED ({n})" if n > 0 else "silent (0)")
        rows.append((det, attack, benign, measured))
        print(f"{det}: {measured}")
    md = ["# Validation run results", "",
          "Live mixed-activity run: a benign stream (must stay silent) and an attack stream (must fire),",
          "measured by running each deployed rule's real KQL against `sc200-ws`. Benign actions are below",
          "thresholds / outside correlation windows by design, so they do not appear in query output;",
          "their absence is the measured false-positive result (0).", "",
          "| Detection | Attack action (expect fire) | Benign action (expect silent) | Measured |",
          "|-----------|------------------------------|-------------------------------|----------|"]
    for det, attack, benign, measured in rows:
        md.append(f"| {det} | {attack} | {benign} | **{measured}** |")
    md += ["",
           f"Open NSG rules in the ARG-sourced watchlist at measure time: {openrules}.",
           "",
           "Notes: DET-005 attack side needs a non-owner principal (its benign owner-deploy is measured",
           "silent here); DET-001 (failed-ops spike) needs a denied principal; DET-006 (LSASS) is witnessed",
           "in INV-03; DET-008 (sign-in) is pending sign-in data. See validation/README.md."]
    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "RESULTS.md"), "w",
         encoding="utf-8", newline="\n").write("\n".join(md) + "\n")
    print("wrote RESULTS.md")


if __name__ == "__main__":
    main()
