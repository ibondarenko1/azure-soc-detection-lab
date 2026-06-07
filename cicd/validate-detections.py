#!/usr/bin/env python3
"""Validate detection rule YAML before deploy (PR gate).

Always: schema / required-field / value checks (no Azure access needed).
Optional: KQL smoke check — set SENTINEL_WORKSPACE_GUID (Log Analytics customerId) and be
`az` logged in; each query is run with `| take 0` to confirm it parses.
"""
import os
import sys
import glob
import re
import subprocess

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "detections", "rules")
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SEVERITIES = {"Informational", "Low", "Medium", "High"}
REQUIRED = ["id", "name", "severity", "query", "queryFrequency", "queryPeriod",
            "tactics", "relevantTechniques"]
ISO8601 = re.compile(r"^PT(\d+H)?(\d+M)?(\d+S)?$")


def check_rule(path):
    errs = []
    try:
        r = yaml.safe_load(open(path, encoding="utf-8"))
    except Exception as e:
        return [f"YAML parse error: {e}"]
    for k in REQUIRED:
        if not r.get(k):
            errs.append(f"missing required field: {k}")
    if r.get("id") and not GUID.match(str(r["id"])):
        errs.append(f"id is not a GUID: {r['id']}")
    if r.get("severity") and r["severity"] not in SEVERITIES:
        errs.append(f"invalid severity: {r['severity']}")
    for f in ("queryFrequency", "queryPeriod"):
        if r.get(f) and not ISO8601.match(str(r[f])):
            errs.append(f"{f} not ISO8601 duration: {r[f]}")
    if r.get("relevantTechniques"):
        for t in r["relevantTechniques"]:
            if not re.match(r"^T\d{4}(\.\d{3})?$", str(t)):
                errs.append(f"bad technique id: {t}")
    return errs, r


def kql_smoke(query, ws_guid):
    out = subprocess.run(
        ["az", "monitor", "log-analytics", "query", "--workspace", ws_guid,
         "--analytics-query", query.strip() + "\n| take 0", "-o", "none"],
        capture_output=True, text=True, shell=(os.name == "nt"))
    return out.returncode == 0, (out.stderr.strip() or out.stdout.strip())


def main():
    ws_guid = os.environ.get("SENTINEL_WORKSPACE_GUID")
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.yaml")))
    if not files:
        sys.exit("no rule YAML found")
    total = 0
    for path in files:
        name = os.path.basename(path)
        res = check_rule(path)
        errs = res if isinstance(res, list) else res[0]
        rule = None if isinstance(res, list) else res[1]
        if not errs and ws_guid and rule:
            ok, msg = kql_smoke(rule["query"], ws_guid)
            if not ok:
                errs.append(f"KQL parse failed: {msg}")
        if errs:
            total += len(errs)
            print(f"FAIL {name}")
            for e in errs:
                print(f"   - {e}")
        else:
            extra = " (+KQL ok)" if ws_guid else ""
            print(f"OK   {name}{extra}")
    if total:
        sys.exit(f"\n{total} validation error(s)")
    print(f"\nAll {len(files)} rule(s) valid.")


if __name__ == "__main__":
    main()
