#!/usr/bin/env python3
"""Unit-test the detection KQL against synthetic AzureActivity logs.

Runs each rule's REAL query against a local Kusto emulator (kustainer) over
synthetic fixtures, asserting it FIRES on malicious data and stays SILENT on
benign data. No live tenant required, anyone can fork and run this.

Env: KUSTO_URI (default http://localhost:8080), KUSTO_DB (default NetDefaultDB).
"""
import os
import sys
import re
import glob
import json
import datetime
import urllib.request

KUSTO = os.environ.get("KUSTO_URI", "http://localhost:8080").rstrip("/")
DB = os.environ.get("KUSTO_DB", "NetDefaultDB")
RULES = os.path.join(os.path.dirname(__file__), "..", "detections", "rules")
FIX = os.path.join(os.path.dirname(__file__), "fixtures")
COLS = ["TimeGenerated", "ActivityStatusValue", "Caller", "OperationNameValue",
        "ResourceProviderValue", "ResourceId", "Properties_d"]
SCHEMA = ("TimeGenerated:datetime, ActivityStatusValue:string, Caller:string, "
          "OperationNameValue:string, ResourceProviderValue:string, ResourceId:string, "
          "Properties_d:dynamic")

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")


def _post(path, payload):
    req = urllib.request.Request(KUSTO + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def mgmt(cmd):
    _post("/v1/rest/mgmt", {"db": DB, "csl": cmd})


def query_count(csl):
    res = _post("/v1/rest/query", {"db": DB, "csl": csl + "\n| count"})
    return res["Tables"][0]["Rows"][0][0]


def lit(col, val, base):
    if col == "TimeGenerated":
        ts = base - datetime.timedelta(minutes=int(val or 0))
        return f"datetime({ts.strftime('%Y-%m-%dT%H:%M:%S')}Z)"
    if col == "Properties_d":
        return f"dynamic({json.dumps(val or {})})"
    s = str(val if val is not None else "").replace('"', '\\"')
    return f'"{s}"'


def load_table(events):
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
    rows = []
    for e in events:
        rows.append(", ".join(lit(c, e.get("minutesAgo") if c == "TimeGenerated" else e.get(c), base) for c in COLS))
    body = ",\n".join(rows) if rows else ""
    mgmt(f".set-or-replace AzureActivity <| datatable({SCHEMA})[\n{body}\n]")


def main():
    failures = 0
    total = 0
    for path in sorted(glob.glob(os.path.join(RULES, "*.yaml"))):
        rule = yaml.safe_load(open(path, encoding="utf-8"))
        m = re.match(r"(DET-\d+)", os.path.basename(path))
        fx_path = os.path.join(FIX, m.group(1) + ".json")
        if not os.path.exists(fx_path):
            print(f"SKIP {rule['name']}, no fixture"); continue
        fx = json.load(open(fx_path, encoding="utf-8"))
        for scenario, should_fire in (("fires", True), ("silent", False)):
            events = fx.get(scenario, [])
            if not events:
                continue
            total += 1
            load_table(events)
            n = query_count(rule["query"])
            ok = (n > 0) == should_fire
            verb = "FIRED" if n > 0 else "silent"
            mark = "ok  " if ok else "FAIL"
            print(f"  [{mark}] {rule['name']} / {scenario}: expected {'fire' if should_fire else 'silent'}, got {verb} ({n})")
            if not ok:
                failures += 1
    print(f"\n{total - failures}/{total} assertions passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
