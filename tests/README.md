# Detection unit tests

Detections tested **as software**: each rule's real KQL is run against synthetic
AzureActivity fixtures in a local **Kusto emulator** (no live tenant), asserting it
**fires on malicious** data and stays **silent on benign** data. Anyone can fork and run
this — the validation is reproducible, not tied to my Azure.

This complements the live `detection-regression` workflow (which proves rules fire in the
real tenant): unit tests prove the **logic** is correct and won't silently break on a refactor.

## Layout
- `fixtures/SC200-0N.json` — `{ "fires": [...events...], "silent": [...events...] }` per rule.
- `run-detection-tests.py` — loads each rule's `query` from `detections/rules/*.yaml`, ingests
  the fixture into the emulator (`.set-or-replace AzureActivity`), runs the query, asserts the
  fire/silent expectation.

## Run locally (Docker required)
```bash
docker run -d --rm -p 8080:8080 -e ACCEPT_EULA=Y mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
# wait a few seconds for the emulator to start
pip install pyyaml
python tests/run-detection-tests.py
```

In CI the emulator runs as a service container (`.github/workflows/detection-tests.yml`).

## Adding a case
Add events to the rule's fixture. Each event sets the AzureActivity columns the rule uses
(`ActivityStatusValue`, `Caller`, `OperationNameValue`, `ResourceProviderValue`, `ResourceId`,
optional `Properties_d`, optional `minutesAgo` to place it in an earlier 5-minute bin). The
harness assigns `TimeGenerated` so `ago(1h)` / `bin(5m)` behave deterministically.
