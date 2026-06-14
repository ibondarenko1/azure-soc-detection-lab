# Contributing

This repo is detection-as-code: a detection is not clicked into a portal, it is versioned YAML that a
PR-gated pipeline validates, tests, and deploys. So any change to a rule goes through a pull request and
the same checks, whether it is mine or a fork's. This guide is the workflow.

## The model

```
edit rule YAML -> regenerate KQL mirror -> extend test fixture -> run unit tests -> open PR -> CI gates -> review -> merge -> OIDC deploy
```

- Source of truth for every rule: [`detections/rules/*.yaml`](detections/rules).
- One human-readable card per rule lives next to it (`detections/DET-00N-*.md`): logic, MITRE mapping, trigger, evidence.
- The pipeline deploys idempotently by rule GUID; merging to `main` is what pushes a rule to the live workspace. Full mechanics: [docs/03-cicd.md](docs/03-cicd.md).

## Add or change a detection

1. **Branch off `main`.** Use a short topic branch (the existing history uses `phase-<x>/<topic>` or `fix/<topic>`).
2. **Edit the rule YAML** in `detections/rules/`. Keep the GUID stable when editing an existing rule (the deployer keys on it); use a fresh GUID for a new rule.
3. **Regenerate the KQL mirror.** The `kql/detections/*.kql` files are generated copies of each rule's query, kept in sync so the KQL is browsable on its own:
   ```bash
   python cicd/sync-kql-mirror.py
   ```
   CI fails if the mirror is out of sync (`sync-kql-mirror.py --check`), so run this after any query change.
4. **Extend the test fixture.** Add `fires` and `silent` events to the rule's `tests/fixtures/DET-00N.json` so the new or changed logic is asserted. The fixture format and the columns each event needs are documented in [tests/README.md](tests/README.md).
5. **Update the rule card** (`detections/DET-00N-*.md`) and, if MITRE coverage changed, the [ATT&CK layer](navigator/coverage-layer.json).
6. **Run the unit tests locally** (next section) until green.
7. **Open a PR to `main`.** The CI gates below must pass; then it is reviewed and merged, and merge deploys it.

## Run the checks locally

Unit tests, no Azure tenant needed (a local Kusto emulator runs each rule's real KQL over the fixtures):

```bash
docker run -d --rm -p 8080:8080 -e ACCEPT_EULA=Y mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
pip install pyyaml
python cicd/sync-kql-mirror.py --check   # mirror in sync
python tests/run-detection-tests.py      # rules fire on malicious, silent on benign
```

Schema validation (what the `validate` gate runs):

```bash
python cicd/validate-detections.py
```

The live validation harness ([validation/](validation/)) and the regression workflow need a real subscription and `az login`; they are not part of the local loop. See [validation/README.md](validation/README.md).

## CI gates

Every pull request must pass, before review:

- **detection-tests** ([workflow](.github/workflows/detection-tests.yml)): the unit tests above, plus the KQL-mirror sync check.
- **validate** ([workflow](.github/workflows/deploy-detections.yml)): rule schema validation.

`deploy` only runs on merge to `main`, over OIDC, and is a no-op when no `detections/rules/*.yaml` changed (so docs-only PRs do not trigger a Sentinel deploy). A separate [detection-regression](.github/workflows/detection-regression.yml) workflow proves rules still fire in the real tenant.

## Conventions

- **No secrets, ever.** Deployment authenticates with OIDC; there are no stored credentials in the repo and PRs must not add any.
- **Redaction.** Any screenshot must have tenant ID, subscription ID, resource IDs, UPNs, and PII removed before commit. The convention and the scripts are in [screenshots/README.md](screenshots/README.md).
- **Numbers trace to artifacts.** Claims in docs cite a snapshot, a results file, or a screenshot. Do not assert a metric the environment cannot measure (the repo deliberately reports measured false fires, not a fabricated FP rate).
- **Docs stay plain and factual.** Short practitioner prose, no filler.

## Where things live

| Path | What |
|------|------|
| `detections/rules/` | rule YAML (source of truth, deployed by CI) |
| `detections/*.md` | one card per rule |
| `kql/` | generated KQL mirror + hunting library |
| `tests/` | unit tests + fixtures (fork-runnable) |
| `validation/` | live benign + attack harness (needs a tenant) |
| `cicd/` + `.github/` | the pipeline (validate, test, deploy, regression) |
| `navigator/` | ATT&CK coverage layer |
| `docs/` | architecture, methodology, cicd, and the case studies |
