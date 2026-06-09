# Detection KQL mirror (generated)

Portal/ADX-pasteable copies of each deployed rule's query, one `DET-NNN.kql` per rule.

**These files are generated, not source.** The single source of truth is the rule YAML in
[`detections/rules/`](../../detections/rules) (deployed to Sentinel by the CI pipeline). This mirror
is produced from it by [`cicd/sync-kql-mirror.py`](../../cicd/sync-kql-mirror.py):

```bash
python cicd/sync-kql-mirror.py          # regenerate after changing a rule's YAML
python cicd/sync-kql-mirror.py --check  # CI guard: fails if the mirror drifted
```

CI runs the `--check` on every pull request, so the mirror cannot diverge from the deployed rules.
Do not hand-edit these files; change the YAML and regenerate.
