# SOC 2 control mapping: this repo against the Trust Services Criteria

Detection engineering does not live in a vacuum. In a real organization the rules, the change
pipeline, the incident write-ups, and the posture loop in this repo are the exact artifacts a SOC 2
auditor samples when testing the Security (Common Criteria) controls. This document maps what the repo
already does to the criteria it supports, so the work reads in both languages: the engineering one and
the GRC one.

## What this is, and what it is not

This is a **mapping**, not a compliance claim. The environment is a single tenant I operate, it has
not been through a SOC 2 examination, and one person running one subscription cannot produce a SOC 2
report. What a single-operator technical repo *can* show is the control **activity** behind the
criteria: the monitoring that runs, the change process that gates every rule, the incidents that got
worked, and the posture gaps that got measured and closed.

SOC 2 also requires an organizational wrapper this repo deliberately does not pretend to have:
written policies, defined roles and segregation of duties, HR and onboarding controls, vendor and
subservice risk management, and management oversight evidenced over a period. That governance layer is
separate work and sits outside a detection-engineering repository. The point here is narrow and honest:
these technical control activities are real, they are measured, and this is where they would land in
the Common Criteria.

## The mapping

Trust Services Criteria are the 2017 set (Security category, the Common Criteria series). Strength is
my own read of how directly the repo evidences the criterion: **Strong** where the repo is the
primary evidence for the control activity, **Partial** where it shows one side (usually the detect or
technical side) of a criterion whose full satisfaction needs the governance wrapper above.

| TSC | What the criterion asks for | Control activity in this repo | Evidence | Strength |
|-----|-----------------------------|-------------------------------|----------|----------|
| **CC3.2** | Identify and assess risks to objectives | Threat model and ATT&CK coverage with risk-ranked, openly tracked gaps | [docs/08](08-detection-strategy.md), [navigator layer](../navigator/coverage-layer.json), [`detection-gap` issues](../../issues?q=is%3Aissue+label%3Adetection-gap) | Partial (technical risk) |
| **CC4.1** | Monitor and evaluate whether controls are operating | Validation harness measures each rule's true-positive recall and false positives over a real benign and attack batch; posture re-score loop re-measures after fixes | [validation/](../validation/), [RESULTS.md](../validation/RESULTS.md), [metrics.yaml](../detections/metrics.yaml) | Strong |
| **CC6.1** | Logical access controls over identity and privilege | RBAC-change and identity detections; posture "Manage access and permissions" control | [DET-003](../detections/DET-003-rbac-role-assignment-changes.md) / [DET-005](../detections/DET-005-suspicious-deployment-non-owner.md) / [DET-007](../detections/DET-007-rbac-grant-then-deploy.md), [DET-008](../detections/DET-008-signin-success-after-failures.md), [docs/10](10-posture-remediation.md) | Strong (detect side) |
| **CC6.6** | Protect the system boundary from external threats | NSG-exposure detections; posture "Restrict unauthorized network access" control | [DET-002](../detections/DET-002-nsg-rule-modified.md), [DET-009](../detections/DET-009-nsg-opened-inbound-any.md), [docs/10](10-posture-remediation.md) | Strong (detect side) |
| **CC6.8** | Prevent or detect unauthorized or malicious software | Endpoint credential-access detection on a hardened sensor plus the TVM hunting library | [DET-006](../detections/DET-006-lsass-credential-access.md), [kql/hunting](../kql/hunting), [docs/07](07-endpoint-vulnerability-management.md) | Strong (detect side) |
| **CC7.1** | Detect changes and new vulnerabilities | Defender Vulnerability Management hunts plus the exposure-remediation loop (Edge, Windows, OpenSSL handled and verified at the device level) | [docs/07](07-endpoint-vulnerability-management.md), [docs/10](10-posture-remediation.md), [kql/hunting](../kql/hunting) | Strong |
| **CC7.2** | Monitor components for anomalies that could be incidents | The nine-rule catalog across the Azure control plane, endpoint, and identity | [detections/](../detections), [overview screenshot](../screenshots/11-sentinel-overview.png) | Strong |
| **CC7.3** | Evaluate detected events to decide if they are incidents | Triage of fired rules into incidents, each worked as a documented investigation | [INV-01 to INV-05](../investigations) | Strong |
| **CC7.4** | Respond to identified incidents (contain, remediate) | SOAR automation rule plus Logic App enrichment and containment guidance; Security Copilot triage on the same incident | [playbooks/](../playbooks), [docs/06](06-security-copilot.md) | Strong (control plane) |
| **CC7.5** | Recover from incidents and learn from them | Playbook containment and restore guidance; the DET-005 tuning case study is a measured lessons-learned loop | [playbooks/](../playbooks), [docs/09](09-tuning-case-study.md) | Partial (guidance and tuning, not automated recovery) |
| **CC8.1** | Authorize, design, test, approve, and implement changes | Detection-as-Code: every rule change is a PR, CI validates and unit-tests it, a review approves it, and merge deploys it by OIDC, idempotent by rule GUID | [cicd/](../cicd), [deploy-detections.yml](../.github/workflows/deploy-detections.yml), [docs/03](03-cicd.md), [tests/](../tests) | Strong |

## How this would read in an audit

A SOC 2 Type II examination tests whether a control operated over a period, not just at a point in time,
so the auditor samples evidence: the configured rules, the change records behind them, the incident
tickets, and the monitoring output across the window. The repo is already shaped that way. Rule changes
are pull requests with CI and review, which is the change-management evidence for **CC8.1**. The
investigations are dated incident records for **CC7.3** and **CC7.4**. The validation harness and the
posture before-and-after are control-operating-effectiveness evidence for **CC4.1**, measured rather
than asserted. The gap between this and an actual report is the governance wrapper, not the technical
evidence trail, which is the harder half to fake and the half this repo actually has.

## Lesson

The same discipline that makes a detection credible makes a control credible: you do not claim it, you
show it operating and you measure the result. Mapping the catalog, the pipeline, the incidents, and the
posture loop onto the Common Criteria is what connects "I wrote some Sentinel rules" to "here is how
this work supports a recognized control framework", without overstating it into a compliance claim it
has not earned.
