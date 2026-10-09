# Accepted Risks

> **DEPRECATED.** `.clagentic/accepted-risks.md` no longer clears anything. The merge
> gate used to hand this freetext to a model and let it decide which findings it covered;
> whether a finding blocks is now decided in code, from `.clagentic/dispositions.json`
> (example: `share/dispositions.example.json`). The file is still read for one more
> release only to warn that it has no effect. Record each risk below as an entry there
> (`kind: accepted_risk` or `by_design`; a reachable high-severity finding needs
> `kind: mitigated` naming its control). The text below is kept as a writing guide for
> the `rationale` field.

This file documents architectural risk decisions for this project.

Commit it deliberately — its presence in version history is part of the audit trail.

**Trust model:** this file is repo-controlled. It is a workflow convenience for trusted
internal contributors, not a security control. A contributor can add a behavior change
and a covering accepted-risk entry in the same diff; there is no automated check against
this. The structural fix is CODEOWNERS protection on `.clagentic/accepted-risks.md` and
`.clagentic/adversarial-acks.json` so edits require review outside the submitter. Until
that is in place, treat these files as convenience mechanisms, not enforcement controls.

## Format

Each risk entry should include:
- The CWE(s) it covers
- The specific behavior that triggers the finding
- Why it is intentional (the product purpose)
- Who accepted it and when

Use one `##` section per logical risk area. The merge-gate reads this as freetext and
matches findings against it by semantic proximity, not by exact CWE lookup. For
per-CWE structured acknowledgments with path-glob scoping, use
`.clagentic/adversarial-acks.json` instead — that mechanism is more precise and takes
precedence when both apply to the same finding.

## Example entries

### CWE-200: Information Disclosure — Security Dashboard

**Behavior:** Routes under `/api/advisories/*` and `/api/topology/*` return CVE data,
CVSS scores, and deployment topology to authenticated requests.

**Why inherent:** This is the core product feature. The system is a security intelligence
dashboard for security analysts. Returning security data to security analysts is the
stated purpose, not a leak.

**Accepted by:** Andy K, 2026-06-04

---

### CWE-807: Reliance on Untrusted Inputs in a Security Decision — Deployment Discovery

**Behavior:** The reachability scanner reads K8s workload specs from the cluster API
and uses them to build a topology graph. The input is not fully trusted.

**Why inherent:** Deployment-discovery requires reading live cluster state. There is no
alternative data source. The data is used for read-only display to authenticated
analysts; no security decisions are made on this input.

**Accepted by:** Andy K, 2026-06-04
