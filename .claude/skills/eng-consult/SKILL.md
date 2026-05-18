---
name: eng-consult
description: "Engineering Consulting Panel — multi-voice review of code, plans, or architecture. Convenes a specialist roster, triages findings, returns a remediation plan."
user_invocable: true
---

# /eng-consult

Convene a multi-voice engineering consulting panel that reviews code artifacts for quality, security, DevOps readiness, usability, and architectural fitness. Each specialist independently reviews the artifact, then leadership triages findings into a structured remediation plan.

This is a **consulting** exercise. The panel returns recommendations. The operator decides what ships. No verdicts, no rulings, no advisory-tier semantics — just a structured second opinion across multiple engineering disciplines.

---

## When to Use

Call this when you want a thorough multi-discipline review:
- Pre-release review of a module, script, or PR
- Full codebase audit before a wider release or beta
- Targeted security, quality, or deployment readiness review
- Onboarding new contributors to a well-documented codebase

This is not for quick questions. Convening the panel means you want the full treatment across multiple engineering disciplines simultaneously.

**Decision tree — which tool?**
- "Is this code good enough to ship?" → `/eng-consult`
- "How would someone break this?" → `/infosec-rt`
- "Quick cross-CLI review of the staged diff" → `/review` (single-Reviewer pass, not a panel)

---

## Tools to invoke

This skill produces commentary. It does not replace the deterministic gates. Before or during a session, the operator (or the skill itself) may run:

- `scripts/gates.sh secrets | deps | sast` — gitleaks, osv-scanner, semgrep
- `scripts/gates.sh review` — cross-CLI single-Reviewer pass on the staged diff
- `scripts/gates.sh digest` — recent audit-trail summary

Output lands in `.clagentic/audit.db.gate_runs` and `.clagentic/last-review.json`. Specialists may reference any blocking finding from these gates as a Proven issue in their findings. **The skill cannot suppress, downgrade, or override a deterministic-gate finding** — see Commentary policy below.

---

## Commentary policy

`/eng-consult` is commentary. It does not block, gate, or merge anything.

- Deterministic-gate findings (gitleaks/semgrep/osv-scanner) remain blocking at their gates. The panel may discuss them but cannot mark them resolved.
- The LLM Merge Gate (configured by `.claude/agents/merge-gate.md`) is the final pre-merge LLM check inside `/ship`. The panel's Recommendations do not feed into the Merge Gate automatically — they inform the operator, who decides whether to address each item before invoking `/ship`.
- Severity tags here (Critical/High/Medium/Low) are the panel's judgment. The operator decides which of those become commits, which become followup tasks, and which become accepted risks.

---

## The Roster

Member names use real engineering role titles — recognizable to any engineer.

### Leadership (Always Active)

Two leadership roles do not audit in Pass One. They read all specialist findings and jointly run Triage, then The Principal writes the Recommendations.

| Name | Role | Their lens |
|---|---|---|
| **The Principal** | Lead consultant / integrating engineer | Staff- or Principal-level judgment — broad, senior, no single-discipline bias. Reads all findings, runs triage, writes the remediation plan. "Is this code I'd be proud to ship? What's the real risk here?" |
| **The PM** | Product Manager | User and product lens on technical work. "Does this work for the person who installs it? Would a beta user hit a wall here?" Catches blind spots specialists miss by being inside the code. |

### Permanent Specialists (Always Active)

Four specialists always participate. Each audits independently in Pass One.

| Name | Role | Their lens |
|---|---|---|
| **The Security Lead** | Security engineer | Vulnerability surface, threat modeling, secrets exposure, dependency vulns, input validation, auth/authz, OWASP, STRIDE. Scope: *what can be exploited and by whom*. Does not own deployment reliability or incident recovery — those are SRE territory. "How does this get exploited?" |
| **The QA Lead** | Quality assurance | Maintainability, complexity, dead code, test coverage gaps, duplication, naming clarity. "Will the next person who reads this trust it?" |
| **The SRE** | Site reliability / DevOps | Deployment safety, CI/CD hygiene, env config, rollback paths, observability hooks, alerting, install experience, and incident recovery runbooks. Scope: *what fails in production and whether we can detect and recover from it*. Does not own vulnerability modeling or threat analysis — those are Security Lead territory. "Can this be deployed safely and monitored when it breaks?" |
| **The UX Lead** | Ergonomics / usability | CLI ergonomics, error messages, output legibility, onboarding friction, help text quality. "Is this actually usable by someone who isn't the author?" |

### Optional Specialists

Optional members can be invoked explicitly via flags **or** auto-invoked by The Principal based on artifact scope. Auto-invoke is always stated explicitly — never silent.

| Name | Role | Flags | Auto-invoked when... |
|---|---|---|---|
| **The Perf Lead** | Performance | `--perf`, `--performance` | Hot paths, loops, high-frequency scripts, scale-sensitive code, anything with timing concerns |
| **The A11y Lead** | Accessibility / i18n | `--a11y`, `--i18n` | User-facing output, CLI text, templates, string formatting, any file with localizable strings |
| **The Tech Writer** | Documentation | `--docs` | Public API surface, missing docstrings, README/CONTRIBUTING gaps, exported interfaces with no docs |
| **The Supply Chain Lead** | Dependency security | `--deps`, `--supply-chain` | requirements.txt, package.json, Dockerfile, Pipfile, any dependency manifest |

> **Note:** the "Adversary" / premise-challenge role from the original advisory tradition is **not** part of `/eng-consult`. For premise challenges and attack chains, run `/infosec-rt` — that's its job. Keeping them separate prevents this panel from drifting into red-team territory.

---

## Invocation

```
/eng-consult                          — full review, most recent artifact discussed in session
/eng-consult [file or topic]          — scope to specific artifact
/eng-consult --full-codebase          — full repo-wide audit (all files under cwd)
/eng-consult --perf                   — include The Perf Lead
/eng-consult --a11y                   — include The A11y Lead
/eng-consult --docs                   — include The Tech Writer
/eng-consult --deps                   — include The Supply Chain Lead
/eng-consult --full                   — all members including all optionals
```

**Single-specialist mode** (findings only — no triage, no recommendations):
```
/eng-consult --security-lead          — Security Lead only
/eng-consult --qa-lead                — QA Lead only
/eng-consult --sre                    — SRE only
/eng-consult --ux-lead                — UX Lead only
/eng-consult --perf-lead              — Perf Lead only
```

**If no artifact is specified:** Use the most recent file, plan, or code discussed in the session. For a repo-wide audit with no prior artifact context, use `--full-codebase` or pass the repo root path explicitly (e.g. `/eng-consult /path/to/project`).

---

## Execution Protocol

When invoked, execute this sequence exactly:

### 1. Announce the Session

```
── The Consulting Panel convenes ───────────────────────────
Artifact: {what is being reviewed — file, module, PR, codebase path, or description}
Scope: {focus area — or "full review" if unspecified}
Members: The Principal, The PM, The Security Lead, The QA Lead, The SRE, The UX Lead
         [+ any auto-invoked or explicitly requested optional specialists]
```

The Principal then states which optional specialists (if any) are being auto-invoked and the one-line reason for each. If none are needed:
> *No optional specialists invoked — artifact scope does not require them.*

---

### 2. Pass One — Independent Audits

Each specialist reviews the artifact independently, with **no awareness of what others have found**. Leadership (The Principal, The PM) does **not** audit in Pass One — they read all findings and lead Triage.

Each specialist produces:
- Findings tagged by severity: **Critical** / **High** / **Medium** / **Low** / **Suggestion**
- 1–2 sentence rationale per finding
- `[Overlap likely: X]` tag if another specialist is likely to find the same issue

Fixed order: Security Lead → QA Lead → SRE → UX Lead → [optional specialists, in invocation order]

```
── Pass One ────────────────────────────────────────────────

── The Security Lead ───────────────────────────────────────
[Critical] {finding} — {rationale}
[High] {finding} — {rationale}
[Overlap likely: QA Lead] {finding} — {rationale}
...

── The QA Lead ─────────────────────────────────────────────
[High] {finding} — {rationale}
...

── The SRE ─────────────────────────────────────────────────
...

── The UX Lead ─────────────────────────────────────────────
...

[── The [Optional Specialist] ──────────────────────────────]
[{findings — only if active}]
```

**Pass One character notes:**
- Each specialist responds only to the artifact — not to each other.
- No hedging toward anticipated disagreement or agreement.
- If a specialist finds nothing at a given severity level, they omit that level entirely — no "None found" padding.
- Specialists should be substantive and specific. Vague findings ("this could be improved") are not findings.

---

### 3. Triage

The Principal leads Triage and writes all severity decisions. The PM participates in an advisory role — reads all findings, flags user-facing impact, advocates for promotions — but cannot block or veto The Principal's adjudication. No specialist speaks in Triage.

- **Merge duplicates** — distinguish between two types: (1) *same issue, different angle* — merge into one finding, note both originators; (2) *related but distinct remediation* — keep as separate findings, add `[Related: X]` cross-reference tag to each (`X` = specialist role name, e.g. `[Related: SRE]`). Do not collapse findings that share a root cause but require independent fixes.
- **Scan for untagged overlaps** — The Principal actively checks for shared root causes across all findings, not only those tagged `[Overlap likely: X]` by specialists. Shared root cause with independent remediations → `[Related: X]` tags on each. Shared root cause with same remediation → merge.
- **Resolve severity conflicts** — if two specialists disagree on severity, The Principal adjudicates with a one-line rationale.
- **Identify patterns** — three Medium findings with the same root cause → one High; systemic issues are explicitly called out.
- **PM promotion** — The PM may flag a finding with outsized user-facing impact and recommend promotion; The Principal decides. Advisory only.

```
── Triage ──────────────────────────────────────────────────
Duplicates merged: {count} — {brief list, or "None"}
Severity adjustments: {changes with rationale — or "None"}
Patterns identified: {systemic issues connecting multiple findings — or "None"}
```

---

### 4. Recommendations — Remediation Plan

The Principal writes the recommendations: a structured remediation plan organized by severity. This is **not** a verdict or a ruling — it is an engineering action plan you read and act on at your discretion.

```
── Recommendations ─────────────────────────────────────────
Overall: {one sentence — Shippable / Needs Work / Has Blockers}

── Critical (blockers — fix before any release) ─────────────
[{originator}] {finding} → {recommended action}

── High (fix in this cycle) ──────────────────────────────────
[{originator}] {finding} → {recommended action}

── Medium (fix before beta / wider release) ──────────────────
[{originator}] {finding} → {recommended action}

── Low / Suggestions ─────────────────────────────────────────
{finding} → {optional improvement}

── Commendations ─────────────────────────────────────────────
{minimum 1 item — what's done well; this is not purely a criticism session}

── Deferred Findings ─────────────────────────────────────────
[{originator}] {finding} — Deferred: {one-line reason, e.g. "out of scope for this PR", "tracked separately", "accepted risk — documented"}
```

**Recommendations notes:**
- The originator tag `[Security Lead]`, `[QA Lead]`, etc. makes it clear whose domain each finding came from.
- Commendations are not optional. Every codebase has things done right. Name them.
- If there are no Critical findings, omit that section — do not write "Critical: None."
- Same for High and Medium — omit empty severity tiers rather than padding with "None."
- Low / Suggestions can be omitted entirely if there are none.
- **Deferred Findings** records specialist findings that The Principal or PM explicitly scoped out of the current remediation plan. This section exists so findings are never silently dropped — the record is preserved even when the decision is "not now." Omit this section if all findings are actioned. Do not use it to bury Critical findings without explanation.
- **Single-specialist invocations** skip Triage and Recommendations entirely — one pass, findings list only. The section header changes to `── Findings ──` rather than `── Pass One ──`.

---

## Notes

Member names (The Principal, The PM, The Security Lead, The QA Lead, The SRE, The UX Lead, The Perf Lead, The A11y Lead, The Tech Writer, The Supply Chain Lead) are proper nouns — always capitalized. They do not speak outside of `/eng-consult` sessions.

The Principal writes the Recommendations — specialists produce findings and may have their findings merged, promoted, or demoted in Triage. No voting. Findings explicitly scoped out of the remediation plan appear in the Deferred Findings section — they are never silently dropped.

Optional members do not persist across sessions. They must be invoked explicitly or auto-invoked by The Principal based on artifact scope.

The Recommendations are **commentary**, not a gate. They do not pass or fail a `/ship` run; they inform the operator's backlog. The deterministic gates (gitleaks/semgrep/osv-scanner) and the LLM Merge Gate are the only blocking surfaces.

Never reuse `/eng-consult` member names for other purposes. Note: "The Supply Chain Lead" (this skill) is distinct from "The Supply Chain Analyst" in `/infosec-rt` — different roles, different sessions, different scope. The Supply Chain Lead audits dependency manifests for hygiene. The Supply Chain Analyst models dependency compromise as an attack vector.
