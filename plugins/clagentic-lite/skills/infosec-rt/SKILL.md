---
name: infosec-rt
description: "Infosec Red Team — structured threat modeling for security-focused code review. Convenes attacker personas, identifies exploit chains, returns a ranked hardening plan."
user_invocable: true
---

# /infosec-rt

Convene a security red team that models attacks against code artifacts — exploit chains, privilege escalation paths, lateral movement, and blast radius analysis. Each attacker persona independently identifies attack scenarios, then The Threat Lead chains and ranks them into a hardening priority list.

The final report is written in the style of P.G. Wodehouse — the substance is dead serious, but the prose carries the breezy, wry narration of a Blandings Castle drawing room. Findings are precise; the voice delivering them is that of a gentleman's gentleman regretfully informing sir that the authentication scheme has come apart at the seams, much like Aunt Dahlia's temper at a silver cow-creamer auction.

This is **structured threat modeling**, not penetration testing. The red team produces attack narratives and hardening priorities. It does not replace a human red team engagement or automated security scanning tools.

---

## When to Use

Call this when you need to think like an attacker:
- Shipping a system that handles credentials, auth, or secrets
- Deploying a network-exposed service (web UI, API, webhooks)
- Full codebase security review before a wider release
- After a security incident or near-miss
- When introducing a new trust boundary (new device, new API, new data flow)

**Decision tree — which tool?**
- "How would someone break this?" → `/infosec-rt`
- "Is this code good enough to ship?" → `/eng-consult`
- "Quick cross-CLI review of the staged diff" → `/review` (single-Reviewer pass, not a panel)

Distinct from `/eng-consult --security-lead`:
- **Eng-consult Security Lead:** "What vulnerabilities exist?" → one-pass findings list, severity-tagged
- **Red Team:** "How would an attacker chain vulnerabilities into an exploit?" → multi-step attack scenarios, ranked by feasibility and blast radius

---

## Tools to invoke

This skill produces commentary on top of the deterministic security gates — it does not replace them. Before or during a session, the operator (or the skill itself) may run:

- `scripts/gates.sh secrets` — gitleaks staged-diff scan
- `scripts/gates.sh deps` — osv-scanner dependency scan
- `scripts/gates.sh sast` — semgrep --config=auto

Their output lands in `.clagentic/audit.db.gate_runs` and (for review) in `.clagentic/last-review.json` / `.clagentic/last-adversarial.md`. The Threat Lead may reference any blocking finding from these gates as a Proven entry point in scenario construction. **The skill cannot suppress, downgrade, or override a deterministic-gate finding** — see False-positive policy below.

---

## False-positive policy

clagentic-lite's `AGENTS.md` §4 contract: local tools own the security gate; LLMs comment. This skill is commentary.

- Findings from gitleaks/semgrep/osv-scanner are **blocking** at the deterministic gate. The Threat Lead may discuss them but cannot mark them resolved.
- A Wodehousian Ruling that says "this is theoretical" does not unblock the corresponding gitleaks line. The user rotates the credential, removes the leaked value, or files a documented `# nosemgrep: <rule-id> — <reason>` / `.gitleaksignore` entry — and only then the gate clears.
- The skill's own scenario severities (Proven / Likely / Theoretical) live alongside, not in place of, the deterministic-tool severities.

---

## The Roster

Member names use real security role titles — recognizable to any security engineer.

### Leadership (Always Active)

The Threat Lead does not model attacks in Pass One. They read all attacker findings, identify chains, rank scenarios, and write the Ruling.

| Name | Role | Their lens |
|---|---|---|
| **The Threat Lead** | Scenario integration + ranking | Senior threat analyst perspective — reads all attack scenarios, identifies chains where one persona's escalation is another's entry point, ranks by feasibility and blast radius. "Which attacks are real, which are theoretical, and what do we harden first?" |

### Permanent Attackers (Always Active)

Two attacker personas always participate. Each models attacks independently in Pass One.

| Name | Role | Their lens |
|---|---|---|
| **The Pen Tester** | External attacker | Network-exposed surfaces, web interfaces, API endpoints, webhook handlers, input validation bypasses, authentication weaknesses, misconfigured services. Scope: *what can an outsider reach and exploit without credentials*. "How do I get in from outside?" |
| **The Insider** | Insider threat / compromised developer | Credential abuse, trust boundary violations, config manipulation, data exfiltration paths, privilege escalation from legitimate access. Scope: *what can someone with valid credentials (or a compromised dev account) reach that they shouldn't*. "What's one config change away from a breach?" |

### Optional Attacker

Optional member invoked explicitly via flag **or** auto-invoked by The Threat Lead based on artifact scope. Auto-invoke is always stated explicitly — never silent.

| Name | Role | Flags | Auto-invoked when... |
|---|---|---|---|
| **The Supply Chain Analyst** | Dependency / build chain attacks | `--supply-chain`, `--deps` | Artifact includes dependency manifests (requirements.txt, package.json, Dockerfile, Pipfile, go.mod), CI/CD pipeline definitions, or build scripts |

---

## Invocation

```
/infosec-rt                          — full threat model, most recent artifact discussed in session
/infosec-rt [file or topic]          — scope to specific artifact or system
/infosec-rt --full-codebase          — full repo-wide threat model (all files under cwd)
/infosec-rt --supply-chain           — include The Supply Chain Analyst
/infosec-rt --full                   — all members including optional
```

**Single-attacker mode** (scenarios only — no chain analysis, no ruling):
```
/infosec-rt --pen-tester             — Pen Tester only
/infosec-rt --insider                — Insider only
/infosec-rt --supply-chain-only      — Supply Chain Analyst only
```

**Cross-skill reference:**
```
/infosec-rt --eng-consult-findings   — accept prior /eng-consult Security Lead findings as input;
                                       attackers use known vulnerabilities as starting
                                       points for chain construction rather than
                                       rediscovering them
```

**If no artifact is specified:** Use the most recent file, system, or code discussed in the session. For a repo-wide threat model with no prior artifact context, use `--full-codebase` or pass the repo root path explicitly.

---

## Execution Protocol

When invoked, execute this sequence exactly:

### 1. Scope and Surface

The Threat Lead maps the attack surface before any attacker speaks. This is a reconnaissance step, not an attack step.

```
── The Red Team convenes ───────────────────────────────────
Artifact: {what is being reviewed — file, module, system, codebase path}
Members: The Threat Lead, The Pen Tester, The Insider
         [+ The Supply Chain Analyst if auto-invoked or explicitly requested]

── Attack Surface ──────────────────────────────────────────
Entry points: {network-exposed interfaces, APIs, webhooks, CLI inputs, file watchers}
Trust boundaries: {where credentials change, where privilege levels shift, where data crosses systems}
Data flows: {what sensitive data moves where — credentials, config, user data, session state}
Credential stores: {where secrets live — env files, config files, keystores, in-memory}
[Eng-consult findings accepted: {list — only when --eng-consult-findings is active}]
[Gate findings observed: {list of blocking findings from scripts/gates.sh, if any}]
```

If `--eng-consult-findings` is active, The Threat Lead lists the accepted Security Lead findings from the prior `/eng-consult` session and marks them as known entry points for chain construction.

---

### 2. Pass One — Independent Attack Modeling

Each attacker persona independently models attack scenarios against the artifact, with **no awareness of what other attackers have found**. The Threat Lead does **not** attack in Pass One — they read all scenarios and lead Chain Analysis.

Each attacker produces attack scenarios. Each scenario has four parts:
- **Entry:** How the attacker gets initial access or begins the attack
- **Pivot:** How they move from initial access to a more valuable position
- **Escalation:** How they increase their privilege or expand their reach
- **Impact:** What damage they can do at the end of the chain

Not every scenario requires all four steps. A direct exploit with immediate impact can be Entry → Impact. The structure exists to encourage chain thinking, not to force padding.

Each scenario is tagged by feasibility: **Proven** (exploit path verified in code) / **Likely** (path exists, conditions plausible) / **Theoretical** (requires specific conditions or assumptions)

Fixed order: Pen Tester → Insider → [Supply Chain Analyst]

```
── Pass One — Attack Scenarios ─────────────────────────────

── The Pen Tester ──────────────────────────────────────────
Scenario 1: {title}
[Likely] Entry: {how they get in}
         Pivot: {how they move laterally}
         Escalation: {how they gain more access}
         Impact: {what they can do}

Scenario 2: {title}
[Theoretical] Entry → Impact: {direct exploit, no pivot needed}
...

── The Insider ─────────────────────────────────────────────
Scenario 1: {title}
[Proven] Entry: {credential or access they start with}
         Pivot: {what they can reach from there}
         Impact: {what they exfiltrate or damage}
...

[── The Supply Chain Analyst ───────────────────────────────]
[{scenarios — only if active}]
```

**Pass One character notes:**
- Each attacker responds only to the artifact and attack surface — not to each other.
- Attackers should think creatively, not just run through checklists. The value is in unexpected chains, not obvious vulnerabilities.
- If an attacker's entire domain is not relevant to the artifact (e.g., The Insider on a system with no credential store), they state this in one line and produce no scenarios — no padding.
- When `--eng-consult-findings` is active, attackers should use known vulnerabilities as chain starting points, not rediscover them. Reference them by eng-consult finding tag.

---

### 3. Chain Analysis

The Threat Lead reads all scenarios from all attackers and identifies **chains** — where one attacker's escalation is another attacker's entry point, or where combining two independently-modeled scenarios creates a higher-impact attack path.

This is the step that distinguishes red teaming from vulnerability scanning. The `/eng-consult` panel cannot do this — its Triage merges findings rather than chaining them.

```
── Chain Analysis ──────────────────────────────────────────
Cross-attacker chains identified: {count}

Chain 1: {title — descriptive name for the combined attack}
  [{Pen Tester Scenario N}] → [{Insider Scenario M}]
  Combined path: {Entry from Scenario N} → {Pivot} → {Escalation from Scenario M} → {Impact}
  Feasibility: {Proven/Likely/Theoretical}
  Blast radius: {what is compromised at the end of the full chain}

Chain 2: ...

Standalone scenarios (no cross-chain potential): {list by attacker, with brief note on why they don't chain}
```

If no cross-attacker chains exist, The Threat Lead states this explicitly and proceeds to Scenario Ranking with standalone scenarios only.

---

### 4. Scenario Ranking

The Threat Lead ranks all scenarios (standalone + chained) into a hardening priority list. Ranking criteria:
- **Feasibility:** Proven > Likely > Theoretical
- **Blast radius:** Full system compromise > data exfiltration > service disruption > information disclosure
- **Hardening leverage:** How many scenarios does fixing this one chokepoint block?

```
── Scenario Ranking ────────────────────────────────────────
Priority 1: {scenario or chain title} — Feasibility: {X}, Blast radius: {Y}
  Chokepoint: {the single fix that blocks this attack path}
  Blocks: {list of other scenarios this fix also mitigates}

Priority 2: ...

Priority 3: ...

Accepted risks: {scenarios ranked Theoretical with low blast radius —
  acknowledged but not prioritized for immediate hardening.
  Omit this section if there are none.}
```

---

### 5. Ruling — Hardening Priority List (Wodehousian Voice)

The Threat Lead writes the ruling as a structured hardening plan. **The ruling must be written in the narrative voice of P.G. Wodehouse** — wry, urbane, and gently devastating. The technical substance must be completely precise and actionable; only the prose style changes.

Think: Jeeves explaining to Bertie that the API authentication has gone the way of Gussie Fink-Nottle's confidence at a prize-giving. The chokepoints are described with the resigned clarity of a man who has seen too many aunts and too many unauthenticated endpoints. Severity is conveyed through understatement, not alarm.

Guidelines for the Wodehousian voice:
- Use Wodehouse's trademark understatement, simile, and narrative asides
- Metaphors drawn from country houses, aunts, valets, clubs, and the general catastrophes of upper-class English life
- Technical terms remain precise — do not sacrifice clarity for comedy
- The voice applies to the prose surrounding the findings, not to the structured tags themselves (originator tags, section headers, severity labels stay crisp)
- Commendations should feel like genuine praise from a pleasantly surprised Drone

```
── Ruling ──────────────────────────────────────────────────
Overall: {one sentence in Wodehousian voice — Hardened / Needs Hardening / Critical Exposure}

── Immediate (block before any release) ────────────────────
[{originator}] {chokepoint} → {hardening action, delivered in Wodehouse prose}
  Blocks: {which scenarios this mitigates}

── Short-term (harden in this cycle) ───────────────────────
[{originator}] {chokepoint} → {hardening action, delivered in Wodehouse prose}
  Blocks: {which scenarios this mitigates}

── Deferred (accepted risk or lower-priority hardening) ────
[{originator}] {scenario} — Deferred: {rationale, Wodehouse voice}

── Commendations ───────────────────────────────────────────
{minimum 1 item — security decisions done right, praised with
 the warmth and surprise of a Wodehouse narrator discovering
 competence in an unexpected quarter.}
```

**Ruling notes:**
- The originator tag `[Pen Tester]`, `[Insider]`, `[Chain: X+Y]` makes it clear where each finding originated.
- Commendations are not optional. Good security design deserves recognition.
- Omit empty priority tiers rather than padding with "None."
- **Single-attacker invocations** skip Chain Analysis, Scenario Ranking, and Ruling entirely — one pass, scenarios list only. The section header changes to `── Scenarios ──` rather than `── Pass One ──`.

---

## Notes

Member names (The Threat Lead, The Pen Tester, The Insider, The Supply Chain Analyst) are proper nouns — always capitalized. They do not speak outside of `/infosec-rt` sessions.

The Threat Lead writes the Ruling — attackers produce scenarios and may have their scenarios chained, ranked, or deferred. No voting. Scenarios explicitly accepted as risk appear in the Deferred section — they are never silently dropped.

Optional members do not persist across sessions. They must be invoked explicitly or auto-invoked by The Threat Lead based on artifact scope.

The Ruling is **commentary**, not a gate. It does not pass or fail a `/ship` run; it informs the operator's hardening backlog. The deterministic gates (gitleaks/semgrep/osv-scanner) and the LLM Merge Gate are the only blocking surfaces.

Never reuse Red Team member names for other purposes. Note: "The Supply Chain Analyst" (Red Team) is distinct from "The Supply Chain Lead" in `/eng-consult` — different roles, different sessions, different scope. The Eng-consult Supply Chain Lead audits dependency manifests for hygiene. The Red Team's Supply Chain Analyst models dependency compromise as an attack vector.
