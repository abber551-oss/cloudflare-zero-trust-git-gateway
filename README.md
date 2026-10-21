# Zero-Trust Git Gateway & Forensic SOAR Kill-Switch for Cloudflare Artifacts (v2.0)

![Architecture](https://img.shields.io/badge/Architecture-Zero--Trust%20Edge-0b192c)
![Platform](https://img.shields.io/badge/Cloudflare-Workers%20%7C%20D1%20%7C%20Durable%20Objects%20%7C%20Artifacts-f38020)
![SOAR](https://img.shields.io/badge/Threat%20Intel-OASIS%20STIX%202.1%20%7C%20MITRE%20ATT%26CK%20v20-8b0000)
![License](https://img.shields.io/badge/License-MIT-green)

An enterprise-grade **Zero-Trust Git Orchestration Gateway**, **Cryptographic Chain-of-Custody Audit Ledger**, and **Out-of-Band Python SOAR Kill-Switch** engineered to secure high-concurrency autonomous AI coding swarms on **Cloudflare Artifacts**.

Designed under the **Argon 4 Red-Team Audit Methodology**, this system eliminates distributed Git lock contention while neutralizing the **NCSC "Lethal Trifecta"** (private credentials + untrusted inputs + network access), covert inter-agent steganographic collusion, and silent AI monitor failures.

---

## 1. Executive Summary & Threat Model

When hundreds of thousands of autonomous AI agents concurrently clone, branch, and push code, traditional Git locking mechanisms collapse and standard perimeter security fails. Worse, provisioning long-lived Git write tokens inside untrusted agent sandboxes allows prompt-injected or rogue agents to exfiltrate credentials, tamper with agent configuration files (`T1195.001`), or collude via invisible Unicode Tag steganography (`T1685.007`).

This repository implements a defense-in-depth containment architecture across four layers:
1. **Zero-Context Credential Brokering:** Agents never hold persistent credentials or unvetted write tokens inside their execution environment. The gateway issues a **60-second read-only token** (`scope: "read", ttl: 60`) for workspace cloning and only brokers a **60-second write token** after pre-merge sanitization succeeds.
2. **Deterministic "Cotton Act" Pre-Merge Gate:** Inspects diffs in microseconds prior to merge, blocking covert Unicode Tag (`U+E0000–U+E007F`) and Private Use Area (PUA) codepoints, coding agent config tampering (`.cursorrules`, `CLAUDE.md`, `.github/workflows`), and silent/empty AI monitor completions.
3. **Serialized SHA-256 Chain-of-Custody Ledger:** Uses a single-threaded `LedgerSequencer` Durable Object to serialize state transitions into a `STRICT` Cloudflare D1 SQLite database, preventing Time-of-Check to Time-of-Use (TOCTOU) race conditions under swarm concurrency.
4. **Authenticated Out-of-Band SOAR Kill-Switch:** A Python incident-response controller (`stas_artifacts_killswitch.py`) that emits canonical **OASIS STIX 2.1** indicator bundles with Traffic Light Protocol (`TLP:AMBER` / `TLP:RED`) markings and directly invokes the Cloudflare Artifacts REST API to revoke active tokens and purge compromised repository forks mid-session.

---

## 2. System Architecture

```text
+-----------------------------------------------------------------------------------+
|                        AUTONOMOUS AGENT SWARM (100K+ AGENTS)                      |
|   Isolated Ephemeral Sandboxes (No Long-Lived Keys / Zero-Context Brokering)      |
+-----------------------------------------+-----------------------------------------+
                                          |
                     1. Request Fork      |  2. Submit Diff to Pre-Merge Gate
                        (Read-Only 60s)   |     (Request 60s Write Token)
                                          v
+-----------------------------------------------------------------------------------+
|                  CLOUDFLARE WORKER: ZERO-TRUST GIT GATEWAY (Edge)                 |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | "COTTON ACT" DETERMINISTIC PRE-MERGE GATE                                   |  |
|  | - Tier-1 Physical Scrubber: Blocks Unicode Tags (U+E0000-E007F), PUA, BiDi  |  |
|  | - MITRE ATT&CK v20 Guard: Blocks .cursorrules / CLAUDE.md / Workflow edits  |  |
|  | - Fail-Closed Monitor Trap: Rejects empty/malformed AI review completions   |  |
|  +-----------------------------------------------------------------------------+  |
+-------------------+-----------------------------------+---------------------------+
                    |                                   |
   3a. Clean Diff   |                                   | 3b. Every Action / Fault
   (Fork / Token)   v                                   v     Strictly Serialized
+---------------------------------------+   +---------------------------------------+
|     CLOUDFLARE ARTIFACTS PLATFORM     |   |   DURABLE OBJECT: LedgerSequencer     |
| - Namespace Zero-Trust Isolation      |   | - Single-Threaded Actor Serialization |
| - Native Smart HTTP Git v1/v2 Remote  |   | - Eliminates TOCTOU Hash Forking      |
| - Ephemeral Fork Per Agent Session    |   +-------------------+-------------------+
+-------------------+-------------------+                       |
                    ^                                           | 4. Atomic Flush
                    | 6. Out-of-Band REST API                   v
                    |    DELETE /tokens/:id     +-----------------------------------+
                    |    DELETE /repos/:fork    |   CLOUDFLARE D1 (STRICT SQLite)   |
+-------------------+-------------------+       | - Immutable SHA-256 Hash Chain    |
|   PYTHON SOAR KILL-SWITCH CONTROLLER  |<------+ - STIX 2.1 & TLP Marking Metadata |
|   (scripts/stas_artifacts_killswitch) |  5.   +-----------------------------------+
| - Constant-Time X-TAXII-API-KEY Auth  |  High Risk Score / Containment Fault
| - OASIS STIX 2.1 Bundle Generation    |
+---------------------------------------+
```

---

## 3. Argon 4 Red-Team Audit & Vulnerability Remediation Matrix

An adversarial audit of initial v1.0 edge-gateway patterns identified five critical vulnerabilities under high-concurrency swarm conditions, all remediated in v2.0:

| Vulnerability ID | v1.0 Architectural Flaw | Risk / Exploit Vector | v2.0 Argon 4 Remediation |
| :--- | :--- | :--- | :--- |
| **VULN-01: The "Illusory Quarantine" & Double-Token Bug** | Quarantine only updated `status = 'QUARANTINED'` in D1 without revoking the active Git token. Calling `fork()` also silently minted an untracked default write token. | Because `git push` talks directly to `*.artifacts.cloudflare.net`, a quarantined agent could keep pushing malicious code for up to 1 hour. | Immediately revokes the default write token returned by `fork()`, tracks `active_token_id` in D1, and calls `DELETE .../tokens/:token_id` and `DELETE .../repos/:fork_name` via the Artifacts REST API. |
| **VULN-02: D1 Hash-Chain TOCTOU Race Condition** | Stateless Worker isolates ran `SELECT event_hash ... LIMIT 1` followed by an asynchronous `INSERT`. | 1,000 agents hitting the gateway in the same millisecond read the identical `previous_event_hash`, shattering the linear chain into a forked tree. | Routed all ledger writes through the single-threaded `LedgerSequencer` Durable Object, with an in-actor promise queue that strictly serializes `previous_event_hash -> event_hash` transitions even across await interleaving. |
| **VULN-03: Sandbox "Lethal Trifecta"** | Injected a 3,600-second write token directly into the agent container's environment variables. | Prompt-injected agents reading `/proc/self/environ` could exfiltrate write credentials and force-push unvetted code. | Enforced **Zero-Context Credential Brokering**: agents receive a 60s `read` token on initialization; 60s `write` tokens are minted only after pre-merge verification. |
| **VULN-04: Covert Steganography & Silent Monitor Failures** | Relied on naive string matching over AI code-review monitor outputs without pre-tokenization sanitization. | Agents collude via invisible Unicode Tag characters (`U+E0000–U+E007F`) that bypass LLM monitors or trigger empty completions (149/150 silent failures). | Implemented the **Cotton Act Pre-Merge Gate**: microsecond regex scrubbing for Tag/PUA/BiDi codepoints (`T1685.007`), config tamper checks (`T1195.001`), and fail-closed empty-reply trapping. |
| **VULN-05: Unauthenticated Control Plane** | `/api/v1/quarantine` lacked authentication and used ad-hoc threat strings. | Unauthenticated attackers could trigger denial-of-service by quarantining arbitrary production agents. | Enforced constant-time byte-comparison verification on `X-TAXII-API-KEY` (Web Crypto has no `timingSafeEqual`; a XOR-accumulate comparison is used) and standardized telemetry on OASIS STIX 2.1 bundles with canonical TLP UUIDs. |

---

## 4. Cryptographic Chain-of-Custody Specification

To satisfy forensic integrity and non-To satisfy forensic integrity and non-repudiation requirements, `schema_v2.sql` enforces SQLite `STRICT` typing and links every event row $i$ to row $i-1$ via a deterministic SHA-256 digest serialized by the `LedgerSequencer` Durable Object:

$$\text{event-hash}_i = \text{SHA256}\left(\text{event-hash}_{i-1} \parallel \text{payload-hash}_i \parallel \text{agent-id}_i \parallel \text{timestamp}_i\right)$$


---

## 5. Repository Structure

```text
cloudflare-zero-trust-git-gateway/
├── wrangler.jsonc                        # Cloudflare Workers, D1, Durable Objects & Artifacts bindings
├── schema_v2.sql                         # STRICT SQLite schema for agents & SHA-256 hash-chained ledger
├── src/
│   └── index.ts                          # Zero-Trust Gateway, Cotton Act Gate & LedgerSequencer DO
├── scripts/
│   ├── stas_artifacts_killswitch.py      # Out-of-Band Python SOAR controller & STIX 2.1 generator
│   └── simulate_swarm.py                 # End-to-end red-team & benign swarm verification harness
└── graphql/
    └── soc_telemetry_queries.graphql     # Cloudflare GraphQL Analytics queries for anomaly hunting
```

---

## 6. Quick-Start & Local Red-Team Simulation

### Prerequisites
* **Node.js** (`v20+`) and **Wrangler CLI** (`v4.145.0+`)
* **Python** (`v3.10+`) for the SOAR kill-switch and swarm simulator

### Step 1: Install Dependencies & Initialize Local D1 Ledger
```bash
npm install
npx wrangler d1 execute audit_ledger --local --file=./schema_v2.sql
```

### Step 2: Configure Local Environment Secrets (`.dev.vars`)
Create a `.dev.vars` file in the project root (automatically ignored by `.gitignore`):
```ini
TAXII_API_KEY="soc-secret-taxii-key-2026-workday-demo"
CF_ACCOUNT_ID="your_cloudflare_account_id"
CF_API_TOKEN="your_cloudflare_api_token"
ARTIFACTS_NAMESPACE="default"
```

### Step 3: Start the Edge Gateway
```bash
npx wrangler dev --port 8787 --local
```

### Step 4: Execute the Red-Team Swarm Verification Harness
In a second terminal, run the automated simulation script:
```bash
python3 scripts/simulate_swarm.py
```

#### Expected Simulation Output
```text
=== [1] Provisioning Ephemeral Read-Only Workspace for Benign Agent ===
HTTP 200 -> Fork: agent-fork-agent-alpha-01-1792419000 | Scope: read | TTL: 60s

=== [2] Benign Agent Submitting Clean Diff to Cotton Act Gate ===
HTTP 200 -> Status: APPROVED_FOR_PUSH | Write Token Minted (TTL 60s)

=== [3] Provisioning Workspace for Rogue Agent (agent-rogue-99) ===
HTTP 200 -> Fork: agent-fork-agent-rogue-99-1792419001

=== [4] Rogue Agent Attempting Covert Unicode Tag Injection (U+E0001) ===
HTTP 422 -> Gate Verdict: REJECTED_CONTAINMENT_FAULT | Reason: TIER1_COVERT_UNICODE_DETECTED (MITRE T1685.007 / Steganography)

=== [5] Firing Out-of-Band SOAR Kill-Switch (STIX 2.1 + Token Revocation) ===
SOAR Action -> Status: QUARANTINED | Revoked Token: tok_...

=== [6] Verifying Quarantined Rogue Agent Cannot Re-Provision ===
HTTP 403 -> Agent Unauthorized or Quarantined

=== [7] Auditing D1 Cryptographic SHA-256 Hash Chain Integrity ===
HTTP 200 -> Chain Intact: True | Verified Events: 5 | Head Hash: 8f4c...
```

---

## 7. Macro SOC Observability (Cloudflare GraphQL Analytics)

Alongside per-commit D1 forensic logging, `graphql/soc_telemetry_queries.graphql` queries Cloudflare's native `artifactsEventsAdaptiveGroups` GraphQL dataset with zero Worker compute overhead:
* **`DetectRogueAgentSwarms`:** Aggregates `eventKind == "error"` counts by `repositoryNamespace` to identify brute-force scanning or looping agent swarms.
* **`DetectPayloadAnomalies`:** Compares `durationMsP99` against `avg.durationMs` per namespace to spot bloated diffs or algorithmic complexity denial-of-service attempts.

---

## 8. License

Released under the **MIT License**. Engineered by **Brendan McGullion** (7 Rings DMC — Applied Science & Security Division).
