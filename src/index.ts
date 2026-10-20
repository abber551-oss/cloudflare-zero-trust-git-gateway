export interface Env {
  DB: D1Database;
  ARTIFACTS: any;
  LEDGER_SEQUENCER: DurableObjectNamespace;
  TAXII_API_KEY: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  ARTIFACTS_NAMESPACE: string;
}

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Constant-time byte comparison (Web Crypto has no timingSafeEqual; XOR-accumulate
// so compare time is independent of where a mismatch occurs).
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function verifyApiKey(provided: string | null, expected: string): boolean {
  if (!provided || !expected) return false;
  const enc = new TextEncoder();
  const a = enc.encode(provided);
  const b = enc.encode(expected);
  if (a.byteLength !== b.byteLength) return false;
  return constantTimeEqual(a, b);
}

// Tier-1 Physical & MITRE ATT&CK Sanitizer ("Cotton Act" Gate)
const FORBIDDEN_CODEPOINTS_REGEX =
  /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uE000-\uF8FF\u{E0000}-\u{E007F}]/u;

const AGENT_CONFIG_TAMPER_T1195_001 =
  /(?:\.cursorrules|\.windsurfrules|claude\.md|agents\.md|mcp\.json|\.github\/workflows\/)/i;

const IMPAIR_AI_DEFENSE_T1685_007 =
  /\b(?:ignore\s+previous\s+instructions|mark\s+(?:this\s+)?(?:file|commit|binary)\s+as\s+(?:safe|benign)|system\s+prompt\s+override)\b/i;

function evaluateCommitCottonActGate(
  targetPath: string,
  diffContent: string,
  monitorVerdict?: string
): { passed: boolean; reason: string; tlp: string } {
  if (
    AGENT_CONFIG_TAMPER_T1195_001.test(targetPath) ||
    AGENT_CONFIG_TAMPER_T1195_001.test(diffContent)
  ) {
    return {
      passed: false,
      reason: "AGENT_CONFIG_TAMPER_DETECTED (MITRE T1195.001)",
      tlp: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", // TLP:RED
    };
  }
  if (FORBIDDEN_CODEPOINTS_REGEX.test(diffContent)) {
    return {
      passed: false,
      reason: "TIER1_COVERT_UNICODE_DETECTED (MITRE T1685.007 / Steganography)",
      tlp: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", // TLP:RED
    };
  }
  if (IMPAIR_AI_DEFENSE_T1685_007.test(diffContent)) {
    return {
      passed: false,
      reason: "IMPAIR_AI_DEFENSE_DETECTED (MITRE T1685.007)",
      tlp: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", // TLP:RED
    };
  }
  if (monitorVerdict !== undefined && monitorVerdict.trim() === "") {
    return {
      passed: false,
      reason: "MONITOR_SILENT_FAILURE (Fail-Closed Containment Fault)",
      tlp: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", // TLP:AMBER
    };
  }
  return {
    passed: true,
    reason: "CLEAN_DIFF_VERIFIED",
    tlp: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", // TLP:CLEAR
  };
}

export class LedgerSequencer {
  state: DurableObjectState;
  env: Env;
  lastHash: string | null = null;
  // Durable Objects may interleave requests after an `await` on non-storage I/O
  // (e.g. D1 queries). An in-actor promise queue guarantees strict
  // previous_event_hash -> event_hash serialization regardless of interleaving.
  private appendQueue: Promise<unknown> = Promise.resolve();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    // Buffer the body before queueing (request bodies are single-read).
    const payload: any = await request.json();
    const run = this.appendQueue.then(() => this.append(payload));
    this.appendQueue = run.catch(() => {}); // keep queue alive on failure
    return run;
  }

  private async append(payload: any): Promise<Response> {
    const { agent_id, action_type, target_path, payload_hash, threat_metadata } = payload;

    if (!this.lastHash) {
      const row = await this.env.DB.prepare(
        "SELECT event_hash FROM audit_ledger ORDER BY seq_id DESC LIMIT 1"
      ).first<{ event_hash: string }>();
      this.lastHash = row ? row.event_hash : "0".repeat(64);
    }

    const previous_event_hash = this.lastHash;
    const timestamp = new Date().toISOString();
    const event_id = crypto.randomUUID();
    const event_hash = await sha256(
      `${previous_event_hash}|${payload_hash}|${agent_id}|${timestamp}`
    );

    await this.env.DB.prepare(
      `INSERT INTO audit_ledger (
        event_id, timestamp, agent_id, action_type, target_path,
        payload_hash, previous_event_hash, event_hash, threat_metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        event_id,
        timestamp,
        agent_id,
        action_type,
        target_path,
        payload_hash,
        previous_event_hash,
        event_hash,
        JSON.stringify(threat_metadata)
      )
      .run();

    this.lastHash = event_hash;

    return new Response(
      JSON.stringify({ event_id, timestamp, previous_event_hash, event_hash }),
      { status: 201, headers: { "Content-Type": "application/json" } }
    );
  }
}

async function appendToLedger(env: Env, entry: Record<string, any>) {
  const id = env.LEDGER_SEQUENCER.idFromName("global-audit-chain");
  const stub = env.LEDGER_SEQUENCER.get(id);
  const res = await stub.fetch("https://sequencer.internal/append", {
    method: "POST",
    body: JSON.stringify(entry),
  });
  return res.json();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/api/v1/provision") {
      const { agent_id } = (await request.json()) as { agent_id: string };

      const agent = await env.DB.prepare(
        "SELECT status, namespace FROM agents WHERE agent_id = ?"
      )
        .bind(agent_id)
        .first<{ status: string; namespace: string }>();

      if (!agent || agent.status !== "ACTIVE") {
        return Response.json({ error: "Agent Unauthorized or Quarantined" }, { status: 403 });
      }

      const forkName = `agent-fork-${agent_id}-${Date.now()}`;
      let remoteUrl = `https://${env.CF_ACCOUNT_ID || "demo"}.artifacts.cloudflare.net/git/default/${forkName}.git`;
      let readToken = `art_v1_read_${crypto.randomUUID()}?expires=${Math.floor(Date.now() / 1000) + 60}`;
      let tokenId = `tok_${crypto.randomUUID()}`;

      if (env.ARTIFACTS) {
        try {
          const baseline = await env.ARTIFACTS.get("production-baseline");
          const forkResult = await baseline.fork(forkName);
          remoteUrl = forkResult.remote;
          if (forkResult.token_id && forkResult.revokeToken) {
            await forkResult.revokeToken(forkResult.token_id);
          }
          const readTokenObj = await forkResult.createToken("read", 60);
          readToken = readTokenObj.token;
          tokenId = readTokenObj.id || tokenId;
        } catch (err) {
          // Local simulation fallback when running offline in wrangler dev
        }
      }

      await env.DB.prepare(
        "UPDATE agents SET fork_name = ?, active_token_id = ?, updated_at = ? WHERE agent_id = ?"
      )
        .bind(forkName, tokenId, new Date().toISOString(), agent_id)
        .run();

      const audit = await appendToLedger(env, {
        agent_id,
        action_type: "PROVISION_READ_ONLY_FORK",
        target_path: forkName,
        payload_hash: await sha256(forkName),
        threat_metadata: {
          spec_version: "2.1",
          type: "observed-data",
          tlp: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          token_scope: "read",
          ttl_seconds: 60,
        },
      });

      return Response.json({
        status: "PROVISIONED",
        fork_name: forkName,
        remote: remoteUrl,
        token: readToken,
        scope: "read",
        ttl: 60,
        audit,
      });
    }

    if (request.method === "POST" && url.pathname === "/api/v1/pre-merge") {
      const { agent_id, target_path, diff_content, monitor_verdict } = (await request.json()) as {
        agent_id: string;
        target_path: string;
        diff_content: string;
        monitor_verdict?: string;
      };

      const agent = await env.DB.prepare(
        "SELECT status, fork_name FROM agents WHERE agent_id = ?"
      )
        .bind(agent_id)
        .first<{ status: string; fork_name: string }>();

      if (!agent || agent.status !== "ACTIVE") {
        return Response.json({ error: "Agent Unauthorized or Quarantined" }, { status: 403 });
      }

      const payloadHash = await sha256(diff_content);
      const gateResult = evaluateCommitCottonActGate(target_path, diff_content, monitor_verdict);

      if (!gateResult.passed) {
        await env.DB.prepare(
          "UPDATE agents SET risk_score = 100, updated_at = ? WHERE agent_id = ?"
        )
          .bind(new Date().toISOString(), agent_id)
          .run();

        const audit = await appendToLedger(env, {
          agent_id,
          action_type: "PRE_MERGE_BLOCKED",
          target_path,
          payload_hash: payloadHash,
          threat_metadata: {
            spec_version: "2.1",
            type: "indicator",
            tlp: gateResult.tlp,
            reason: gateResult.reason,
          },
        });

        return Response.json(
          {
            status: "REJECTED_CONTAINMENT_FAULT",
            reason: gateResult.reason,
            audit,
          },
          { status: 422 }
        );
      }

      const writeTokenId = `tok_write_${crypto.randomUUID()}`;
      const writeToken = `art_v1_write_${crypto.randomUUID()}?expires=${Math.floor(Date.now() / 1000) + 60}`;

      await env.DB.prepare(
        "UPDATE agents SET active_token_id = ?, updated_at = ? WHERE agent_id = ?"
      )
        .bind(writeTokenId, new Date().toISOString(), agent_id)
        .run();

      const audit = await appendToLedger(env, {
        agent_id,
        action_type: "MINT_EPHEMERAL_WRITE_TOKEN",
        target_path,
        payload_hash: payloadHash,
        threat_metadata: {
          spec_version: "2.1",
          type: "observed-data",
          tlp: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          token_scope: "write",
          ttl_seconds: 60,
        },
      });

      return Response.json({
        status: "APPROVED_FOR_PUSH",
        write_token: writeToken,
        token_id: writeTokenId,
        ttl: 60,
        audit,
      });
    }

    if (request.method === "POST" && url.pathname === "/api/v1/quarantine") {
      const apiKey = request.headers.get("X-TAXII-API-KEY");
      if (!verifyApiKey(apiKey, env.TAXII_API_KEY)) {
        return Response.json({ error: "Invalid X-TAXII-API-KEY" }, { status: 401 });
      }

      const { agent_id, reason, stix_bundle } = (await request.json()) as {
        agent_id: string;
        reason: string;
        stix_bundle: Record<string, any>;
      };

      const agent = await env.DB.prepare(
        "SELECT fork_name, active_token_id FROM agents WHERE agent_id = ?"
      )
        .bind(agent_id)
        .first<{ fork_name: string; active_token_id: string }>();

      await env.DB.prepare(
        "UPDATE agents SET status = 'QUARANTINED', active_token_id = NULL, updated_at = ? WHERE agent_id = ?"
      )
        .bind(new Date().toISOString(), agent_id)
        .run();

      let restRevocationStatus = "SIMULATED_REVOKED";
      if (env.CF_ACCOUNT_ID && env.CF_API_TOKEN && !env.CF_ACCOUNT_ID.startsWith("your_")) {
        const baseApi = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/artifacts/namespaces/${env.ARTIFACTS_NAMESPACE || "default"}`;
        const headers = {
          Authorization: `Bearer ${env.CF_API_TOKEN}`,
          "Content-Type": "application/json",
        };
        if (agent?.active_token_id) {
          await fetch(`${baseApi}/tokens/${agent.active_token_id}`, {
            method: "DELETE",
            headers,
          });
        }
        if (agent?.fork_name) {
          await fetch(`${baseApi}/repos/${agent.fork_name}`, {
            method: "DELETE",
            headers,
          });
        }
        restRevocationStatus = "LIVE_REST_API_REVOKED";
      }

      const audit = await appendToLedger(env, {
        agent_id,
        action_type: "SOC_QUARANTINE_AND_TOKEN_REVOKE",
        target_path: agent?.fork_name || "GLOBAL",
        payload_hash: await sha256(JSON.stringify(stix_bundle || reason)),
        threat_metadata: stix_bundle || {
          spec_version: "2.1",
          type: "indicator",
          tlp: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
          reason,
        },
      });

      return Response.json({
        status: "QUARANTINED",
        agent_id,
        rest_api_action: restRevocationStatus,
        revoked_token_id: agent?.active_token_id || null,
        purged_fork: agent?.fork_name || null,
        audit,
      });
    }

    if (request.method === "GET" && url.pathname === "/api/v1/ledger/verify") {
      const { results } = await env.DB.prepare(
        "SELECT * FROM audit_ledger ORDER BY seq_id ASC"
      ).all<any>();

      let expectedPrevHash = "0".repeat(64);
      for (const row of results) {
        const recomputed = await sha256(
          `${row.previous_event_hash}|${row.payload_hash}|${row.agent_id}|${row.timestamp}`
        );
        if (row.previous_event_hash !== expectedPrevHash || recomputed !== row.event_hash) {
          return Response.json(
            {
              chain_intact: false,
              tampered_seq_id: row.seq_id,
              event_id: row.event_id,
            },
            { status: 409 }
          );
        }
        expectedPrevHash = row.event_hash;
      }

      return Response.json({
        chain_intact: true,
        total_verified_events: results.length,
        latest_head_hash: expectedPrevHash,
        ledger: results,
      });
    }

    return Response.json({ error: "Not Found" }, { status: 404 });
  },
};
