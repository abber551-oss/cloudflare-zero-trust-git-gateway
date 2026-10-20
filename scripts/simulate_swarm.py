#!/usr/bin/env python3
"""
End-to-End Swarm & Red-Team Verification Harness
"""
import json
import urllib.request
import urllib.error
from stas_artifacts_killswitch import trigger_quarantine

GATEWAY_URL = "http://127.0.0.1:8787"


def call_gateway(path: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        f"{GATEWAY_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def run_simulation():
    print("=== [1] Provisioning Ephemeral Read-Only Workspace for Benign Agent ===")
    code, res = call_gateway("/api/v1/provision", "POST", {"agent_id": "agent-alpha-01"})
    print(f"HTTP {code} -> Fork: {res.get('fork_name')} | Scope: {res.get('scope')} | TTL: {res.get('ttl')}s")

    print("\n=== [2] Benign Agent Submitting Clean Diff to Cotton Act Gate ===")
    clean_diff = "+++ b/src/auth.ts\n+export function validateSession(id: string): boolean { return id.length > 0; }"
    code, res = call_gateway(
        "/api/v1/pre-merge",
        "POST",
        {"agent_id": "agent-alpha-01", "target_path": "src/auth.ts", "diff_content": clean_diff},
    )
    print(f"HTTP {code} -> Status: {res.get('status')} | Write Token Minted (TTL {res.get('ttl')}s)")

    print("\n=== [3] Provisioning Workspace for Rogue Agent (agent-rogue-99) ===")
    code, res = call_gateway("/api/v1/provision", "POST", {"agent_id": "agent-rogue-99"})
    print(f"HTTP {code} -> Fork: {res.get('fork_name')}")

    print("\n=== [4] Rogue Agent Attempting Covert Unicode Tag Injection (U+E0001) ===")
    poisoned_diff = "+++ b/src/config.ts\n+// Standard comment \U000E0001\U000E0041\U000E007F"
    code, res = call_gateway(
        "/api/v1/pre-merge",
        "POST",
        {"agent_id": "agent-rogue-99", "target_path": "src/config.ts", "diff_content": poisoned_diff},
    )
    print(f"HTTP {code} -> Gate Verdict: {res.get('status')} | Reason: {res.get('reason')}")

    if code == 422:
        print("\n=== [5] Firing Out-of-Band SOAR Kill-Switch (STIX 2.1 + Token Revocation) ===")
        soar_res = trigger_quarantine(
            agent_id="agent-rogue-99",
            reason=res.get("reason", "Covert Unicode steganography blocked at pre-merge gate"),
            risk_score=100,
        )
        print(f"SOAR Action -> Status: {soar_res.get('status')} | Revoked Token: {soar_res.get('revoked_token_id')}")

    print("\n=== [6] Verifying Quarantined Rogue Agent Cannot Re-Provision ===")
    code, res = call_gateway("/api/v1/provision", "POST", {"agent_id": "agent-rogue-99"})
    print(f"HTTP {code} -> {res.get('error')}")

    print("\n=== [7] Auditing D1 Cryptographic SHA-256 Hash Chain Integrity ===")
    code, res = call_gateway("/api/v1/ledger/verify", "GET")
    print(
        f"HTTP {code} -> Chain Intact: {res.get('chain_intact')} | "
        f"Verified Events: {res.get('total_verified_events')} | "
        f"Head Hash: {res.get('latest_head_hash')}"
    )


if __name__ == "__main__":
    run_simulation()
