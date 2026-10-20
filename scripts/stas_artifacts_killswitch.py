#!/usr/bin/env python3
"""
7 Rings STAS - Out-of-Band SOAR Kill-Switch for Cloudflare Artifacts
Serializes threat telemetry into OASIS STIX 2.1 bundles and revokes compromised agent tokens.
"""
import os
import uuid
import json
import urllib.request
from datetime import datetime, timezone

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8787")
TAXII_API_KEY = os.getenv("TAXII_API_KEY", "soc-secret-taxii-key-2026-workday-demo")


def build_stix21_bundle(agent_id: str, reason: str, risk_score: int) -> dict:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator_id = f"indicator--{uuid.uuid4()}"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"Rogue Autonomous Agent Containment: {agent_id}",
                "description": reason,
                "pattern": f"[x-cloudflare-agent:id = '{agent_id}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": min(risk_score, 100),
                "object_marking_refs": [
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                ],
                "external_references": [
                    {
                        "source_name": "MITRE ATT&CK",
                        "external_id": "T1685.007",
                        "description": "Covert Unicode Tag Injection / Steganographic Collusion",
                    }
                ],
            }
        ],
    }


def trigger_quarantine(agent_id: str, reason: str, risk_score: int = 95) -> dict:
    stix_bundle = build_stix21_bundle(agent_id, reason, risk_score)
    payload = json.dumps(
        {
            "agent_id": agent_id,
            "reason": reason,
            "stix_bundle": stix_bundle,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{GATEWAY_URL}/api/v1/quarantine",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-TAXII-API-KEY": TAXII_API_KEY,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


if __name__ == "__main__":
    result = trigger_quarantine(
        agent_id="agent-rogue-99",
        reason="Manual SOC Kill-Switch: Covert Unicode Tag payload detected in pre-merge diff.",
    )
    print(json.dumps(result, indent=2))
