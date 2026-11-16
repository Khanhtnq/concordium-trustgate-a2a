from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from typing import Any

from .agent_card import (
    build_agent_card,
    compute_agent_card_hash,
    verify_agent_card,
)
from .audit_eu_ai import (
    AccountableExecutionLedger,
)
from .badge import (
    decode_cis8004_badge,
    format_caip19,
)
from .x402_rail import (
    settle_x402_sponsored_payment,
)
from .zk_gate import (
    verify_zk_access_proof,
)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "concordium-trustgate-mcp"
SERVER_VERSION = "1.0.0"


class MCPTrustGateHandler:
    """In-process and stdio JSON-RPC 2.0 MCP handler for Concordium TrustGate."""

    def __init__(self, zk_issuer_secret: bytes | None = None):
        self.zk_issuer_secret = zk_issuer_secret or hashlib.sha256(b"concordium-web3id-testnet-issuer-v1").digest()
        self.active_zk_challenges: dict[str, dict[str, Any]] = {}
        self.active_x402_challenges: dict[str, dict[str, Any]] = {}
        self.processed_txs: set[str] = set()
        self.audit_ledger = AccountableExecutionLedger()
        self.on_chain_registry: dict[str, dict[str, Any]] = {}

        # Seed initial on-chain mock for demonstration and unit testing
        self._seed_default_registry()

    def _seed_default_registry(self) -> None:
        """Seed default canonical Agent Card on Concordium contract (10082, 0)."""
        card = build_agent_card(
            name="TrustGate Settlement Agent",
            description="Autonomous Concordium Accountable Agent facilitating zero-gas x402 sponsored micropayments.",
            version="1.0.0",
            image_uri="https://trustgate.agency/icon.png",
            services=[
                {"name": "A2A", "endpoint": "https://agent.trustgate.agency/a2a", "version": "1.0.0"},
                {"name": "MCP", "endpoint": "https://agent.trustgate.agency/mcp", "version": "2025-06-18"}
            ],
            token_id=1,
            ccd_account="4B2H5j88888888888888888888888888888888888888",
            network="mainnet"
        )
        card_hash = compute_agent_card_hash(card)
        badge = card["extensions"]["concordiumBadge"]["shortBadge"]

        self.on_chain_registry[badge] = {
            "status": "Active",
            "contract_index": 10082,
            "contract_subindex": 0,
            "token_id": 1,
            "owner": "4B2H5j88888888888888888888888888888888888888",
            "metadata_hash": card_hash,
            "card": card
        }

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP tools manifest."""
        return [
            {
                "name": "parse_concordium_badge",
                "description": "Decode CIS-8004 Base58Check short badge and resolve CAIP-19 asset identifier.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "badge": {"type": "string", "description": "Concordium CIS-8004 Base58Check badge string"}
                    },
                    "required": ["badge"]
                }
            },
            {
                "name": "verify_agent_card",
                "description": "Verify ERC-8004 + A2A Agent Card integrity and on-chain registration state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_card": {"type": "object", "description": "Agent Card JSON payload"},
                        "on_chain_state": {
                            "type": "object",
                            "description": "Registry record containing metadata_hash and status"
                        }
                    },
                    "required": ["agent_card", "on_chain_state"]
                }
            },
            {
                "name": "verify_zk_access_proof",
                "description": "Verify Web3Id ZK attribute proof (age_over_18, jurisdiction, accredited).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof_payload": {"type": "object", "description": "Client ZK response payload"}
                    },
                    "required": ["proof_payload"]
                }
            },
            {
                "name": "settle_x402_sponsored_payment",
                "description": "Settle Concordium x402 sponsored PLT micropayment with zero gas fee guarantee.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payment_payload": {"type": "object", "description": "X-PAYMENT header signed payload"}
                    },
                    "required": ["payment_payload"]
                }
            },
            {
                "name": "execute_accountable_agent_task",
                "description": "Execute trusted agent task across 5 vectors and record EU AI Act audit proof.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "badge": {"type": "string"},
                        "zk_proof": {"type": "object"},
                        "x402_payment": {"type": "object"},
                        "task_input": {"type": "string"}
                    },
                    "required": ["badge", "zk_proof", "x402_payment", "task_input"]
                }
            },
            {
                "name": "verify_eu_ai_audit_proof",
                "description": "Verify an EU AI Act Article 12 compliance certificate using RFC-6962 inclusion proofs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "audit_certificate": {"type": "object"}
                    },
                    "required": ["audit_certificate"]
                }
            }
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool by name with arguments."""
        if name == "parse_concordium_badge":
            badge_str = arguments.get("badge", "")
            idx, subidx, tok = decode_cis8004_badge(badge_str)
            caip19_mainnet = format_caip19(badge_str, "mainnet")
            caip19_testnet = format_caip19(badge_str, "testnet")
            return {
                "short_badge": badge_str,
                "contract_index": idx,
                "contract_subindex": subidx,
                "token_id": tok,
                "caip19_mainnet": caip19_mainnet,
                "caip19_testnet": caip19_testnet
            }

        elif name == "verify_agent_card":
            card = arguments.get("agent_card", {})
            state = arguments.get("on_chain_state", {})
            return verify_agent_card(card, state)

        elif name == "verify_zk_access_proof":
            proof = arguments.get("proof_payload", {})
            return verify_zk_access_proof(
                proof, self.active_zk_challenges, expected_signer_secret=self.zk_issuer_secret
            )

        elif name == "settle_x402_sponsored_payment":
            payment = arguments.get("payment_payload", {})
            return settle_x402_sponsored_payment(payment, self.active_x402_challenges, self.processed_txs)

        elif name == "execute_accountable_agent_task":
            badge = arguments.get("badge", "")
            zk_proof = arguments.get("zk_proof", {})
            x402_payment = arguments.get("x402_payment", {})
            task_input = arguments.get("task_input", "")

            # 1. Badge lookup
            if badge not in self.on_chain_registry:
                return {"success": False, "reason": "Unregistered Concordium Agent Badge"}
            reg = self.on_chain_registry[badge]

            # 2. Agent card check
            card_res = verify_agent_card(reg["card"], reg)
            if not card_res.get("verified"):
                return {"success": False, "reason": f"Agent Card validation failed: {card_res.get('reason')}"}

            # 3. ZK check
            zk_res = verify_zk_access_proof(
                zk_proof, self.active_zk_challenges, expected_signer_secret=self.zk_issuer_secret
            )
            if not zk_res.get("verified"):
                return {"success": False, "reason": f"Web3Id ZK policy gate failed: {zk_res.get('reason')}"}

            # 4. x402 payment settlement
            x402_res = settle_x402_sponsored_payment(x402_payment, self.active_x402_challenges, self.processed_txs)
            if not x402_res.get("settled"):
                return {"success": False, "reason": f"x402 payment settlement failed: {x402_res.get('reason')}"}

            # 5. Task execution
            task_output = f"Processed input '{task_input}' for verified agent {badge}"

            # 6. EU AI Act Article 12 Merkle Audit Recording
            owner_caip10 = reg["card"]["extensions"]["concordiumBadge"]["ownerCaip10"]
            rec = self.audit_ledger.log_execution(
                agent_badge=badge,
                owner_caip10=owner_caip10,
                zk_policy_hash=zk_res["policy_hash"],
                x402_receipt_hash=x402_res["receipt_hash"],
                task_input=task_input,
                task_output=task_output
            )
            cert = self.audit_ledger.generate_audit_certificate(len(self.audit_ledger.records) - 1)

            return {
                "success": True,
                "agent_badge": badge,
                "task_output": task_output,
                "zk_policy_passed": True,
                "x402_tx_hash": x402_res["tx_hash"],
                "eu_ai_act_record_id": rec.record_id,
                "merkle_root": cert["merkle_root"],
                "audit_certificate": cert
            }

        elif name == "verify_eu_ai_audit_proof":
            cert = arguments.get("audit_certificate", {})
            is_valid = AccountableExecutionLedger.verify_audit_certificate(cert)
            return {
                "valid": is_valid,
                "merkle_root": cert.get("merkle_root"),
                "record_id": cert.get("record_id")
            }

        else:
            raise ValueError(f"Unknown tool name: {name}")

    def handle_jsonrpc(self, req: dict[str, Any]) -> dict[str, Any]:
        """Process incoming JSON-RPC 2.0 request."""
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION
                    },
                    "capabilities": {
                        "tools": {"listChanged": False}
                    }
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.list_tools()
                }
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                out = self.call_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(out, indent=2)}
                        ]
                    }
                }
            except (ValueError, TypeError, KeyError, IndexError, RuntimeError, OSError) as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(e)
                    }
                }

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }

    @staticmethod
    def connect_hosted_mcp(
        url: str = "https://agent-registry-mcp.concordium.com/mcp",
        timeout_sec: float = 2.0
    ) -> dict[str, Any] | None:
        """Optional connector querying Concordium's hosted Agent Registry MCP."""
        try:
            req_data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode("utf-8")
            http_req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "ConcordiumTrustGate/1.0"}
            )
            with urllib.request.urlopen(http_req, timeout=timeout_sec) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        return None
