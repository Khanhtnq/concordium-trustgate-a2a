from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import Any

from .agent_card import (
    build_agent_card,
    compute_agent_card_hash,
    verify_agent_card,
)
from .audit_eu_ai import AccountableExecutionLedger
from .badge import (
    decode_cis8004_badge,
    encode_cis8004_badge,
    format_caip19,
)
from .mcp_server import MCPTrustGateHandler
from .x402_rail import (
    create_x402_payment_payload,
    generate_402_challenge,
    settle_x402_sponsored_payment,
)
from .zk_gate import (
    create_zk_challenge,
    generate_zk_proof_response,
    verify_zk_access_proof,
)


def run_demo_flow(json_out: bool = False) -> dict[str, Any]:
    """Execute complete 5-vector Concordium TrustGate Accountable Agent Commerce transaction."""
    # 1. Badge & CAIP-19 Resolution
    token_id = 42
    contract_index = 10082
    contract_subindex = 0
    short_badge = encode_cis8004_badge(contract_index, contract_subindex, token_id)
    caip19_mainnet = format_caip19(short_badge, "mainnet")
    caip19_testnet = format_caip19(short_badge, "testnet")

    # 2. Combined ERC-8004 + A2A v1.0 Agent Card
    ccd_account = "3y9m7R88888888888888888888888888888888888888"
    agent_card = build_agent_card(
        name="Concordium TrustGate Autonomous Auditor",
        description="Enterprise autonomous compliance agent enforcing privacy-preserving zero-gas commerce.",
        version="1.0.0",
        image_uri="https://trustgate.agency/assets/agent.png",
        services=[
            {"name": "A2A", "endpoint": "https://agent.trustgate.agency/a2a", "version": "1.0.0"},
            {"name": "MCP", "endpoint": "https://agent.trustgate.agency/mcp", "version": "2025-06-18"}
        ],
        token_id=token_id,
        ccd_account=ccd_account,
        network="mainnet"
    )
    metadata_hash = compute_agent_card_hash(agent_card)
    on_chain_state = {
        "status": "Active",
        "metadata_hash": metadata_hash,
        "owner": ccd_account
    }
    card_verification = verify_agent_card(agent_card, on_chain_state)

    # 3. Web3Id Zero-Knowledge Attribute Policy Gate
    zk_challenges: dict[str, dict[str, Any]] = {}
    client_id = "A2A-CLIENT-NODE-01"
    zk_challenge = create_zk_challenge(
        client_id=client_id,
        requested_attributes=["age_over_18", "jurisdiction_allowed", "accredited_operator"]
    )
    zk_challenges[zk_challenge["challenge_id"]] = zk_challenge

    zk_signer_secret = hashlib.sha256(b"CONCORDIUM_WEB3ID_SEED_SECRET").digest()
    zk_proof = generate_zk_proof_response(
        challenge=zk_challenge,
        subject_account=ccd_account,
        attribute_claims={
            "age_over_18": True,
            "country_code": "DK",  # Denmark (EU)
            "accredited_operator": True
        },
        signer_secret=zk_signer_secret
    )
    zk_result = verify_zk_access_proof(zk_proof, zk_challenges, expected_signer_secret=zk_signer_secret)

    # 4. x402 Sponsored Micropayment Settlement
    x402_challenges: dict[str, dict[str, Any]] = {}
    price_micro_ccd = 250000  # 0.25 CCD
    recipient = "4B2H5j88888888888888888888888888888888888888"
    sponsor = "3SponsorRelayerAccount8888888888888888888888"
    x402_ch = generate_402_challenge(
        resource_uri="/v1/execute-audit",
        price_micro_ccd=price_micro_ccd,
        recipient_address=recipient,
        sponsor_relayer=sponsor
    )
    x402_challenges[x402_ch["challenge_nonce"]] = x402_ch

    tx_hash = hashlib.sha256(f"MOCK_TX:{x402_ch['challenge_nonce']}:42".encode()).hexdigest()
    payment_payload = create_x402_payment_payload(x402_ch, sender_address=ccd_account, tx_hash=tx_hash)
    processed_txs: set[str] = set()
    x402_settlement = settle_x402_sponsored_payment(payment_payload, x402_challenges, processed_txs)

    # 5. EU AI Act Article 12 Accountable Execution Ledger
    ledger = AccountableExecutionLedger()
    task_input = "Compute cross-border AML risk assessment for Nordic corporate registry"
    task_output = "Risk Score: 0.02 (Minimal Risk). Automated clearance granted under EU AMLD-6."

    rec = ledger.log_execution(
        agent_badge=short_badge,
        owner_caip10=agent_card["extensions"]["concordiumBadge"]["ownerCaip10"],
        zk_policy_hash=zk_result["policy_hash"],
        x402_receipt_hash=x402_settlement["receipt_hash"],
        task_input=task_input,
        task_output=task_output
    )
    cert = ledger.generate_audit_certificate(0)

    report = {
        "status": "SUCCESS",
        "protocol": "Concordium TrustGate A2A",
        "standard_alignment": [
            "Concordium CIS-8004 Agent Registry",
            "CAIP-19 Asset Identifier",
            "ERC-8004 + A2A v1.0 Agent Card",
            "Concordium CIS-8 Cross-Chain Key Registry",
            "Concordium Web3Id Zero-Knowledge Attribute Gate",
            "Concordium x402 Sponsored PLT Micropayments (0-Gas)",
            "EU AI Act Article 12 RFC-6962 Accountable Ledger"
        ],
        "step_1_badge": {
            "short_badge": short_badge,
            "contract_index": contract_index,
            "contract_subindex": contract_subindex,
            "token_id": token_id,
            "caip19_mainnet": caip19_mainnet,
            "caip19_testnet": caip19_testnet
        },
        "step_2_agent_card": {
            "name": agent_card["name"],
            "version": agent_card["version"],
            "metadata_hash": metadata_hash,
            "on_chain_verified": card_verification["verified"]
        },
        "step_3_web3id_zk": {
            "policy_passed": zk_result["policy_passed"],
            "verified_attributes": zk_result["verified_attributes"],
            "policy_hash": zk_result["policy_hash"]
        },
        "step_4_x402_micropayment": {
            "settled": x402_settlement["settled"],
            "amount_micro_ccd": x402_settlement["amount_micro_ccd"],
            "user_gas_fee": x402_settlement["user_gas_fee"],
            "sponsor": x402_settlement["sponsor_relayer"],
            "tx_hash": x402_settlement["tx_hash"],
            "explorer_url": x402_settlement["explorer_url"]
        },
        "step_5_eu_ai_act_audit": {
            "record_id": rec.record_id,
            "merkle_root": cert["merkle_root"],
            "proof_verified": cert["proof_verified"],
            "compliance_standard": cert["compliance_standard"]
        }
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print("[*] CONCORDIUM TRUSTGATE A2A: END-TO-END ACCOUNTABLE TRANSACTION")
        print("=" * 72)
        print(f"[+] Step 1 (CIS-8004 Badge):   {short_badge}")
        print(f"    CAIP-19 Mainnet:          {caip19_mainnet}")
        print(f"[+] Step 2 (Agent Card):      {agent_card['name']} (v{agent_card['version']})")
        print(f"    SHA-256 Metadata Hash:    {metadata_hash}")
        print(f"    On-Chain Status:          {on_chain_state['status']} (Verified: {card_verification['verified']})")
        print(f"[+] Step 3 (Web3Id ZK Gate):  Passed ({', '.join(zk_result['verified_attributes'])})")
        print(f"    Policy Commitment Hash:   {zk_result['policy_hash'][:16]}...")
        print(f"[+] Step 4 (x402 Sponsored):  {x402_settlement['amount_micro_ccd']} microCCD settled")
        print(f"    User Gas Fee:             {x402_settlement['user_gas_fee']} CCD (100% Sponsored)")
        print(f"    Tx Hash:                  {x402_settlement['tx_hash']}")
        print(f"    Explorer URL:             {x402_settlement['explorer_url']}")
        print(f"[+] Step 5 (EU AI Act Art12): {cert['compliance_standard']}")
        print(f"    Record ID:                {rec.record_id}")
        print(f"    RFC-6962 Merkle Root:     {cert['merkle_root']}")
        print(f"    Inclusion Proof Valid:    {cert['proof_verified']}")
        print("=" * 72)
        print("[*] RESULT: 100% ACCOUNTABLE AUTONOMOUS AGENT COMMERCE ACHIEVED")
        print("=" * 72)

    return report


def run_benchmark(iterations: int = 200, json_out: bool = False) -> dict[str, Any]:
    """Measure per-vector cryptographic latency across all 5 TrustGate compliance stages."""
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    token_id = 42
    contract_index = 10082
    contract_subindex = 0
    short_badge = encode_cis8004_badge(contract_index, contract_subindex, token_id)
    ccd_account = "3y9m7R88888888888888888888888888888888888888"

    t0 = time.perf_counter()
    for _ in range(iterations):
        decode_cis8004_badge(short_badge)
        format_caip19(short_badge, "mainnet")
    v1_ms = (time.perf_counter() - t0) * 1000.0 / iterations

    agent_card = build_agent_card(
        name="Concordium TrustGate Autonomous Auditor",
        description="Enterprise autonomous compliance agent enforcing privacy-preserving zero-gas commerce.",
        version="1.0.0",
        image_uri="https://trustgate.agency/assets/agent.png",
        services=[
            {"name": "A2A", "endpoint": "https://agent.trustgate.agency/a2a", "version": "1.0.0"},
            {"name": "MCP", "endpoint": "https://agent.trustgate.agency/mcp", "version": "2025-06-18"}
        ],
        token_id=token_id,
        ccd_account=ccd_account,
        network="mainnet"
    )
    metadata_hash = compute_agent_card_hash(agent_card)
    on_chain_state = {"status": "Active", "metadata_hash": metadata_hash, "owner": ccd_account}

    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_agent_card(agent_card, on_chain_state)
    v2_ms = (time.perf_counter() - t0) * 1000.0 / iterations

    zk_secret = hashlib.sha256(b"CONCORDIUM_WEB3ID_SEED_SECRET").digest()
    t0 = time.perf_counter()
    for _ in range(iterations):
        ch_map: dict[str, dict[str, Any]] = {}
        ch = create_zk_challenge("A2A-CLIENT-NODE-01", ["age_over_18", "jurisdiction_allowed", "accredited_operator"])
        ch_map[ch["challenge_id"]] = ch
        proof = generate_zk_proof_response(
            ch, ccd_account,
            {"age_over_18": True, "country_code": "DK", "accredited_operator": True},
            zk_secret
        )
        verify_zk_access_proof(proof, ch_map, expected_signer_secret=zk_secret)
    v3_ms = (time.perf_counter() - t0) * 1000.0 / iterations

    t0 = time.perf_counter()
    for i in range(iterations):
        x_map: dict[str, dict[str, Any]] = {}
        c402 = generate_402_challenge(
            "/v1/execute-audit", 250000,
            "4B2H5j88888888888888888888888888888888888888",
            "3SponsorRelayerAccount8888888888888888888888"
        )
        x_map[c402["challenge_nonce"]] = c402
        payload = create_x402_payment_payload(c402, ccd_account, f"{i:064x}")
        settle_x402_sponsored_payment(payload, x_map, set())
    v4_ms = (time.perf_counter() - t0) * 1000.0 / iterations

    ledger = AccountableExecutionLedger()
    owner_caip10 = agent_card["extensions"]["concordiumBadge"]["ownerCaip10"]
    t0 = time.perf_counter()
    for i in range(iterations):
        ledger.log_execution(short_badge, owner_caip10, "policy_hash", "receipt_hash", "input", "output")
        cert = ledger.generate_audit_certificate(i)
        AccountableExecutionLedger.verify_audit_certificate(cert)
    v5_ms = (time.perf_counter() - t0) * 1000.0 / iterations

    total_ms = v1_ms + v2_ms + v3_ms + v4_ms + v5_ms
    result = {
        "iterations": iterations,
        "vectors": {
            "cis8004_badge_resolution_ms": round(v1_ms, 4),
            "erc8004_a2a_card_verify_ms": round(v2_ms, 4),
            "web3id_zk_policy_gate_ms": round(v3_ms, 4),
            "x402_0gas_settlement_ms": round(v4_ms, 4),
            "eu_ai_act_rfc6962_merkle_ms": round(v5_ms, 4),
        },
        "total_pipeline_ms": round(total_ms, 4),
        "throughput_tx_per_sec": round(1000.0 / total_ms, 1) if total_ms > 0 else 0.0,
    }

    if json_out:
        print(json.dumps(result, indent=2))
    else:
        print(f"Concordium TrustGate A2A Benchmark ({iterations} iterations/vector)")
        print(f"  1. CIS-8004 Badge + CAIP-19 Resolution : {result['vectors']['cis8004_badge_resolution_ms']:.4f} ms")
        print(f"  2. ERC-8004 + A2A Card Integrity       : {result['vectors']['erc8004_a2a_card_verify_ms']:.4f} ms")
        print(f"  3. Web3Id ZK Policy Gate (0-PII)       : {result['vectors']['web3id_zk_policy_gate_ms']:.4f} ms")
        print(f"  4. x402 0-Gas microCCD Settlement      : {result['vectors']['x402_0gas_settlement_ms']:.4f} ms")
        print(f"  5. EU AI Act Art. 12 RFC-6962 Receipt  : {result['vectors']['eu_ai_act_rfc6962_merkle_ms']:.4f} ms")
        print(
            f"  Total End-to-End 5-Vector Latency      : "
            f"{result['total_pipeline_ms']:.4f} ms ({result['throughput_tx_per_sec']} tx/s)"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description="Concordium TrustGate A2A CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # demo-flow
    demo_parser = subparsers.add_parser("demo-flow", help="Run 5-vector end-to-end accountable transaction")
    demo_parser.add_argument("--json-out", action="store_true", help="Print structured JSON output")

    # mint-card
    mint_parser = subparsers.add_parser("mint-card", help="Build and display canonical Agent Card")
    mint_parser.add_argument("--name", default="Concordium Agent", help="Agent name")
    mint_parser.add_argument("--desc", default="Autonomous accountable agent on Concordium.", help="Description")
    mint_parser.add_argument("--token-id", type=int, default=1, help="Token ID")
    mint_parser.add_argument("--account", default="4B2H5j88888888888888888888888888888888888888", help="CCD account")

    # verify-badge
    badge_parser = subparsers.add_parser("verify-badge", help="Decode and inspect CIS-8004 badge")
    badge_parser.add_argument("badge", help="CIS-8004 Base58Check short badge string")

    # mcp-tools
    subparsers.add_parser("mcp-tools", help="List registered Model Context Protocol tools")

    # benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Measure 5-vector latency benchmarks")
    bench_parser.add_argument("--iterations", type=int, default=200, help="Iterations per vector")
    bench_parser.add_argument("--json-out", action="store_true", help="Print structured JSON output")

    args = parser.parse_args()

    if args.command == "demo-flow" or not args.command:
        json_mode = getattr(args, "json_out", False)
        run_demo_flow(json_out=json_mode)

    elif args.command == "mint-card":
        card = build_agent_card(
            name=args.name,
            description=args.desc,
            version="1.0.0",
            image_uri="https://trustgate.agency/assets/agent.png",
            services=[{"name": "A2A", "endpoint": "https://agent.example.com/a2a", "version": "1.0.0"}],
            token_id=args.token_id,
            ccd_account=args.account
        )
        print(json.dumps(card, indent=2))

    elif args.command == "verify-badge":
        idx, subidx, tok = decode_cis8004_badge(args.badge)
        caip19_m = format_caip19(args.badge, "mainnet")
        caip19_t = format_caip19(args.badge, "testnet")
        print(json.dumps({
            "short_badge": args.badge,
            "contract_index": idx,
            "contract_subindex": subidx,
            "token_id": tok,
            "caip19_mainnet": caip19_m,
            "caip19_testnet": caip19_t
        }, indent=2))

    elif args.command == "mcp-tools":
        handler = MCPTrustGateHandler()
        tools = handler.list_tools()
        print(json.dumps(tools, indent=2))

    elif args.command == "benchmark":
        run_benchmark(iterations=args.iterations, json_out=getattr(args, "json_out", False))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
