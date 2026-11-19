from __future__ import annotations

import hashlib
import json
import unittest

from ccd_trustgate.agent_card import (
    build_agent_card,
    compute_agent_card_hash,
    sign_cis8_binding_deterministic,
    validate_raw_hex,
    verify_agent_card,
    verify_cis8_binding,
)
from ccd_trustgate.audit_eu_ai import (
    AccountableExecutionLedger,
    Rfc6962MerkleTree,
)
from ccd_trustgate.badge import (
    MAINNET_GENESIS,
    TESTNET_GENESIS,
    b58decode,
    b58encode,
    decode_cis8004_badge,
    decode_uleb128,
    encode_cis8004_badge,
    encode_uleb128,
    format_caip19,
    parse_caip19,
)
from ccd_trustgate.cli import run_benchmark, run_demo_flow
from ccd_trustgate.mcp_server import MCPTrustGateHandler
from ccd_trustgate.x402_rail import (
    create_x402_payment_payload,
    generate_402_challenge,
    settle_x402_sponsored_payment,
)
from ccd_trustgate.zk_gate import (
    create_zk_challenge,
    generate_zk_proof_response,
    verify_zk_access_proof,
)


class TestConcordiumTrustGate(unittest.TestCase):

    # --- 1. CIS-8004 Badge & CAIP-19 Tests ---

    def test_01_uleb128_roundtrip_and_boundaries(self):
        test_values = [0, 1, 63, 64, 127, 128, 255, 256, 10082, 16383, 16384, (1 << 64) - 1]
        for val in test_values:
            encoded = encode_uleb128(val)
            decoded, offset = decode_uleb128(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, len(encoded))

    def test_02_uleb128_invalid_inputs(self):
        with self.assertRaises(ValueError):
            encode_uleb128(-1)
        with self.assertRaises(ValueError):
            decode_uleb128(b"")

    def test_03_base58_encoding_decoding_roundtrip(self):
        data = b"\x00\x00\x01\x02\x03\xff\xfe\xfd"
        encoded = b58encode(data)
        decoded = b58decode(encoded)
        self.assertEqual(decoded, data)

    def test_04_cis8004_badge_encode_decode_roundtrip(self):
        badge = encode_cis8004_badge(10082, 0, 42)
        idx, subidx, tok = decode_cis8004_badge(badge)
        self.assertEqual(idx, 10082)
        self.assertEqual(subidx, 0)
        self.assertEqual(tok, 42)

    def test_05_cis8004_badge_tampered_checksum_rejected(self):
        badge = encode_cis8004_badge(10082, 0, 42)
        # Flip characters in the badge to corrupt checksum
        tampered = badge[:-2] + ("1" if badge[-1] != "1" else "2") + badge[-1]
        with self.assertRaises(ValueError):
            decode_cis8004_badge(tampered)

    def test_06_cis8004_token_id_range_rejection(self):
        with self.assertRaises(ValueError):
            encode_cis8004_badge(10082, 0, -1)
        with self.assertRaises(ValueError):
            encode_cis8004_badge(10082, 0, 1 << 64)

    def test_07_caip19_formatting_and_parsing(self):
        badge = encode_cis8004_badge(10082, 0, 99)
        caip19_m = format_caip19(badge, "mainnet")
        self.assertTrue(caip19_m.startswith(f"ccd:{MAINNET_GENESIS}/cis-2:"))

        parsed = parse_caip19(caip19_m)
        self.assertEqual(parsed["network"], "mainnet")
        self.assertEqual(parsed["token_id"], 99)
        self.assertEqual(parsed["contract_index"], 10082)

        caip19_t = format_caip19(badge, "testnet")
        self.assertTrue(caip19_t.startswith(f"ccd:{TESTNET_GENESIS}/cis-2:"))
        parsed_t = parse_caip19(caip19_t)
        self.assertEqual(parsed_t["network"], "testnet")

    def test_08_invalid_caip19_rejected(self):
        with self.assertRaises(ValueError):
            parse_caip19("ethereum:1/erc721:123")
        with self.assertRaises(ValueError):
            parse_caip19(f"ccd:{MAINNET_GENESIS}:wrong_format")

    # --- 2. ERC-8004 + A2A v1.0 Agent Card & CIS-8 Binding Tests ---

    def test_09_build_agent_card_structure(self):
        card = build_agent_card(
            name="Compliance Bot",
            description="Automated risk assessor.",
            version="1.0.0",
            image_uri="https://trustgate.agency/bot.png",
            services=[{"name": "A2A", "endpoint": "https://bot.example.com", "version": "1.0.0"}],
            token_id=7,
            ccd_account="4B2H5j88888888888888888888888888888888888888"
        )
        self.assertEqual(card["type"], "https://eips.ethereum.org/EIPS/eip-8004#registration-v1")
        self.assertTrue(card["x402Support"])
        self.assertTrue(card["active"])
        self.assertIn("concordiumBadge", card["extensions"])

    def test_10_agent_card_name_and_description_bounds(self):
        with self.assertRaises(ValueError):
            build_agent_card("", "desc", "1.0.0", "https://img.png", [{"name": "A2A"}], 1, "4B2H5...")
        with self.assertRaises(ValueError):
            build_agent_card("A" * 129, "desc", "1.0.0", "https://img.png", [{"name": "A2A"}], 1, "4B2H5...")
        with self.assertRaises(ValueError):
            build_agent_card("Valid Name", "D" * 2049, "1.0.0", "https://img.png", [{"name": "A2A"}], 1, "4B2H5...")
        with self.assertRaises(ValueError):
            build_agent_card("Valid Name", "desc", "not-semver", "https://img.png", [{"name": "A2A"}], 1, "4B2H5...")

    def test_11_agent_card_verification_success_and_tamper(self):
        card = build_agent_card(
            name="Auditor Agent",
            description="EU AI Act auditor.",
            version="2.1.0",
            image_uri="https://img.png",
            services=[{"name": "A2A", "endpoint": "https://a.com", "version": "1.0.0"}],
            token_id=10,
            ccd_account="4B2H5j88888888888888888888888888888888888888"
        )
        h = compute_agent_card_hash(card)
        state = {"status": "Active", "metadata_hash": h}

        res = verify_agent_card(card, state)
        self.assertTrue(res["verified"])

        # Tamper name
        tampered_card = dict(card)
        tampered_card["name"] = "Tampered Auditor"
        tampered_res = verify_agent_card(tampered_card, state)
        self.assertFalse(tampered_res["verified"])
        self.assertIn("Metadata hash mismatch", tampered_res["reason"])

    def test_12_revoked_agent_rejected(self):
        card = build_agent_card(
            name="Revoked Bot",
            description="Bad actor bot.",
            version="1.0.0",
            image_uri="https://img.png",
            services=[{"name": "A2A", "endpoint": "https://a.com", "version": "1.0.0"}],
            token_id=11,
            ccd_account="4B2H5..."
        )
        h = compute_agent_card_hash(card)
        state = {"status": "Revoked", "metadata_hash": h}
        res = verify_agent_card(card, state)
        self.assertFalse(res["verified"])
        self.assertIn("Revoked", res["reason"])

    def test_13_cis8_raw_hex_validation_rejects_0x_prefix(self):
        # Raw lowercase hex is valid
        valid_hex = "0123456789abcdef" * 4
        self.assertEqual(validate_raw_hex(valid_hex, "test_key"), valid_hex)

        # "0x" prefix MUST raise ValueError per CIS-8 mandate
        with self.assertRaises(ValueError):
            validate_raw_hex("0x" + valid_hex, "test_key")

        # Uppercase hex rejected
        with self.assertRaises(ValueError):
            validate_raw_hex(valid_hex.upper(), "test_key")

    def test_14_cis8_binding_signature_roundtrip(self):
        seed = b"TEST_CONCORDIUM_CIS8_SEED_123456"
        ccd_acc = "4B2H5j88888888888888888888888888888888888888"
        pubkey = hashlib.sha256(b"solana_pubkey").hexdigest()

        sig = sign_cis8_binding_deterministic(
            secret_seed=seed,
            ccd_account=ccd_acc,
            namespace="solana",
            key_type="ed25519",
            public_key_hex=pubkey,
            scheme="solana-ed25519"
        )
        self.assertFalse(sig.startswith("0x"))
        self.assertEqual(len(sig), 64)

        verified = verify_cis8_binding(
            ccd_account=ccd_acc,
            namespace="solana",
            key_type="ed25519",
            public_key_hex=pubkey,
            scheme="solana-ed25519",
            signature_hex=sig,
            known_secret_oracle=seed
        )
        self.assertTrue(verified)

    # --- 3. Web3Id Zero-Knowledge Policy Gate Tests ---

    def test_15_zk_gate_challenge_creation(self):
        ch = create_zk_challenge("client_01", ["age_over_18", "jurisdiction_allowed"])
        self.assertTrue(ch["challenge_id"].startswith("ZKC-"))
        self.assertEqual(len(ch["challenge_nonce"]), 64)
        self.assertFalse(ch["challenge_nonce"].startswith("0x"))
        self.assertGreater(ch["expires_at"], ch["issued_at"])

    def test_16_zk_gate_proof_verification_success(self):
        challenges = {}
        ch = create_zk_challenge("client_01", ["age_over_18", "jurisdiction_allowed"])
        challenges[ch["challenge_id"]] = ch

        secret = b"ZK_SECRET_KEY_SEED"
        proof = generate_zk_proof_response(
            challenge=ch,
            subject_account="4B2H5...",
            attribute_claims={"age_over_18": True, "country_code": "DE"},
            signer_secret=secret
        )

        res = verify_zk_access_proof(proof, challenges, expected_signer_secret=secret)
        self.assertTrue(res["verified"])
        self.assertTrue(res["policy_passed"])

    def test_17_zk_gate_nonce_anti_replay(self):
        challenges = {}
        ch = create_zk_challenge("client_01", ["age_over_18"])
        challenges[ch["challenge_id"]] = ch

        secret = b"ZK_SECRET_KEY_SEED"
        proof = generate_zk_proof_response(
            challenge=ch,
            subject_account="4B2H5...",
            attribute_claims={"age_over_18": True},
            signer_secret=secret
        )

        # First verification succeeds
        res1 = verify_zk_access_proof(proof, challenges, expected_signer_secret=secret)
        self.assertTrue(res1["verified"])

        # Second verification fails because challenge was consumed
        res2 = verify_zk_access_proof(proof, challenges, expected_signer_secret=secret)
        self.assertFalse(res2["verified"])
        self.assertIn("already consumed", res2["reason"])

    def test_18_zk_gate_sanctioned_jurisdiction_rejected(self):
        challenges = {}
        ch = create_zk_challenge("client_01", ["jurisdiction_allowed"])
        challenges[ch["challenge_id"]] = ch

        secret = b"ZK_SECRET_KEY_SEED"
        proof = generate_zk_proof_response(
            challenge=ch,
            subject_account="4B2H5...",
            attribute_claims={"country_code": "KP"},  # North Korea (Sanctioned)
            signer_secret=secret
        )

        res = verify_zk_access_proof(proof, challenges, expected_signer_secret=secret)
        self.assertFalse(res["verified"])
        self.assertIn("not satisfied", res["reason"])

    def test_19_zk_gate_zero_pii_leak_prevention(self):
        ch = create_zk_challenge("client_01", ["age_over_18"])
        secret = b"ZK_SECRET_KEY_SEED"

        # Attempting to insert raw PII must immediately raise ValueError
        with self.assertRaises(ValueError):
            generate_zk_proof_response(
                challenge=ch,
                subject_account="4B2H5...",
                attribute_claims={"age_over_18": True, "date_of_birth": "1990-01-01"},
                signer_secret=secret
            )

        with self.assertRaises(ValueError):
            generate_zk_proof_response(
                challenge=ch,
                subject_account="4B2H5...",
                attribute_claims={"age_over_18": True, "passport_number": "A12345678"},
                signer_secret=secret
            )

    # --- 4. x402 Sponsored PLT Micropayment Tests ---

    def test_20_x402_challenge_and_settlement(self):
        challenges = {}
        ch = generate_402_challenge("/api/predict", 50000, "4Recipient...", "3SponsorRelayer...")
        challenges[ch["challenge_nonce"]] = ch

        tx_hash = hashlib.sha256(b"TX_RECEIPT_1").hexdigest()
        payment = create_x402_payment_payload(ch, "4Sender...", tx_hash)
        self.assertEqual(payment["user_gas_fee"], 0)

        processed = set()
        settlement = settle_x402_sponsored_payment(payment, challenges, processed)
        self.assertTrue(settlement["settled"])
        self.assertEqual(settlement["user_gas_fee"], 0)
        self.assertIn("testnet.ccdexplorer.io", settlement["explorer_url"])

    def test_21_x402_replay_tx_rejected(self):
        challenges = {}
        ch = generate_402_challenge("/api/predict", 50000, "4Recipient...", "3SponsorRelayer...")
        challenges[ch["challenge_nonce"]] = ch

        tx_hash = hashlib.sha256(b"TX_RECEIPT_2").hexdigest()
        payment = create_x402_payment_payload(ch, "4Sender...", tx_hash)

        processed = {tx_hash}  # Pre-mark as processed
        settlement = settle_x402_sponsored_payment(payment, challenges, processed)
        self.assertFalse(settlement["settled"])
        self.assertIn("replay detected", settlement["reason"])

    def test_22_x402_non_zero_user_gas_rejected(self):
        challenges = {}
        ch = generate_402_challenge("/api/predict", 50000, "4Recipient...", "3SponsorRelayer...")
        challenges[ch["challenge_nonce"]] = ch

        tx_hash = hashlib.sha256(b"TX_RECEIPT_3").hexdigest()
        payment = create_x402_payment_payload(ch, "4Sender...", tx_hash)
        payment["user_gas_fee"] = 100  # Violate zero-gas invariant

        processed = set()
        settlement = settle_x402_sponsored_payment(payment, challenges, processed)
        self.assertFalse(settlement["settled"])
        self.assertIn("user_gas_fee", settlement["reason"])

    # --- 5. EU AI Act Article 12 RFC-6962 Merkle Ledger Tests ---

    def test_23_rfc6962_merkle_tree_cve_2012_2459_immunity(self):
        """Merkle tree with 3 leaves must strictly differ from 4 leaves where 4th is copy of 3rd."""
        tree_odd = Rfc6962MerkleTree(["leaf_a", "leaf_b", "leaf_c"])
        tree_dup = Rfc6962MerkleTree(["leaf_a", "leaf_b", "leaf_c", "leaf_c"])
        self.assertNotEqual(tree_odd.get_root(), tree_dup.get_root())

    def test_24_rfc6962_inclusion_proofs_across_arbitrary_counts(self):
        """get_proof and verify_proof must succeed for all indices across counts 1..10."""
        for n in range(1, 11):
            leaves = [f"rec_{i}" for i in range(n)]
            tree = Rfc6962MerkleTree(leaves)
            root = tree.get_root()
            self.assertEqual(len(root), 64)
            for idx in range(n):
                proof = tree.get_proof(idx)
                leaf_hash = tree.leaves[idx]
                self.assertTrue(
                    Rfc6962MerkleTree.verify_proof(leaf_hash, proof, root),
                    f"Failed at n={n}, idx={idx}"
                )
                self.assertTrue(tree.verify_leaf(leaf_hash))

    def test_25_accountable_execution_ledger_certificate(self):
        ledger = AccountableExecutionLedger()
        rec = ledger.log_execution(
            agent_badge="Mf22oWt8BKonzdwrwFqCM",
            owner_caip10=f"ccd:{MAINNET_GENESIS}:4B2H5...",
            zk_policy_hash=hashlib.sha256(b"zk").hexdigest(),
            x402_receipt_hash=hashlib.sha256(b"receipt").hexdigest(),
            task_input="Verify AML status",
            task_output="Clean"
        )
        self.assertTrue(rec.record_id.startswith("REC-"))
        cert = ledger.generate_audit_certificate(0)
        self.assertTrue(cert["proof_verified"])
        self.assertTrue(AccountableExecutionLedger.verify_audit_certificate(cert))

        # Tampering with certificate fields must cause verification failure
        tampered_badge_cert = dict(cert)
        tampered_badge_cert["agent_badge"] = "FORGED_BADGE"
        self.assertFalse(AccountableExecutionLedger.verify_audit_certificate(tampered_badge_cert))

        tampered_owner_cert = dict(cert)
        tampered_owner_cert["owner_caip10"] = "ccd:forged:owner"
        self.assertFalse(AccountableExecutionLedger.verify_audit_certificate(tampered_owner_cert))

    def test_26_agent_card_auth_bypass_guards(self):
        """Empty metadata_hash, inactive card, or wrong type must be rejected."""
        card = build_agent_card(
            name="Test Bot",
            description="Test description.",
            version="1.0.0",
            image_uri="https://img.png",
            services=[{"name": "A2A", "endpoint": "https://a.com", "version": "1.0.0"}],
            token_id=1,
            ccd_account="4B2H5..."
        )
        valid_hash = compute_agent_card_hash(card)

        # 1. Empty metadata_hash rejected
        res_empty = verify_agent_card(card, {"status": "Active", "metadata_hash": ""})
        self.assertFalse(res_empty["verified"])
        self.assertIn("Missing, empty, or invalid", res_empty["reason"])

        # 2. Inactive card rejected
        inactive_card = dict(card)
        inactive_card["active"] = False
        res_inactive = verify_agent_card(inactive_card, {"status": "Active", "metadata_hash": valid_hash})
        self.assertFalse(res_inactive["verified"])
        self.assertIn("inactive", res_inactive["reason"])

        # 3. Wrong type rejected
        wrong_type_card = dict(card)
        wrong_type_card["type"] = "https://wrong.spec/v1"
        res_type = verify_agent_card(wrong_type_card, {"status": "Active", "metadata_hash": valid_hash})
        self.assertFalse(res_type["verified"])
        self.assertIn("type must be", res_type["reason"])

    # --- 6. MCP Server & CLI End-to-End Tests ---

    def test_27_mcp_handler_rejects_forged_zk_signature(self):
        """MCP server must enforce zk_issuer_secret HMAC and reject forged signature."""
        handler = MCPTrustGateHandler()

        # Create challenge
        ch = create_zk_challenge("client_mcp", ["age_over_18"])
        handler.active_zk_challenges[ch["challenge_id"]] = ch

        # Forge signature with 'a' * 64
        forged_proof = {
            "challenge_id": ch["challenge_id"],
            "challenge_nonce": ch["challenge_nonce"],
            "subject_id_hash": hashlib.sha256(b"subject").hexdigest(),
            "proven_attributes": {"age_over_18": True},
            "commitment_signature": "a" * 64,
            "timestamp": 123456789.0
        }

        call_res = handler.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "verify_zk_access_proof",
                "arguments": {"proof_payload": forged_proof}
            }
        })
        content_text = call_res["result"]["content"][0]["text"]
        parsed = json.loads(content_text)
        self.assertFalse(parsed["verified"])
        self.assertIn("signature verification failed", parsed["reason"])

    def test_28_mcp_handler_jsonrpc_tools_and_dispatch(self):
        handler = MCPTrustGateHandler()

        # 1. Initialize
        init_res = handler.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init_res["result"]["serverInfo"]["name"], "concordium-trustgate-mcp")

        # 2. Tools list
        tools_res = handler.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = tools_res["result"]["tools"]
        self.assertGreaterEqual(len(tools), 6)

        # 3. Tool call
        badge = encode_cis8004_badge(10082, 0, 1)
        call_res = handler.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "parse_concordium_badge",
                "arguments": {"badge": badge}
            }
        })
        content_text = call_res["result"]["content"][0]["text"]
        parsed = json.loads(content_text)
        self.assertEqual(parsed["token_id"], 1)

    def test_29_cli_demo_flow_end_to_end(self):
        report = run_demo_flow(json_out=True)
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(len(report["standard_alignment"]), 7)
        self.assertTrue(report["step_2_agent_card"]["on_chain_verified"])
        self.assertTrue(report["step_3_web3id_zk"]["policy_passed"])
        self.assertTrue(report["step_4_x402_micropayment"]["settled"])
        self.assertEqual(report["step_4_x402_micropayment"]["user_gas_fee"], 0)
        self.assertTrue(report["step_5_eu_ai_act_audit"]["proof_verified"])

    def test_30_adversarial_type_and_genesis_guards(self):
        """Reject bogus CAIP-19 genesis, nested PII, truthy-string ZK bypass, and bool False gas bypass."""
        badge = encode_cis8004_badge(10082, 0, 5)
        with self.assertRaises(ValueError):
            parse_caip19(f"ccd:deadbeef000000000000000000000000/cis-2:{badge}")
        with self.assertRaises(ValueError):
            format_caip19(badge, "devnet_unknown")

        # Nested PII inside proven_attributes must raise ValueError
        ch = create_zk_challenge("client_adv", ["age_over_18"])
        challenges = {ch["challenge_id"]: ch}
        with self.assertRaises(ValueError):
            verify_zk_access_proof(
                {
                    "challenge_id": ch["challenge_id"],
                    "challenge_nonce": ch["challenge_nonce"],
                    "proven_attributes": {"age_over_18": True, "ssn": "000-00-0000"},
                    "commitment_signature": "b" * 64,
                },
                challenges,
            )

        # Truthy string "false" in proven_attributes must be rejected
        res_truthy = verify_zk_access_proof(
            {
                "challenge_id": ch["challenge_id"],
                "challenge_nonce": ch["challenge_nonce"],
                "proven_attributes": {"age_over_18": "false"},
                "commitment_signature": "b" * 64,
            },
            challenges,
        )
        self.assertFalse(res_truthy["verified"])

        # Boolean False in user_gas_fee must be rejected (isinstance(False, int) guard)
        x_ch = generate_402_challenge("/api/v1", 1000, "4Rec...", "3Spo...")
        x_challenges = {x_ch["challenge_nonce"]: x_ch}
        tx_hash = hashlib.sha256(b"TX_BOOL_GAS").hexdigest()
        pay = create_x402_payment_payload(x_ch, "4Send...", tx_hash)
        pay["user_gas_fee"] = False
        settled = settle_x402_sponsored_payment(pay, x_challenges, set())
        self.assertFalse(settled["settled"])

    def test_31_cli_benchmark_execution(self):
        """CLI benchmark must return positive sub-millisecond/low-ms metrics for all 5 vectors."""
        res = run_benchmark(iterations=20, json_out=False)
        self.assertEqual(res["iterations"], 20)
        self.assertGreater(res["throughput_tx_per_sec"], 0.0)
        vectors = res["vectors"]
        for key in (
            "cis8004_badge_resolution_ms",
            "erc8004_a2a_card_verify_ms",
            "web3id_zk_policy_gate_ms",
            "x402_0gas_settlement_ms",
            "eu_ai_act_rfc6962_merkle_ms",
        ):
            self.assertIn(key, vectors)
            self.assertGreater(vectors[key], 0.0)
        with self.assertRaises(ValueError):
            run_benchmark(iterations=0)


if __name__ == "__main__":
    unittest.main()
