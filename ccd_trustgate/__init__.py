"""Concordium TrustGate A2A: Accountable Autonomous Agent Commerce & Compliance Gateway."""

from __future__ import annotations

from .agent_card import (
    build_agent_card,
    build_cis8_canonical_bytes,
    compute_agent_card_hash,
    sign_cis8_binding_deterministic,
    validate_raw_hex,
    verify_agent_card,
    verify_cis8_binding,
)
from .audit_eu_ai import (
    AccountableExecutionLedger,
    AccountableExecutionRecord,
    Rfc6962MerkleTree,
)
from .badge import (
    MAINNET_CIS8_KEY_INDEX,
    MAINNET_CIS8_KEY_SUBINDEX,
    MAINNET_CIS8_MODULE,
    MAINNET_GENESIS,
    MAINNET_REGISTRY_INDEX,
    MAINNET_REGISTRY_MODULE,
    MAINNET_REGISTRY_SUBINDEX,
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
from .mcp_server import (
    MCPTrustGateHandler,
)
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

__version__ = "1.0.0"
__all__ = [
    "MAINNET_CIS8_KEY_INDEX",
    "MAINNET_CIS8_KEY_SUBINDEX",
    "MAINNET_CIS8_MODULE",
    "MAINNET_GENESIS",
    "MAINNET_REGISTRY_INDEX",
    "MAINNET_REGISTRY_MODULE",
    "MAINNET_REGISTRY_SUBINDEX",
    "TESTNET_GENESIS",
    "AccountableExecutionLedger",
    "AccountableExecutionRecord",
    "MCPTrustGateHandler",
    "Rfc6962MerkleTree",
    "b58decode",
    "b58encode",
    "build_agent_card",
    "build_cis8_canonical_bytes",
    "compute_agent_card_hash",
    "create_x402_payment_payload",
    "create_zk_challenge",
    "decode_cis8004_badge",
    "decode_uleb128",
    "encode_cis8004_badge",
    "encode_uleb128",
    "format_caip19",
    "generate_402_challenge",
    "generate_zk_proof_response",
    "parse_caip19",
    "settle_x402_sponsored_payment",
    "sign_cis8_binding_deterministic",
    "validate_raw_hex",
    "verify_agent_card",
    "verify_cis8_binding",
    "verify_zk_access_proof",
]
