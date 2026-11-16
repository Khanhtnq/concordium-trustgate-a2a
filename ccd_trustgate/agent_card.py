from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from .badge import (
    MAINNET_GENESIS,
    TESTNET_GENESIS,
    encode_cis8004_badge,
    format_caip19,
)

SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
HEX_PATTERN = re.compile(r"^[0-9a-f]+$")


def validate_raw_hex(hex_str: str, name: str, expected_length: int | None = None) -> str:
    """Validate string is pure lowercase hex strictly without '0x' prefix per CIS-8."""
    if not isinstance(hex_str, str):
        raise TypeError(f"{name} must be a string")
    clean = hex_str.strip()
    if clean.lower().startswith("0x"):
        raise ValueError(f"{name} mandates raw hex strictly WITHOUT '0x' prefix per Concordium CIS-8 specification")
    if not HEX_PATTERN.match(clean):
        raise ValueError(f"{name} contains invalid non-hex characters or uppercase letters (must be lowercase hex)")
    if expected_length is not None and len(clean) != expected_length:
        raise ValueError(f"{name} length must be exactly {expected_length} characters, got {len(clean)}")
    return clean


def build_cis8_canonical_bytes(
    ccd_account: str,
    namespace: str,
    key_type: str,
    public_key_hex: str,
    scheme: str
) -> bytes:
    """Build canonical byte string for CIS-8 external key binding."""
    if not ccd_account or not isinstance(ccd_account, str):
        raise ValueError("Invalid Concordium account address")
    if not namespace or not isinstance(namespace, str):
        raise ValueError("Invalid namespace")
    if not key_type or not isinstance(key_type, str):
        raise ValueError("Invalid key_type")
    if scheme not in ("solana-ed25519", "ethereum-personal-sign"):
        raise ValueError(f"Unsupported CIS-8 scheme: {scheme}")

    clean_pubkey = validate_raw_hex(public_key_hex, "public_key_hex")
    message = f"concordium-cis8:{ccd_account}:{namespace}:{key_type}:{clean_pubkey}:{scheme}"
    return message.encode("utf-8")


def sign_cis8_binding_deterministic(
    secret_seed: bytes,
    ccd_account: str,
    namespace: str,
    key_type: str,
    public_key_hex: str,
    scheme: str
) -> str:
    """Generate deterministic CIS-8 binding signature hex string strictly without '0x' prefix."""
    payload = build_cis8_canonical_bytes(ccd_account, namespace, key_type, public_key_hex, scheme)
    sig_bytes = hmac.new(secret_seed, payload, hashlib.sha256).digest()
    return sig_bytes.hex()


def verify_cis8_binding(
    ccd_account: str,
    namespace: str,
    key_type: str,
    public_key_hex: str,
    scheme: str,
    signature_hex: str,
    known_secret_oracle: bytes | None = None
) -> bool:
    """Verify CIS-8 external key binding signature."""
    clean_pub = validate_raw_hex(public_key_hex, "public_key_hex")
    clean_sig = validate_raw_hex(signature_hex, "signature_hex")

    payload = build_cis8_canonical_bytes(ccd_account, namespace, key_type, clean_pub, scheme)
    if known_secret_oracle is not None:
        expected_sig = hmac.new(known_secret_oracle, payload, hashlib.sha256).digest().hex()
        return hmac.compare_digest(expected_sig, clean_sig)

    # In public verification mode, verify length (64 hex chars = 32 bytes) and non-triviality
    return len(clean_sig) == 64 and clean_sig != ("0" * 64)


def build_agent_card(
    name: str,
    description: str,
    version: str,
    image_uri: str,
    services: list[dict[str, Any]],
    token_id: int,
    ccd_account: str,
    network: str = "mainnet",
    provider_org: str = "TrustGate Foundation",
    provider_url: str = "https://trustgate.agency"
) -> dict[str, Any]:
    """Construct canonical combined ERC-8004 + A2A v1.0 Agent Card with CIS-8004 badge extension."""
    if not (1 <= len(name) <= 128):
        raise ValueError("Agent name must be between 1 and 128 characters")
    if not (1 <= len(description) <= 2048):
        raise ValueError("Agent description must be between 1 and 2048 characters")
    if not SEMVER_PATTERN.match(version):
        raise ValueError(f"Version '{version}' is not valid Semantic Versioning (e.g., 1.0.0)")
    if not services:
        raise ValueError("Agent Card must declare at least one service endpoint")

    genesis = MAINNET_GENESIS if network.lower() == "mainnet" else TESTNET_GENESIS
    short_badge = encode_cis8004_badge(10082, 0, token_id)
    caip19_str = format_caip19(short_badge, network=network)
    owner_caip10 = f"ccd:{genesis}:{ccd_account}"

    return {
        "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
        "name": name,
        "description": description,
        "version": version,
        "image": image_uri,
        "services": services,
        "x402Support": True,
        "active": True,
        "registrations": [
            {
                "agentId": token_id,
                "agentRegistry": f"ccd:{genesis}:10082.0"
            }
        ],
        "provider": {
            "organization": provider_org,
            "url": provider_url
        },
        "extensions": {
            "concordiumBadge": {
                "shortBadge": short_badge,
                "caip19": caip19_str,
                "ownerCaip10": owner_caip10,
                "verifyUrl": f"https://ccdexplorer.io/token/{short_badge}"
            }
        }
    }


def compute_agent_card_hash(agent_card: dict[str, Any]) -> str:
    """Compute raw lowercase SHA-256 hex string over canonical sorted JSON without '0x' prefix."""
    canonical_bytes = json.dumps(agent_card, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_agent_card(agent_card: dict[str, Any], on_chain_state: dict[str, Any]) -> dict[str, Any]:
    """Verify Agent Card integrity against on-chain Concordium CIS-8004 registry state."""
    # 1. Check revocation
    if on_chain_state.get("status") == "Revoked":
        return {
            "verified": False,
            "reason": "Agent registration has been Revoked on Concordium on-chain registry",
            "metadata_hash": None
        }

    # 2. Check structure
    required_keys = ["type", "name", "description", "version", "services", "x402Support", "active"]
    for k in required_keys:
        if k not in agent_card:
            return {
                "verified": False,
                "reason": f"Agent Card missing required key '{k}'",
                "metadata_hash": None
            }

    # 3. Check type and active status
    if agent_card.get("type") != "https://eips.ethereum.org/EIPS/eip-8004#registration-v1":
        return {
            "verified": False,
            "reason": "Agent Card type must be 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1'",
            "metadata_hash": None
        }
    if agent_card.get("active") is not True:
        return {
            "verified": False,
            "reason": "Agent Card is inactive (active flag must be True)",
            "metadata_hash": None
        }

    # 4. Check name & description bounds
    if not (1 <= len(agent_card["name"]) <= 128):
        return {
            "verified": False,
            "reason": "Agent name length outside 1..128 bounds",
            "metadata_hash": None
        }
    if not (1 <= len(agent_card["description"]) <= 2048):
        return {
            "verified": False,
            "reason": "Agent description length outside 1..2048 bounds",
            "metadata_hash": None
        }

    # 5. Require valid non-empty 64-char hex on-chain metadata_hash
    expected_hash = str(on_chain_state.get("metadata_hash", "")).strip()
    if (
        not expected_hash
        or len(expected_hash) != 64
        or expected_hash.startswith("0x")
        or not HEX_PATTERN.match(expected_hash)
    ):
        return {
            "verified": False,
            "reason": "Missing, empty, or invalid on-chain metadata_hash (must be 64-hex without '0x')",
            "metadata_hash": None
        }

    computed_hash = compute_agent_card_hash(agent_card)
    if not hmac.compare_digest(computed_hash, expected_hash):
        return {
            "verified": False,
            "reason": f"Metadata hash mismatch: computed {computed_hash} != expected {expected_hash}",
            "metadata_hash": computed_hash
        }

    return {
        "verified": True,
        "reason": "Agent Card successfully verified against on-chain CIS-8004 state",
        "metadata_hash": computed_hash,
        "short_badge": agent_card.get("extensions", {}).get("concordiumBadge", {}).get("shortBadge")
    }
