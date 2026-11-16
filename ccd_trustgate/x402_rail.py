from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any

HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def generate_402_challenge(
    resource_uri: str,
    price_micro_ccd: int,
    recipient_address: str,
    sponsor_relayer: str,
    ttl_seconds: int = 180
) -> dict[str, Any]:
    """Generate an HTTP 402 Payment Required challenge specification for Concordium PLT tokens."""
    if price_micro_ccd <= 0:
        raise ValueError("Price must be greater than zero microCCD")
    if not recipient_address:
        raise ValueError("Recipient address must be provided")
    if not sponsor_relayer:
        raise ValueError("Sponsor relayer address must be provided")

    now = time.time()
    nonce = hashlib.sha256(uuid.uuid4().bytes + uuid.uuid4().bytes).hexdigest()

    return {
        "status_code": 402,
        "header_name": "PAYMENT-REQUIRED",
        "resource_uri": resource_uri,
        "token": "PLT-microCCD",
        "amount_micro_ccd": price_micro_ccd,
        "recipient": recipient_address,
        "sponsor_relayer": sponsor_relayer,
        "challenge_nonce": nonce,
        "issued_at": now,
        "expires_at": now + ttl_seconds
    }


def create_x402_payment_payload(
    challenge: dict[str, Any],
    sender_address: str,
    tx_hash: str
) -> dict[str, Any]:
    """Client-side constructor for the X-PAYMENT response header/payload."""
    clean_tx = tx_hash.strip().lower()
    if clean_tx.startswith("0x"):
        raise ValueError("Concordium tx_hash mandates raw hex strictly WITHOUT '0x' prefix")
    if not HEX_64_PATTERN.match(clean_tx):
        raise ValueError("Invalid Concordium transaction hash: must be exactly 64 lowercase hex characters")

    return {
        "resource_uri": challenge["resource_uri"],
        "token": challenge["token"],
        "amount_micro_ccd": challenge["amount_micro_ccd"],
        "sender_address": sender_address,
        "recipient_address": challenge["recipient"],
        "challenge_nonce": challenge["challenge_nonce"],
        "sponsor_relayer": challenge["sponsor_relayer"],
        "user_gas_fee": 0,  # Zero-gas invariant guaranteed by Concordium sponsor relayer
        "tx_hash": clean_tx,
        "payment_timestamp": time.time()
    }


def settle_x402_sponsored_payment(
    payment_payload: dict[str, Any],
    active_challenges: dict[str, dict[str, Any]],
    processed_txs: set[str]
) -> dict[str, Any]:
    """Verify and settle x402 sponsored micropayment with replay protection and zero-gas invariant."""
    nonce = payment_payload.get("challenge_nonce")
    if not nonce or nonce not in active_challenges:
        return {
            "settled": False,
            "reason": "Payment challenge nonce not found, already consumed, or invalid"
        }

    challenge = active_challenges[nonce]

    # 1. Expiry check
    if time.time() > challenge["expires_at"]:
        del active_challenges[nonce]
        return {
            "settled": False,
            "reason": "Payment challenge has expired"
        }

    # Consume challenge nonce (anti-replay)
    del active_challenges[nonce]

    # 2. Transaction hash validation & replay check
    tx_hash = payment_payload.get("tx_hash", "").strip().lower()
    if tx_hash.startswith("0x") or not HEX_64_PATTERN.match(tx_hash):
        return {
            "settled": False,
            "reason": "Invalid Concordium tx_hash format (must be 64-hex without '0x')"
        }

    if tx_hash in processed_txs:
        return {
            "settled": False,
            "reason": "Transaction replay detected: tx_hash has already been settled"
        }

    # 3. Parameter checks
    amount = payment_payload.get("amount_micro_ccd")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < challenge["amount_micro_ccd"]:
        return {
            "settled": False,
            "reason": f"Insufficient or invalid payment amount: {amount} < {challenge['amount_micro_ccd']}"
        }

    if payment_payload.get("recipient_address") != challenge["recipient"]:
        return {
            "settled": False,
            "reason": "Payment recipient address does not match challenge specification"
        }

    # 4. Zero gas fee invariant (strictly integer 0, rejecting bool False)
    user_gas = payment_payload.get("user_gas_fee")
    if isinstance(user_gas, bool) or not isinstance(user_gas, int) or user_gas != 0:
        return {
            "settled": False,
            "reason": f"Sponsor gas violation: user_gas_fee ({user_gas}) must be strictly integer 0"
        }

    # Mark transaction as processed
    processed_txs.add(tx_hash)

    receipt_hash = hashlib.sha256(
        f"{tx_hash}:{amount}:{challenge['recipient']}:{challenge['sponsor_relayer']}".encode()
    ).hexdigest()

    return {
        "settled": True,
        "tx_hash": tx_hash,
        "amount_micro_ccd": amount,
        "token": challenge["token"],
        "recipient": challenge["recipient"],
        "sponsor_relayer": challenge["sponsor_relayer"],
        "user_gas_fee": 0,
        "receipt_hash": receipt_hash,
        "explorer_url": f"https://testnet.ccdexplorer.io/tx/{tx_hash}",
        "settlement_timestamp": time.time()
    }
