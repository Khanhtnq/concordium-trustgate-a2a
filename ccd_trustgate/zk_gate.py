from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any

SANCTIONED_COUNTRIES = frozenset({"CU", "IR", "KP", "SY", "RU_SANCTIONED"})
FORBIDDEN_PII_KEYS = frozenset({
    "dob", "date_of_birth", "birth_date",
    "passport", "passport_number",
    "full_name", "first_name", "last_name",
    "ssn", "social_security_number",
    "national_id", "tax_id"
})


def generate_challenge_nonce() -> str:
    """Generate 64-character lowercase hex nonce strictly without '0x' prefix."""
    raw = uuid.uuid4().bytes + uuid.uuid4().bytes
    return hashlib.sha256(raw).hexdigest()


def create_zk_challenge(
    client_id: str,
    requested_attributes: list[str],
    ttl_seconds: int = 300
) -> dict[str, Any]:
    """Issue a privacy-preserving Web3Id zero-knowledge policy challenge."""
    if not client_id:
        raise ValueError("client_id cannot be empty")
    if not requested_attributes:
        raise ValueError("Must request at least one zero-knowledge attribute")

    now = time.time()
    nonce = generate_challenge_nonce()
    challenge_id = f"ZKC-{uuid.uuid4().hex[:12].upper()}"

    context_str = f"{client_id}:{nonce}:{sorted(requested_attributes)}"
    context_binding = hashlib.sha256(context_str.encode("utf-8")).hexdigest()

    return {
        "challenge_id": challenge_id,
        "client_id": client_id,
        "challenge_nonce": nonce,
        "requested_attributes": sorted(requested_attributes),
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "context_binding": context_binding
    }


def generate_zk_proof_response(
    challenge: dict[str, Any],
    subject_account: str,
    attribute_claims: dict[str, Any],
    signer_secret: bytes
) -> dict[str, Any]:
    """Client-side Web3Id ZK proof generator (strictly zero raw PII)."""
    # Enforce zero PII leak
    for k in attribute_claims:
        if k.lower() in FORBIDDEN_PII_KEYS:
            raise ValueError(f"Zero-Knowledge privacy violation: raw PII attribute '{k}' cannot be in ZK proof payload")

    proven_attributes: dict[str, bool] = {}
    for attr in challenge["requested_attributes"]:
        if attr == "age_over_18":
            proven_attributes[attr] = bool(attribute_claims.get("age_over_18", False))
        elif attr == "jurisdiction_allowed":
            country = str(attribute_claims.get("country_code", "XX")).upper()
            proven_attributes[attr] = country not in SANCTIONED_COUNTRIES
        elif attr == "accredited_operator":
            proven_attributes[attr] = bool(attribute_claims.get("accredited_operator", False))
        else:
            proven_attributes[attr] = bool(attribute_claims.get(attr, False))

    subject_hash = hashlib.sha256(subject_account.encode("utf-8")).hexdigest()
    commitment_msg = f"{challenge['challenge_nonce']}:{subject_hash}:{sorted(proven_attributes.items())}"
    commitment_sig = hmac.new(signer_secret, commitment_msg.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["challenge_nonce"],
        "subject_id_hash": subject_hash,
        "proven_attributes": proven_attributes,
        "commitment_signature": commitment_sig,
        "timestamp": time.time()
    }


def _assert_zero_pii(payload: Any) -> None:
    """Recursively ensure no forbidden raw PII keys exist anywhere inside a ZK payload."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key.lower() in FORBIDDEN_PII_KEYS:
                raise ValueError(f"Zero-Knowledge violation: Raw PII key '{key}' detected in proof payload")
            _assert_zero_pii(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_zero_pii(item)


def verify_zk_access_proof(
    proof_payload: dict[str, Any],
    active_challenges: dict[str, dict[str, Any]],
    expected_signer_secret: bytes | None = None
) -> dict[str, Any]:
    """Verify Concordium Web3Id zero-knowledge proof against active challenge."""
    # 1. Recursive Zero-PII check across top-level and nested dicts
    _assert_zero_pii(proof_payload)

    # 2. Lookup challenge
    cid = proof_payload.get("challenge_id")
    if not cid or cid not in active_challenges:
        return {
            "verified": False,
            "reason": "Challenge ID not found or already consumed (replay protection)"
        }

    challenge = active_challenges[cid]

    # 3. Expiry check
    if time.time() > challenge["expires_at"]:
        del active_challenges[cid]
        return {
            "verified": False,
            "reason": "ZK challenge has expired"
        }

    # 4. Nonce match (do not evict challenge on wrong nonce to prevent unauthenticated DoS)
    if proof_payload.get("challenge_nonce") != challenge["challenge_nonce"]:
        return {
            "verified": False,
            "reason": "Nonce mismatch in ZK proof payload"
        }

    # 5. Consume challenge immediately upon valid nonce binding (anti-replay)
    del active_challenges[cid]

    # 6. Verify all requested attributes are strictly boolean True
    proven = proof_payload.get("proven_attributes", {})
    if not isinstance(proven, dict):
        return {
            "verified": False,
            "reason": "proven_attributes must be a dictionary of boolean predicate outcomes"
        }
    for req in challenge["requested_attributes"]:
        if proven.get(req) is not True:
            return {
                "verified": False,
                "reason": f"Required zero-knowledge attribute '{req}' was not satisfied or evaluated to False"
            }

    # 7. Signature verification
    sig = proof_payload.get("commitment_signature", "")
    if not sig or len(sig) != 64 or sig.startswith("0x"):
        return {
            "verified": False,
            "reason": "Invalid commitment signature format"
        }

    if expected_signer_secret is not None:
        subject_hash = proof_payload.get("subject_id_hash", "")
        expected_msg = f"{challenge['challenge_nonce']}:{subject_hash}:{sorted(proven.items())}"
        computed_sig = hmac.new(expected_signer_secret, expected_msg.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_sig, sig):
            return {
                "verified": False,
                "reason": "Cryptographic commitment signature verification failed"
            }

    policy_hash = hashlib.sha256(f"{cid}:{sorted(proven.items())}".encode()).hexdigest()

    return {
        "verified": True,
        "policy_passed": True,
        "subject_id_hash": proof_payload.get("subject_id_hash"),
        "verified_attributes": list(proven.keys()),
        "policy_hash": policy_hash
    }
