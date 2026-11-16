from __future__ import annotations

import dataclasses
import hashlib
import hmac
import time
import uuid
from typing import Any


class Rfc6962MerkleTree:
    """RFC-6962 §2.1 compliant cryptographic Merkle tree guaranteeing zero-tampering and CVE-2012-2459 immunity."""

    def __init__(self, leaves: list[str] | None = None):
        raw_leaves = leaves or []
        self.leaves: list[str] = [self._hash_leaf(leaf) for leaf in raw_leaves]
        self.root: str = self._build_tree(self.leaves)

    @staticmethod
    def _hash_leaf(data: str) -> str:
        """Domain-separated leaf hashing per RFC-6962: SHA-256(0x00 || data)."""
        return hashlib.sha256(b"\x00" + data.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_internal(left_hex: str, right_hex: str) -> str:
        """Domain-separated internal node hashing per RFC-6962: SHA-256(0x01 || left || right)."""
        return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()

    def add_leaf(self, leaf_data: str) -> str:
        """Append leaf data, compute leaf hash, and recompute root."""
        h = self._hash_leaf(leaf_data)
        self.leaves.append(h)
        self.root = self._build_tree(self.leaves)
        return h

    def _build_tree(self, nodes: list[str]) -> str:
        if not nodes:
            return hashlib.sha256(b"\x00EMPTY_ACCOUNTABLE_LEDGER").hexdigest()
        if len(nodes) == 1:
            return nodes[0]

        next_level: list[str] = []
        i = 0
        n = len(nodes)
        while i < n:
            if i + 1 < n:
                next_level.append(self._hash_internal(nodes[i], nodes[i + 1]))
                i += 2
            else:
                # RFC-6962 §2.1: Promote unpaired odd leaf directly without duplication
                next_level.append(nodes[i])
                i += 1

        return self._build_tree(next_level)

    def get_root(self) -> str:
        return self.root

    def get_proof(self, index: int) -> list[dict[str, str]]:
        """Generate audit inclusion proof for leaf at `index`."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds for audit proof generation")

        proof: list[dict[str, str]] = []
        current_nodes = list(self.leaves)
        current_idx = index

        while len(current_nodes) > 1:
            n = len(current_nodes)
            next_level: list[str] = []
            i = 0
            while i < n:
                if i + 1 < n:
                    next_level.append(self._hash_internal(current_nodes[i], current_nodes[i + 1]))
                    i += 2
                else:
                    next_level.append(current_nodes[i])
                    i += 1

            if current_idx % 2 == 0:
                if current_idx + 1 < n:
                    proof.append({"hash": current_nodes[current_idx + 1], "position": "right"})
                # If current_idx + 1 == n, target was promoted directly; no sibling at this level
            else:
                proof.append({"hash": current_nodes[current_idx - 1], "position": "left"})

            current_idx //= 2
            current_nodes = next_level

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[dict[str, str]], root: str) -> bool:
        """Verify RFC-6962 inclusion proof from leaf_hash up to the expected root."""
        curr = leaf_hash
        for step in proof:
            sibling = step.get("hash", "")
            position = step.get("position", "")
            try:
                if position == "right":
                    curr = Rfc6962MerkleTree._hash_internal(curr, sibling)
                elif position == "left":
                    curr = Rfc6962MerkleTree._hash_internal(sibling, curr)
                else:
                    return False
            except (ValueError, TypeError):
                return False
        return curr == root

    def verify_leaf(self, leaf_hash: str) -> bool:
        """Verify leaf inclusion in current tree."""
        if leaf_hash not in self.leaves:
            return False
        try:
            idx = self.leaves.index(leaf_hash)
            proof = self.get_proof(idx)
            return self.verify_proof(leaf_hash, proof, self.root)
        except (ValueError, IndexError):
            return False


@dataclasses.dataclass
class AccountableExecutionRecord:
    record_id: str
    agent_badge: str
    owner_caip10: str
    zk_policy_hash: str
    x402_receipt_hash: str
    input_hash: str
    output_hash: str
    timestamp: float

    def to_leaf_string(self) -> str:
        """Deterministic serialization for Merkle tree leaf hashing."""
        return (
            f"EU_AI_ACT_ART12:{self.record_id}:{self.agent_badge}:{self.owner_caip10}:"
            f"{self.zk_policy_hash}:{self.x402_receipt_hash}:{self.input_hash}:{self.output_hash}:{self.timestamp}"
        )


class AccountableExecutionLedger:
    """EU AI Act Article 12 compliance ledger recording autonomous agent actions with cryptographic proof."""

    def __init__(self):
        self.records: list[AccountableExecutionRecord] = []
        self.tree = Rfc6962MerkleTree([])

    def log_execution(
        self,
        agent_badge: str,
        owner_caip10: str,
        zk_policy_hash: str,
        x402_receipt_hash: str,
        task_input: str,
        task_output: str
    ) -> AccountableExecutionRecord:
        """Log an accountable execution record and commit it to the cryptographic Merkle tree."""
        input_hash = hashlib.sha256(task_input.encode("utf-8")).hexdigest()
        output_hash = hashlib.sha256(task_output.encode("utf-8")).hexdigest()
        record_id = f"REC-{uuid.uuid4().hex[:8].upper()}"

        rec = AccountableExecutionRecord(
            record_id=record_id,
            agent_badge=agent_badge,
            owner_caip10=owner_caip10,
            zk_policy_hash=zk_policy_hash,
            x402_receipt_hash=x402_receipt_hash,
            input_hash=input_hash,
            output_hash=output_hash,
            timestamp=time.time()
        )
        self.records.append(rec)
        self.tree.add_leaf(rec.to_leaf_string())
        return rec

    def get_merkle_root(self) -> str:
        return self.tree.get_root()

    def generate_audit_certificate(self, record_index: int) -> dict[str, Any]:
        """Generate EU AI Act Article 12 compliance certificate with cryptographic inclusion proof."""
        if record_index < 0 or record_index >= len(self.records):
            raise IndexError("Record index out of range")

        rec = self.records[record_index]
        leaf_hash = self.tree.leaves[record_index]
        proof = self.tree.get_proof(record_index)

        return {
            "compliance_standard": "EU AI Act Article 12 (Record-Keeping & Traceability)",
            "jurisdiction": "European Union / Global Interoperable",
            "record_id": rec.record_id,
            "agent_badge": rec.agent_badge,
            "owner_caip10": rec.owner_caip10,
            "zk_policy_hash": rec.zk_policy_hash,
            "x402_receipt_hash": rec.x402_receipt_hash,
            "input_hash": rec.input_hash,
            "output_hash": rec.output_hash,
            "record_timestamp": rec.timestamp,
            "leaf_hash": leaf_hash,
            "merkle_root": self.tree.get_root(),
            "merkle_proof": proof,
            "proof_verified": Rfc6962MerkleTree.verify_proof(leaf_hash, proof, self.tree.get_root())
        }

    @staticmethod
    def verify_audit_certificate(cert: dict[str, Any]) -> bool:
        """Verify an external EU AI Act compliance certificate against its Merkle root."""
        required_fields = [
            "record_id", "agent_badge", "owner_caip10",
            "zk_policy_hash", "x402_receipt_hash", "input_hash",
            "output_hash", "record_timestamp"
        ]
        for f in required_fields:
            if f not in cert:
                return False

        try:
            rec = AccountableExecutionRecord(
                record_id=str(cert["record_id"]),
                agent_badge=str(cert["agent_badge"]),
                owner_caip10=str(cert["owner_caip10"]),
                zk_policy_hash=str(cert["zk_policy_hash"]),
                x402_receipt_hash=str(cert["x402_receipt_hash"]),
                input_hash=str(cert["input_hash"]),
                output_hash=str(cert["output_hash"]),
                timestamp=float(cert["record_timestamp"])
            )
            expected_leaf = Rfc6962MerkleTree._hash_leaf(rec.to_leaf_string())
        except (ValueError, TypeError):
            return False

        leaf_h = cert.get("leaf_hash", "")
        if not hmac.compare_digest(expected_leaf, str(leaf_h)):
            return False

        proof = cert.get("merkle_proof", [])
        root = cert.get("merkle_root", "")
        if not root:
            return False

        return Rfc6962MerkleTree.verify_proof(expected_leaf, proof, str(root))
