from __future__ import annotations

import hashlib

# Bitcoin Base58 Alphabet
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Concordium Mainnet & Testnet Genesis Hashes
MAINNET_GENESIS = "9dd9ca4d19e9393877d2c44b70f89acb"
TESTNET_GENESIS = "4221332d34e1694168c2a0c0b3fd0f27"

# Official Concordium Mainnet Contract References
MAINNET_REGISTRY_INDEX = 10082
MAINNET_REGISTRY_SUBINDEX = 0
MAINNET_REGISTRY_MODULE = "ba03e95330de2ad70cb8551d132bc7afe291b22068172a44e3a00dc09b63855f"

MAINNET_CIS8_KEY_INDEX = 10081
MAINNET_CIS8_KEY_SUBINDEX = 0
MAINNET_CIS8_MODULE = "08f71acbd16cdaca1e4184dbbc59b773ffc8f93c76fe2e56bfbd50bfcbee9d1d"


def b58encode(data: bytes) -> str:
    """Encode bytes into standard Base58 string preserving leading zero bytes."""
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(ALPHABET[r])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(chars))


def b58decode(s: str) -> bytes:
    """Decode a standard Base58 string into bytes."""
    n = 0
    for char in s:
        idx = ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 character: '{char}'")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def encode_uleb128(val: int) -> bytes:
    """Encode a non-negative integer into variable-length ULEB128 bytes."""
    if val < 0:
        raise ValueError("ULEB128 only supports non-negative integers")
    out = bytearray()
    while True:
        byte = val & 127
        val >>= 7
        if val != 0:
            byte |= 128
        out.append(byte)
        if val == 0:
            break
    return bytes(out)


def decode_uleb128(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an integer from ULEB128 bytes returning (value, next_offset)."""
    val = 0
    shift = 0
    idx = offset
    while idx < len(data):
        byte = data[idx]
        idx += 1
        val |= (byte & 127) << shift
        if (byte & 128) == 0:
            return val, idx
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 value exceeds 64-bit integer limit")
    raise ValueError("Unexpected end of ULEB128 data")


def encode_cis8004_badge(contract_index: int, contract_subindex: int, token_id: int) -> str:
    """Encode contract address and token ID into official Concordium CIS-8004 short badge.

    Wire format:
      b"\\x02" + ULEB128(contract_index) + ULEB128(contract_subindex) + token_id.to_bytes(8, "little")
    Appended with 4-byte double-SHA256 checksum, then Base58Check encoded.
    """
    if contract_index < 0 or contract_subindex < 0:
        raise ValueError("Contract index and subindex must be non-negative")
    if not (0 <= token_id < (1 << 64)):
        raise ValueError("Token ID must fit into an unsigned 64-bit integer (0..2^64-1)")

    payload = (
        b"\x02"
        + encode_uleb128(contract_index)
        + encode_uleb128(contract_subindex)
        + token_id.to_bytes(8, "little")
    )
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


def decode_cis8004_badge(badge_str: str) -> tuple[int, int, int]:
    """Decode a CIS-8004 short badge string into (contract_index, contract_subindex, token_id).

    Validates 4-byte double-SHA256 checksum and leading b"\\x02" tag byte.
    """
    if not badge_str or not isinstance(badge_str, str):
        raise ValueError("Badge string must be a non-empty string")

    decoded = b58decode(badge_str.strip())
    if len(decoded) < 15:  # 1 (tag) + 1 (idx) + 1 (subidx) + 8 (token_id) + 4 (checksum)
        raise ValueError(f"Decoded badge length ({len(decoded)}) is shorter than minimum 15 bytes")

    payload = decoded[:-4]
    expected_checksum = decoded[-4:]
    actual_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    if actual_checksum != expected_checksum:
        raise ValueError("Checksum verification failed: badge is tampered or corrupted")

    if payload[0] != 2:
        raise ValueError(f"Invalid CIS-8004 tag byte: expected 2, got {payload[0]}")

    contract_index, off1 = decode_uleb128(payload[1:])
    contract_subindex, off2 = decode_uleb128(payload[1:], off1)

    token_bytes = payload[1 + off2:]
    if len(token_bytes) != 8:
        raise ValueError(f"Token ID byte segment length ({len(token_bytes)}) is not 8 bytes")

    token_id = int.from_bytes(token_bytes, "little")
    return contract_index, contract_subindex, token_id


def format_caip19(short_badge: str, network: str = "mainnet") -> str:
    """Format canonical CAIP-19 identifier: ccd:<genesis_hash>/cis-2:<short_badge>."""
    decode_cis8004_badge(short_badge)
    net = network.lower().strip()
    if net == "mainnet":
        genesis = MAINNET_GENESIS
    elif net == "testnet":
        genesis = TESTNET_GENESIS
    else:
        raise ValueError(f"Unsupported Concordium network '{network}': expected 'mainnet' or 'testnet'")
    return f"ccd:{genesis}/cis-2:{short_badge}"


def parse_caip19(caip19_str: str) -> dict[str, str | int]:
    """Parse a canonical CAIP-19 identifier into network, genesis, short badge, and token params."""
    if not caip19_str.startswith("ccd:"):
        raise ValueError("Invalid CAIP-19 identifier: must start with 'ccd:' prefix")

    parts = caip19_str.split("/")
    if len(parts) != 2:
        raise ValueError("Invalid CAIP-19 format: missing asset namespace separator '/'")

    chain_part = parts[0]  # ccd:<genesis>
    asset_part = parts[1]  # cis-2:<short_badge>

    genesis = chain_part[4:]
    if genesis not in (MAINNET_GENESIS, TESTNET_GENESIS):
        raise ValueError(f"Unsupported Concordium genesis hash in CAIP-19 identifier: '{genesis}'")
    if not asset_part.startswith("cis-2:"):
        raise ValueError("Invalid CAIP-19 asset namespace: expected 'cis-2:'")

    short_badge = asset_part[6:]
    idx, subidx, tok_id = decode_cis8004_badge(short_badge)

    network = "mainnet" if genesis == MAINNET_GENESIS else "testnet"
    return {
        "network": network,
        "genesis_hash": genesis,
        "short_badge": short_badge,
        "contract_index": idx,
        "contract_subindex": subidx,
        "token_id": tok_id
    }
