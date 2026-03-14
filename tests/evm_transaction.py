"""
EVM transaction: RLP decode, display helpers, EIP-155 signing hash.
Supports: legacy (type 0) and EIP-1559 (type 2).
"""


# --- RLP decoder ---

def _rlp_decode(data: bytes, pos: int = 0):
    b = data[pos]
    if b <= 0x7F:
        return b, pos + 1
    elif b <= 0xB7:
        length = b - 0x80
        return data[pos+1:pos+1+length], pos+1+length
    elif b <= 0xBF:
        len_of_len = b - 0xB7
        length = int.from_bytes(data[pos+1:pos+1+len_of_len], 'big')
        start = pos + 1 + len_of_len
        return data[start:start+length], start+length
    elif b <= 0xF7:
        length = b - 0xC0
        return _rlp_decode_list(data, pos+1, pos+1+length), pos+1+length
    else:
        len_of_len = b - 0xF7
        length = int.from_bytes(data[pos+1:pos+1+len_of_len], 'big')
        start = pos + 1 + len_of_len
        return _rlp_decode_list(data, start, start+length), start+length


def _rlp_decode_list(data: bytes, start: int, end: int):
    items = []
    pos = start
    while pos < end:
        item, pos = _rlp_decode(data, pos)
        items.append(item)
    return items


def _rlp_int(b) -> int:
    if isinstance(b, int):
        return b
    if isinstance(b, bytes):
        return int.from_bytes(b, 'big') if b else 0
    return 0


# --- Transaction parsers ---

def parse_legacy_tx(rlp_data: bytes) -> dict:
    """
    Parse legacy (type 0) unsigned transaction.
    RLP: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
    or:  [nonce, gasPrice, gasLimit, to, value, data]  (pre-EIP155)
    """
    items, _ = _rlp_decode(rlp_data)
    if not isinstance(items, list):
        raise ValueError("Expected RLP list")

    nonce    = _rlp_int(items[0])
    gas_price = _rlp_int(items[1])
    gas_limit = _rlp_int(items[2])
    to       = items[3].hex() if isinstance(items[3], bytes) and items[3] else None
    value    = _rlp_int(items[4])
    data     = items[5] if isinstance(items[5], bytes) else b''
    chain_id = _rlp_int(items[6]) if len(items) > 6 else 1

    return {
        "type": 0,
        "nonce": nonce,
        "gas_price": gas_price,
        "gas_limit": gas_limit,
        "to": f"0x{to}" if to else None,
        "value_wei": value,
        "data": data,
        "chain_id": chain_id,
    }


def parse_eip1559_tx(raw_data: bytes) -> dict:
    """
    Parse EIP-1559 (type 2) unsigned transaction.
    raw_data[0] == 0x02, rest is RLP list.
    RLP: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
          gasLimit, to, value, data, accessList]
    """
    rlp_data = raw_data[1:]  # убираем byte 0x02
    items, _ = _rlp_decode(rlp_data)

    chain_id  = _rlp_int(items[0])
    nonce     = _rlp_int(items[1])
    max_priority = _rlp_int(items[2])
    max_fee   = _rlp_int(items[3])
    gas_limit = _rlp_int(items[4])
    to        = items[5].hex() if isinstance(items[5], bytes) and items[5] else None
    value     = _rlp_int(items[6])
    data      = items[7] if isinstance(items[7], bytes) else b''

    return {
        "type": 2,
        "nonce": nonce,
        "max_priority_fee": max_priority,
        "max_fee": max_fee,
        "gas_limit": gas_limit,
        "to": f"0x{to}" if to else None,
        "value_wei": value,
        "data": data,
        "chain_id": chain_id,
    }


def parse_transaction(raw_data: bytes) -> dict:
    """Auto-detect transaction type and parse."""
    if raw_data[0] == 0x02:
        return parse_eip1559_tx(raw_data)
    else:
        return parse_legacy_tx(raw_data)


# --- Display helpers ---

def wei_to_eth(wei: int) -> str:
    eth = wei / 10**18
    if eth == 0:
        return "0 ETH"
    elif eth < 0.000001:
        return f"{wei} Wei"
    elif eth < 0.001:
        return f"{wei / 10**9:.6f} Gwei"
    else:
        return f"{eth:.8f} ETH".rstrip('0').rstrip('.')

def gwei(wei: int) -> str:
    return f"{wei / 10**9:.2f} Gwei"

CHAIN_NAMES = {
    1:     "Ethereum",
    56:    "BSC",
    137:   "Polygon",
    42161: "Arbitrum",
    10:    "Optimism",
    43114: "Avalanche",
    8453:  "Base",
}

def chain_name(chain_id: int) -> str:
    return CHAIN_NAMES.get(chain_id, f"Chain {chain_id}")


# --- EIP-155 signing hash ---

def _rlp_encode_item(item) -> bytes:
    if isinstance(item, int):
        if item == 0:
            return b'\x80'
        b = item.to_bytes((item.bit_length() + 7) // 8, 'big')
        return _rlp_encode_item(b)
    elif isinstance(item, bytes):
        if len(item) == 1 and item[0] <= 0x7F:
            return item
        elif len(item) <= 55:
            return bytes([0x80 + len(item)]) + item
        else:
            ll = (len(item).bit_length() + 7) // 8
            return bytes([0xB7 + ll]) + len(item).to_bytes(ll, 'big') + item
    elif isinstance(item, list):
        encoded = b''.join(_rlp_encode_item(i) for i in item)
        if len(encoded) <= 55:
            return bytes([0xC0 + len(encoded)]) + encoded
        else:
            ll = (len(encoded).bit_length() + 7) // 8
            return bytes([0xF7 + ll]) + len(encoded).to_bytes(ll, 'big') + encoded


def signing_hash_legacy(tx: dict) -> bytes:
    """EIP-155 hash for legacy transaction."""
    import hashlib
    to_bytes = bytes.fromhex(tx['to'][2:]) if tx['to'] else b''
    fields = [
        tx['nonce'],
        tx['gas_price'],
        tx['gas_limit'],
        to_bytes,
        tx['value_wei'],
        tx['data'],
        tx['chain_id'],
        0,
        0,
    ]
    rlp = _rlp_encode_item(fields)
    return hashlib.sha256(hashlib.sha256(rlp).digest()).digest()  # placeholder
    # Реальный: keccak256(rlp)


def signing_hash(tx: dict, raw_data: bytes) -> bytes:
    """
    Compute the hash to sign.
    Для legacy: keccak256(RLP([nonce,gasPrice,gasLimit,to,value,data,chainId,0,0]))
    Для EIP-1559: keccak256(0x02 || RLP([chainId,nonce,...]))
    """
    from seedsigner.models.ethereum import _keccak256

    if tx['type'] == 0:
        to_bytes = bytes.fromhex(tx['to'][2:]) if tx['to'] else b''
        fields = [
            tx['nonce'], tx['gas_price'], tx['gas_limit'],
            to_bytes, tx['value_wei'], tx['data'],
            tx['chain_id'], 0, 0,
        ]
        return _keccak256(_rlp_encode_item(fields))
    else:
        # EIP-1559: hash of 0x02 || RLP(...)
        to_bytes = bytes.fromhex(tx['to'][2:]) if tx['to'] else b''
        fields = [
            tx['chain_id'], tx['nonce'],
            tx['max_priority_fee'], tx['max_fee'],
            tx['gas_limit'], to_bytes,
            tx['value_wei'], tx['data'], [],
        ]
        return _keccak256(bytes([0x02]) + _rlp_encode_item(fields))
