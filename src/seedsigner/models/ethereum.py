"""
Ethereum address derivation. No external dependencies beyond embit.
Keccak256 implemented inline (pure Python).
"""
from embit import bip32, bip39


# --- Встроенная реализация Keccak-256 (pure Python) ---

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_ROTC = [
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44,
]

_KECCAK_PIL = [
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1,
]

def _rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _keccak_f(state):
    for rc in _KECCAK_RC:
        # Theta
        C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
        D = [C[(x+4)%5] ^ _rol64(C[(x+1)%5], 1) for x in range(5)]
        state = [state[x] ^ D[x%5] for x in range(25)]
        # Rho + Pi
        B = [0]*25
        B[0] = state[0]
        x, y = 1, 0
        for i, r in enumerate(_KECCAK_ROTC):
            B[_KECCAK_PIL[i]] = _rol64(state[x + 5*y], r)
            x, y = y, (2*x + 3*y) % 5
        # Chi
        state = [B[x+5*y] ^ ((~B[(x+1)%5+5*y]) & B[(x+2)%5+5*y])
                 for y in range(5) for x in range(5)]
        # Iota
        state[0] ^= rc
    return state

def _keccak256(data: bytes) -> bytes:
    rate = 136  # 1088 bits / 8
    msg = bytearray(data)
    # Padding
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] |= 0x80
    # Absorb
    state = [0]*25
    for i in range(0, len(msg), rate):
        block = msg[i:i+rate]
        words = [int.from_bytes(block[j:j+8], 'little') for j in range(0, rate, 8)]
        for j, w in enumerate(words):
            state[j] ^= w
        state = _keccak_f(state)
    # Squeeze
    out = b''.join(s.to_bytes(8, 'little') for s in state[:4])
    return out


# --- Ethereum address derivation ---

def _to_checksum_address(addr_bytes: bytes) -> str:
    hex_addr = addr_bytes.hex()
    checksum_hash = _keccak256(hex_addr.encode('ascii')).hex()
    result = "0x"
    for i, c in enumerate(hex_addr):
        if c in "0123456789":
            result += c
        elif int(checksum_hash[i], 16) >= 8:
            result += c.upper()
        else:
            result += c.lower()
    return result


def _decompress_pubkey(compressed: bytes) -> bytes:
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], 'big')
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if prefix == 0x02:
        if y % 2 != 0:
            y = P - y
    else:
        if y % 2 == 0:
            y = P - y
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _pubkey_to_eth_address(compressed_pubkey_bytes: bytes) -> str:
    raw = _decompress_pubkey(compressed_pubkey_bytes)
    h = _keccak256(raw)
    return _to_checksum_address(h[-20:])


def derive_ethereum_addresses(
    mnemonic: str,
    passphrase: str = "",
    account: int = 0,
    count: int = 5
) -> list:
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, passphrase)
    root = bip32.HDKey.from_seed(seed_bytes)
    results = []
    for i in range(count):
        child = root.derive(f"m/44h/60h/{account}h/0/{i}")
        pub_compressed = child.key.get_public_key().sec()
        address = _pubkey_to_eth_address(pub_compressed)
        results.append({
            "path": f"m/44'/60'/{account}'/0/{i}",
            "address": address,
            "index": i,
        })
    return results
