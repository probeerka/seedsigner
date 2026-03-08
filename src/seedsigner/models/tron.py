"""
Tron (TRC-20) address derivation from BIP39 mnemonic.
BIP44 path: m/44'/195'/account'/0/index
No external dependencies beyond embit.
"""
from embit import bip32, bip39
from seedsigner.models.ethereum import _keccak256, _decompress_pubkey


def _sha256(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()


def _base58check_encode(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    data = payload + checksum
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, 'big')
    result = ""
    while n > 0:
        n, remainder = divmod(n, 58)
        result = alphabet[remainder] + result
    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break
    return result


def _pubkey_to_tron_address(compressed_pubkey_bytes: bytes) -> str:
    raw = _decompress_pubkey(compressed_pubkey_bytes)  # 64 байта x+y
    h = _keccak256(raw)
    addr_bytes = bytes([0x41]) + h[-20:]  # префикс Tron
    return _base58check_encode(addr_bytes)


def derive_tron_addresses(
    mnemonic: str,
    passphrase: str = "",
    account: int = 0,
    count: int = 10
) -> list:
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, passphrase)
    root = bip32.HDKey.from_seed(seed_bytes)
    results = []
    for i in range(count):
        child = root.derive(f"m/44h/195h/{account}h/0/{i}")
        pub_compressed = child.key.get_public_key().sec()
        address = _pubkey_to_tron_address(pub_compressed)
        results.append({
            "path": f"m/44'/195'/{account}'/0/{i}",
            "address": address,
            "index": i,
        })
    return results
