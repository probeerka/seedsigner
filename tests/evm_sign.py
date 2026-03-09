"""
EVM transaction signing via secp256k1.
Uses embit for key derivation, pure Python for signature formatting.
"""
from embit import bip32, bip39
from seedsigner.models.evm_transaction import signing_hash


# secp256k1 параметры
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if P[1] != Q[1]: return None
        m = (3 * P[0] * P[0]) * pow(2 * P[1], _P-2, _P) % _P
    else:
        m = (Q[1] - P[1]) * pow(Q[0] - P[0], _P-2, _P) % _P
    x = (m*m - P[0] - Q[0]) % _P
    y = (m*(P[0]-x) - P[1]) % _P
    return x, y


def _point_mul(k, P):
    R = None
    while k:
        if k & 1: R = _point_add(R, P)
        P = _point_add(P, P)
        k >>= 1
    return R


_G = (_Gx, _Gy)


def _sign_hash(private_key_int: int, msg_hash: bytes) -> tuple[int, int, int]:
    """
    Sign hash with private key.
    Returns (r, s, recovery_id).
    """
    import hashlib
    z = int.from_bytes(msg_hash, 'big')

    # RFC6979 детерминированный k
    def _rfc6979_k():
        bx = private_key_int.to_bytes(32, 'big') + msg_hash
        v = b'\x01' * 32
        k = b'\x00' * 32
        k = hashlib.hmac_new(k, v + b'\x00' + bx, hashlib.sha256).digest() \
            if hasattr(hashlib, 'hmac_new') else \
            _hmac_sha256(k, v + b'\x00' + bx)
        v = _hmac_sha256(k, v)
        k = _hmac_sha256(k, v + b'\x01' + bx)
        v = _hmac_sha256(k, v)
        while True:
            v = _hmac_sha256(k, v)
            candidate = int.from_bytes(v, 'big')
            if 1 <= candidate < _N:
                return candidate
            k = _hmac_sha256(k, v + b'\x00')
            v = _hmac_sha256(k, v)

    def _hmac_sha256(key, msg):
        import hmac
        return hmac.new(key, msg, hashlib.sha256).digest()

    k = _rfc6979_k()
    R = _point_mul(k, _G)
    r = R[0] % _N
    s = pow(k, _N-2, _N) * (z + r * private_key_int) % _N

    # Нормализуем s (low-s)
    if s > _N // 2:
        s = _N - s

    # recovery_id
    recovery_id = R[1] % 2
    if R[0] >= _N:
        recovery_id += 2

    return r, s, recovery_id


def sign_evm_transaction(tx: dict, raw_data: bytes,
                         mnemonic: str, passphrase: str,
                         derivation_path: str) -> bytes:
    """
    Sign EVM transaction.
    Returns 65-byte signature: r(32) + s(32) + v(1).
    """
    # Деривация приватного ключа
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, passphrase)
    root = bip32.HDKey.from_seed(seed_bytes)

    # Конвертируем путь: m/44'/60'/0'/0/0 → m/44h/60h/0h/0/0
    embit_path = derivation_path.replace("'", "h")
    child = root.derive(embit_path)
    privkey_int = int.from_bytes(child.key.secret, 'big')

    # Хэш для подписи
    tx_hash = signing_hash(tx, raw_data)

    # Подписываем
    r, s, rec_id = _sign_hash(privkey_int, tx_hash)

    # EIP-155: v = chain_id * 2 + 35 + recovery_id (для legacy)
    # EIP-1559: v = recovery_id (0 или 1)
    if tx['type'] == 0:
        v = tx['chain_id'] * 2 + 35 + rec_id
    else:
        v = rec_id

    # r + s + v (65 байт, формат для UR eth-signature)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v % 256])
