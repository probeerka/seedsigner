"""
EIP-4527 QR signing protocol for EVM transactions.
Uses existing ur2 and urtypes infrastructure from the project.
Supports: eth-sign-request (decode) and eth-signature (encode).
"""
from seedsigner.helpers.ur2.cbor_lite import CBOREncoder, CBORDecoder
from seedsigner.helpers.ur2.ur_encoder import UREncoder
from seedsigner.helpers.ur2.ur_decoder import URDecoder
from seedsigner.helpers.ur2.ur import UR
from urtypes.crypto import HDKey, Keypath, PathComponent, CoinInfo
from embit import bip32, bip39


# ── crypto-hdkey для импорта в Rabby ─────────────────────────────────────────

def build_eth_hdkey_ur(mnemonic: str, passphrase: str = "",
                        account: int = 0) -> UREncoder:
    """
    Строит UR:CRYPTO-HDKEY для импорта ETH аккаунта в Rabby.
    Возвращает UREncoder — итерируй .next_part() для QR кадров.
    """
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, passphrase)
    root = bip32.HDKey.from_seed(seed_bytes)

    # Деривируем до m/44'/60'/account'
    account_key = root.derive(f"m/44h/60h/{account}h")

    # Keypath: m/44'/60'/account'
    origin = Keypath(
        [
            PathComponent(44, True),
            PathComponent(60, True),
            PathComponent(account, True),
        ],
        root.my_fingerprint,   # source-fingerprint = master fingerprint
        3,                     # depth
    )

    # CoinInfo: coin_type=60 (ETH)
    use_info = CoinInfo(type=60, network=0)

    hdkey = HDKey({
        'key':                account_key.key.get_public_key().sec(),  # 33 bytes
        'chain_code':         account_key.chain_code,                  # 32 bytes
        'origin':             origin,
        'parent_fingerprint': account_key.fingerprint,
        'use_info':           use_info,
    })

    ur = UR("crypto-hdkey", hdkey.to_cbor())
    return UREncoder(ur=ur, max_fragment_len=200)


# ── eth-sign-request декодирование ───────────────────────────────────────────

def decode_eth_sign_request(ur_string: str) -> dict:
    """
    Декодирует UR:ETH-SIGN-REQUEST от Rabby.
    Возвращает dict: sign_data, data_type, chain_id,
                     derivation_path, request_id, address
    """
    # Для анимированных QR — скормить все части URDecoder'у
    # Здесь обрабатываем уже собранную строку (одна часть)
    decoder = URDecoder()
    decoder.receive_part(ur_string)

    if not decoder.is_complete():
        raise ValueError("Incomplete UR — need more QR frames")
    if decoder.is_error():
        raise ValueError(f"UR decode error: {decoder.error()}")

    ur = decoder.result_ur()
    if ur.type != "eth-sign-request":
        raise ValueError(f"Expected eth-sign-request, got {ur.type}")

    return _parse_eth_sign_request_cbor(ur.cbor)


def _parse_eth_sign_request_cbor(cbor_data: bytes) -> dict:
    """
    Парсит CBOR тело eth-sign-request по EIP-4527:
    {
      1: request-id (bytes, UUID tagged 37),
      2: sign-data  (bytes),
      3: data-type  (uint или map {type: uint}),
      4: chain-id   (uint),
      5: derivation-path (Keypath, tagged 304),
      6: address    (bytes, 20 байт) — опционально,
      7: origin     (text) — опционально,
    }
    """
    dec = CBORDecoder(cbor_data)

    # Читаем map
    map_size, _ = dec.decodeMapSize()

    result = {}
    for _ in range(map_size):
        key, _ = dec.decodeUnsigned()

        if key == 1:
            # request-id: tagged(37, bytes)
            # Читаем semantic tag вручную
            tag, value, _ = dec.decodeTagAndValue(0)
            request_id, _ = dec.decodeBytes()
            result['request_id'] = request_id

        elif key == 2:
            # sign-data: bytes (RLP транзакция)
            sign_data, _ = dec.decodeBytes()
            result['sign_data'] = sign_data

        elif key == 3:
            # data-type: uint (1=legacy, 2=typed, 3=raw, 4=eip1559)
            # Может быть map {type: uint} или просто uint
            tag, val, _ = dec.decodeTagAndValue(0)
            from seedsigner.helpers.ur2.cbor_lite import Tag_Major_unsignedInteger, Tag_Major_map
            if tag == Tag_Major_unsignedInteger:
                result['data_type'] = val
            elif tag == Tag_Major_map:
                # {type: uint}
                dec.decodeUnsigned()  # ключ "type" (скорее всего 1)
                dt, _ = dec.decodeUnsigned()
                result['data_type'] = dt
            else:
                result['data_type'] = 1

        elif key == 4:
            # chain-id
            chain_id, _ = dec.decodeUnsigned()
            result['chain_id'] = chain_id

        elif key == 5:
            # derivation-path: Keypath tagged 304
            # Читаем тег, потом CBOR Keypath
            _tag, _val, _ = dec.decodeTagAndValue(0)
            path_str = _decode_keypath(dec)
            result['derivation_path'] = path_str

        elif key == 6:
            # address (опционально)
            addr, _ = dec.decodeBytes()
            result['address'] = addr

        elif key == 7:
            # origin text (опционально)
            origin, _ = dec.decodeText()
            result['origin'] = origin.decode() if isinstance(origin, bytes) else origin

        else:
            # Пропускаем неизвестные поля
            break

    result.setdefault('data_type', 1)
    result.setdefault('chain_id', 1)
    result.setdefault('derivation_path', "m/44'/60'/0'/0/0")
    result.setdefault('request_id', b'\x00' * 16)
    result.setdefault('address', None)

    return result


def _decode_keypath(dec: CBORDecoder) -> str:
    """Декодирует CBOR Keypath в строку вида m/44'/60'/0'/0/0"""
    map_size, _ = dec.decodeMapSize()
    components = []
    source_fingerprint = None
    depth = None

    for _ in range(map_size):
        k, _ = dec.decodeUnsigned()
        if k == 1:
            # components: array of [index, is_hardened, ...]
            arr_size, _ = dec.decodeArraySize()
            for _ in range(arr_size // 2):
                idx, _ = dec.decodeUnsigned()
                hardened, _ = dec.decodeBool()
                components.append((idx, hardened))
        elif k == 2:
            source_fingerprint, _ = dec.decodeUnsigned()
        elif k == 3:
            depth, _ = dec.decodeUnsigned()

    path = "m"
    for idx, hardened in components:
        path += f"/{idx}'" if hardened else f"/{idx}"
    return path


# ── eth-signature кодирование ─────────────────────────────────────────────────

def build_eth_signature_ur(request_id: bytes, signature: bytes,
                            max_fragment_len: int = 200) -> UREncoder:
    """
    Кодирует подпись как UR:ETH-SIGNATURE для Rabby.
    signature — 65 байт: r(32) + s(32) + v(1)
    """
    cbor = _encode_eth_signature_cbor(request_id, signature)
    ur = UR("eth-signature", cbor)
    return UREncoder(ur=ur, max_fragment_len=max_fragment_len)


def _encode_eth_signature_cbor(request_id: bytes, signature: bytes) -> bytes:
    from seedsigner.helpers.ur2.cbor_lite import Tag_Major_semantic
    enc = CBOREncoder()
    enc.encodeMapSize(3)
    # key 1: request-id — semantic tag 37 (UUID) + bytes
    enc.encodeUnsigned(1)
    enc.encodeTagAndValue(Tag_Major_semantic, 37)
    enc.encodeBytes(request_id)
    # key 2: signature (65 bytes)
    enc.encodeUnsigned(2)
    enc.encodeBytes(signature)
    # key 3: origin
    enc.encodeUnsigned(3)
    enc.encodeText("SeedSigner")
    return bytes(enc.get_bytes())
def sign_evm_transaction(sign_data: bytes, derivation_path: str,
                          mnemonic: str, passphrase: str = "",
                          chain_id: int = 1, data_type: int = 1) -> bytes:
    """
    Подписывает EVM транзакцию.
    Возвращает 65 байт: r(32) + s(32) + v(1).
    """
    from seedsigner.models.evm_transaction import parse_transaction, signing_hash

    tx = parse_transaction(sign_data)
    tx_hash = signing_hash(tx, sign_data)

    # Деривируем приватный ключ
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, passphrase)
    root = bip32.HDKey.from_seed(seed_bytes)
    embit_path = derivation_path.replace("'", "h")
    child = root.derive(embit_path)
    privkey_int = int.from_bytes(child.key.secret, 'big')

    r, s, rec_id = _secp256k1_sign(privkey_int, tx_hash)

    # EIP-155 v для legacy, просто rec_id для EIP-1559
    if tx['type'] == 0:
        v = tx['chain_id'] * 2 + 35 + rec_id
    else:
        v = rec_id

    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v & 0xFF])


# ── secp256k1 ─────────────────────────────────────────────────────────────────

_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G  = (_Gx, _Gy)


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if P[1] != Q[1]: return None
        m = 3 * P[0] * P[0] * pow(2 * P[1], _P - 2, _P) % _P
    else:
        m = (Q[1] - P[1]) * pow(Q[0] - P[0], _P - 2, _P) % _P
    x = (m * m - P[0] - Q[0]) % _P
    y = (m * (P[0] - x) - P[1]) % _P
    return x, y


def _point_mul(k, P):
    R = None
    while k:
        if k & 1: R = _point_add(R, P)
        P = _point_add(P, P)
        k >>= 1
    return R


def _secp256k1_sign(privkey: int, msg_hash: bytes) -> tuple:
    """RFC6979 deterministic signing. Returns (r, s, recovery_id)."""
    import hmac, hashlib

    def _hmac(k, v):
        return hmac.new(k, v, hashlib.sha256).digest()

    z  = int.from_bytes(msg_hash, 'big')
    bx = privkey.to_bytes(32, 'big') + msg_hash
    v  = b'\x01' * 32
    k  = b'\x00' * 32
    k  = _hmac(k, v + b'\x00' + bx)
    v  = _hmac(k, v)
    k  = _hmac(k, v + b'\x01' + bx)
    v  = _hmac(k, v)

    while True:
        v = _hmac(k, v)
        candidate = int.from_bytes(v, 'big')
        if 1 <= candidate < _N:
            k_nonce = candidate
            break
        k = _hmac(k, v + b'\x00')
        v = _hmac(k, v)

    R   = _point_mul(k_nonce, _G)
    r   = R[0] % _N
    s   = pow(k_nonce, _N - 2, _N) * (z + r * privkey) % _N
    if s > _N // 2:
        s = _N - s

    rec_id = R[1] % 2
    if R[0] >= _N:
        rec_id += 2

    return r, s, rec_id
