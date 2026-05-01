import base64
import io
import json
import logging
import os
import re
import time
from datetime import datetime

from binascii import a2b_base64, b2a_base64
from enum import IntEnum
from embit import psbt, bip39, ec, bip32
from pyzbar import pyzbar
from pyzbar.pyzbar import ZBarSymbol
from urtypes.crypto import PSBT as UR_PSBT
from urtypes.crypto import Account, Output
from urtypes.bytes import Bytes
import cbor2

from seedsigner.helpers.ur2.ur_decoder import URDecoder
from seedsigner.models.qr_type import QRType
from seedsigner.models.seed import Seed
from seedsigner.models.aezeed import has_valid_checksum as aezeed_has_valid_checksum
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dev-режим: включается через переменную окружения или settings
# ---------------------------------------------------------------------------
_DEV_MODE: bool = os.environ.get("SEEDSIGNER_DEV", "0") == "1"
_SD_LOG_DIR: str = "/mnt/sdcard/seedsigner_dev_logs"


# ---------------------------------------------------------------------------
# Dev-логгер: пишет JSONL на SD-карту, один файл на сессию устройства
# ---------------------------------------------------------------------------
class _URDevLogger:
    """
    Синглтон. Активен только когда SEEDSIGNER_DEV=1.
    Формат записи (одна строка JSONL):
        {"ts":"20260501_143022","dir":"rx","ur_type":"eth-sign-request",
         "frags_got":7,"frags_exp":5,"payload_b":843,
         "cbor_ms":0.4,"total_ms":3812}
        {"ts":"...","dir":"tx","ur_type":"eth-signature",
         "frames_sent":3,"payload_b":64,"total_ms":5100}
    """
    _inst: "_URDevLogger | None" = None

    def __init__(self):
        self._enabled = _DEV_MODE
        self._file = None
        self._path: str | None = None

    @classmethod
    def get(cls) -> "_URDevLogger":
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def _open(self) -> bool:
        if not self._enabled:
            return False
        if self._file:
            return True
        try:
            os.makedirs(_SD_LOG_DIR, exist_ok=True)
            self._path = os.path.join(
                _SD_LOG_DIR, f"ur_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
            )
            self._file = open(self._path, "a", encoding="utf-8")
            logger.debug("[DEV] UR log → %s", self._path)
            return True
        except OSError as e:
            logger.warning("[DEV] Cannot open SD log: %s", e)
            self._enabled = False
            return False

    def write(self, rec: dict) -> None:
        if not self._open():
            return
        try:
            self._file.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._file.flush()
            self._print(rec)
        except OSError as e:
            logger.warning("[DEV] SD write error: %s", e)

    @staticmethod
    def _print(rec: dict) -> None:
        if rec["dir"] == "rx":
            print(
                f"[DEV/RX] {rec['ur_type']}  "
                f"frags={rec['frags_got']}/{rec['frags_exp']}  "
                f"payload={rec['payload_b']}B  "
                f"cbor={rec['cbor_ms']:.1f}ms  "
                f"total={rec['total_ms']:.0f}ms"
            )
        else:
            print(
                f"[DEV/TX] {rec['ur_type']}  "
                f"frames={rec['frames_sent']}  "
                f"payload={rec['payload_b']}B  "
                f"total={rec['total_ms']:.0f}ms"
            )


def _stream_decode_cbor(raw: bytes) -> object:
    """
    Потоковый CBOR-декодер через BytesIO.
    Не создаёт промежуточных копий буфера — CBORDecoder читает
    из потока по мере разбора структуры.
    """
    return cbor2.CBORDecoder(io.BytesIO(raw)).decode()


# ---------------------------------------------------------------------------
# TX-счётчик для стороны отправки (SeedSigner → Rabby)
# ---------------------------------------------------------------------------
class URTXCounter:
    """
    Оборачивает цикл encoder.next_part() и считает отправленные кадры.

    Пример использования в sign_transaction_view.py:
        counter = URTXCounter("eth-signature", len(cbor_payload))
        while not encoder.is_complete():
            frame = encoder.next_part()
            display_qr(frame)
            counter.tick()
        counter.finish()
    """

    def __init__(self, ur_type: str, payload_bytes: int):
        self._ur_type = ur_type
        self._payload_b = payload_bytes
        self._frames = 0
        self._t0 = time.time()

    def tick(self) -> None:
        self._frames += 1

    @property
    def frames_sent(self) -> int:
        return self._frames

    def finish(self) -> dict:
        rec = {
            "ts": time.strftime("%Y%m%d_%H%M%S"),
            "dir": "tx",
            "ur_type": self._ur_type,
            "frames_sent": self._frames,
            "payload_b": self._payload_b,
            "total_ms": round((time.time() - self._t0) * 1000, 1),
        }
        _URDevLogger.get().write(rec)
        return rec


# ---------------------------------------------------------------------------
# Основные классы (без изменений в сигнатурах)
# ---------------------------------------------------------------------------

class DecodeQRStatus(IntEnum):
    PART_COMPLETE = 1
    PART_EXISTING = 2
    COMPLETE = 3
    FALSE = 4
    INVALID = 5
    WRONG_KEY = 6


class DecodeQR:
    """
    Used to process images or string data from animated qr codes.
    """
    def __init__(self, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
                 is_passphrase: bool = False,
                 is_encryptionkey: bool = False,
                 is_text: bool = False):
        self.wordlist_language_code = wordlist_language_code
        self.complete = False
        self.qr_type = None
        self.decoder = None
        self.is_passphrase = is_passphrase
        self.is_encryptionkey = is_encryptionkey
        self.is_text = is_text
        self.is_nonUTF8 = False

        # --- RX-статистика (только для UR-типов с Fountain) ---
        self._rx_t0: float = 0.0
        self._rx_frags_got: int = 0
        self._rx_frags_exp: int = 0


    def add_image(self, image):
        data = DecodeQR.extract_qr_data(image, is_binary=True)
        if data is None:
            return DecodeQRStatus.FALSE
        return self.add_data(data)


    def add_data(self, data):
        if data is None:
            return DecodeQRStatus.FALSE

        if self.is_passphrase:
            qr_type = QRType.PASSPHRASE
        elif self.is_encryptionkey:
            qr_type = QRType.ENCRYPTION_KEY
        elif self.is_text:
            qr_type = QRType.TEXT
        else:
            qr_type = DecodeQR.detect_segment_type(
                data, wordlist_language_code=self.wordlist_language_code
            )

        if self.qr_type is None:
            self.qr_type = qr_type

            if self.qr_type in [
                QRType.PSBT__UR2, QRType.OUTPUT__UR, QRType.ACCOUNT__UR,
                QRType.BYTES__UR, QRType.ETH_SIGN_REQUEST,
            ]:
                self.decoder = URDecoder()
                # Запускаем таймер для dev-статистики
                self._rx_t0 = time.time()

            elif self.qr_type == QRType.PSBT__SPECTER:
                self.decoder = SpecterPsbtQrDecoder()

            elif self.qr_type == QRType.PSBT__BASE64:
                self.decoder = Base64PsbtQrDecoder()

            elif self.qr_type == QRType.PSBT__BASE43:
                self.decoder = Base43PsbtQrDecoder()

            elif self.qr_type in [
                QRType.SEED__SEEDQR, QRType.SEED__COMPACTSEEDQR,
                QRType.SEED__MNEMONIC, QRType.SEED__FOUR_LETTER_MNEMONIC,
                QRType.SEED__UR2,
            ]:
                self.decoder = SeedQrDecoder(
                    wordlist_language_code=self.wordlist_language_code
                )

            elif self.qr_type == QRType.SEED__SLIP39:
                self.decoder = Slip39ShareDecoder()

            elif self.qr_type == QRType.SEED__XPRV:
                self.decoder = XprvQrDecoder()

            elif self.qr_type == QRType.SETTINGS:
                self.decoder = SettingsQrDecoder()

            elif self.qr_type == QRType.BITCOIN_ADDRESS:
                self.decoder = BitcoinAddressQrDecoder()

            elif self.qr_type == QRType.SIGN_MESSAGE:
                self.decoder = SignMessageQrDecoder()

            elif self.qr_type == QRType.WALLET__SPECTER:
                self.decoder = SpecterWalletQrDecoder()

            elif self.qr_type == QRType.WALLET__GENERIC:
                self.decoder = GenericWalletQrDecoder()

            elif self.qr_type == QRType.WALLET__CONFIGFILE:
                self.decoder = MultiSigConfigFileQRDecoder()

            elif self.qr_type == QRType.PASSPHRASE:
                self.decoder = PassphraseQrDecoder()

            elif self.qr_type == QRType.SEED__ENCRYPTEDQR:
                self.decoder = EncryptedQrDecoder()

            elif self.qr_type == QRType.ENCRYPTION_KEY:
                self.decoder = EncryptionKeyQrDecoder()

            elif self.qr_type == QRType.WIF:
                self.decoder = WifQrDecoder()

            elif self.qr_type == QRType.BIP38:
                self.decoder = Bip38QrDecoder()

            elif self.qr_type == QRType.SET_TIME:
                self.decoder = TimeQrDecoder()

            elif self.qr_type == QRType.TEXT:
                self.decoder = TextQrDecoder()

        elif self.qr_type != qr_type:
            raise Exception('QR Fragment Unexpected Type Change')

        if not self.decoder:
            return DecodeQRStatus.INVALID

        # Binary formats
        if self.qr_type in [QRType.SEED__COMPACTSEEDQR, QRType.SEED__ENCRYPTEDQR]:
            rt = self.decoder.add(data, self.qr_type)
            if rt == DecodeQRStatus.COMPLETE:
                self.complete = True
            elif rt == DecodeQRStatus.WRONG_KEY:
                self.wrong_key = True
            return rt

        # Convert bytes → str
        if type(data) == bytes:
            try:
                qr_str = data.decode('utf-8')
            except UnicodeDecodeError:
                self.is_nonUTF8 = True
                return DecodeQRStatus.INVALID
        else:
            qr_str = data

        # UR / Fountain types
        if self.qr_type in [
            QRType.PSBT__UR2, QRType.OUTPUT__UR, QRType.ACCOUNT__UR,
            QRType.BYTES__UR, QRType.ETH_SIGN_REQUEST,
        ]:
            added_part = self.decoder.receive_part(qr_str)

            # Обновляем счётчики прогресса на каждом фрагменте
            self._rx_frags_got += 1
            est = self.decoder.estimated_percent_complete()  # 0.0–1.0
            # estimated_percent_complete — стандартный метод ur2 URDecoder;
            # пересчитываем в приблизительное число ожидаемых фрагментов
            if est and est > 0 and self._rx_frags_got > 0:
                self._rx_frags_exp = max(
                    self._rx_frags_exp,
                    int(round(self._rx_frags_got / est)) if est < 1.0 else self._rx_frags_got,
                )

            if self.decoder.is_complete():
                self.complete = True

                # ── Потоковый CBOR-разбор ──────────────────────────────────
                # Только для ETH_SIGN_REQUEST; остальные UR-типы декодируются
                # позже через get_data_psbt / get_wallet_descriptor (без изменений).
                if self.qr_type == QRType.ETH_SIGN_REQUEST:
                    raw_cbor: bytes = self.decoder.result_message().cbor
                    t_cbor = time.perf_counter()
                    # Потоково декодируем через BytesIO — без полной копии в памяти
                    self._eth_cbor_parsed = _stream_decode_cbor(raw_cbor)
                    cbor_ms = (time.perf_counter() - t_cbor) * 1000

                    # Dev-лог
                    _URDevLogger.get().write({
                        "ts": time.strftime("%Y%m%d_%H%M%S"),
                        "dir": "rx",
                        "ur_type": "eth-sign-request",
                        "frags_got": self._rx_frags_got,
                        "frags_exp": self._rx_frags_exp or self._rx_frags_got,
                        "payload_b": len(raw_cbor),
                        "cbor_ms": round(cbor_ms, 3),
                        "total_ms": round((time.time() - self._rx_t0) * 1000, 1),
                    })
                else:
                    self._eth_cbor_parsed = None

                return DecodeQRStatus.COMPLETE

            if added_part:
                return DecodeQRStatus.PART_COMPLETE
            else:
                return DecodeQRStatus.PART_EXISTING

        else:
            rt = self.decoder.add(qr_str, self.qr_type)
            if rt == DecodeQRStatus.COMPLETE:
                self.complete = True
            return rt


    # ------------------------------------------------------------------
    # Публичные геттеры (сигнатуры не меняются)
    # ------------------------------------------------------------------

    def get_psbt(self):
        if self.complete:
            data = self.get_data_psbt()
            if data is not None:
                try:
                    return psbt.PSBT.parse(data)
                except Exception:
                    return None
        return None


    def get_data_psbt(self):
        if self.complete:
            if self.qr_type == QRType.PSBT__UR2:
                cbor = self.decoder.result_message().cbor
                return UR_PSBT.from_cbor(cbor).data
            else:
                return self.decoder.get_data()
        return None


    def get_base64_psbt(self):
        if self.complete:
            data = self.get_data_psbt()
            b64_psbt = b2a_base64(data)
            if b64_psbt[-1:] == b"\n":
                b64_psbt = b64_psbt[:-1]
            return b64_psbt.decode("utf-8")
        return None


    def get_seed_phrase(self):
        if self.is_seed:
            return self.decoder.get_seed_phrase()

    def get_seed_type(self):
        if self.is_seed:
            return self.decoder.get_seed_type()

    def get_xprv(self):
        if self.is_xprv:
            return self.decoder.get_xprv()

    def get_slip39_share(self):
        if self.is_slip39_share:
            return self.decoder.get_share()

    def get_settings_data(self):
        if self.is_settings:
            return self.decoder.data

    def get_address(self):
        if self.is_address:
            return self.decoder.get_address()

    def get_address_type(self):
        if self.is_address:
            return self.decoder.get_address_type()

    def get_time(self):
        if self.is_time:
            return self.decoder.get_time()

    def get_passphrase(self):
        if self.is_passphrase:
            return self.decoder.get_passphrase()

    def get_encryption_key(self):
        if self.is_encryptionkey:
            return self.decoder.get_encryption_key()

    def get_wif(self):
        if self.is_wif:
            return self.decoder.get_wif()

    def get_bip38(self):
        if self.is_bip38:
            return self.decoder.get_bip38()

    def get_public_data(self):
        if self.is_encrypted_seedqr:
            return self.decoder.get_public_data()

    def get_text(self):
        if self.is_text:
            return self.decoder.get_text()

    def get_eth_cbor(self) -> bytes | None:
        """
        Возвращает сырые CBOR-байты ETH_SIGN_REQUEST (для кода,
        которому нужны именно байты, а не распарсенный объект).
        Заменяет оба дублирующихся _get_eth_sign_request_cbor_duplicate().
        """
        if self.complete and self.qr_type == QRType.ETH_SIGN_REQUEST:
            return self.decoder.result_message().cbor
        return None

    def get_eth_request_parsed(self) -> object | None:
        """
        Возвращает уже распарсенный Python-объект из CBOR,
        декодированный потоково в момент завершения сборки.
        Это основная точка входа для Rabby-view.
        """
        if self.complete and self.qr_type == QRType.ETH_SIGN_REQUEST:
            return getattr(self, "_eth_cbor_parsed", None)
        return None

    def get_qr_data(self) -> dict:
        """
        Единая точка входа для внешнего кода.
        Для ETH_SIGN_REQUEST возвращает уже распарсенный объект
        (не вызывает повторный cbor2.loads).
        """
        if self.qr_type == QRType.ETH_SIGN_REQUEST:
            return self.get_eth_request_parsed()
        return self.decoder.get_qr_data()


    def get_wallet_descriptor(self):
        if self.is_wallet_descriptor:
            if self.qr_type in [QRType.OUTPUT__UR, QRType.ACCOUNT__UR, QRType.BYTES__UR]:
                cbor = self.decoder.result_message().cbor
                if self.qr_type == QRType.OUTPUT__UR:
                    return Output.from_cbor(cbor).descriptor()
                elif self.qr_type == QRType.ACCOUNT__UR:
                    return Account.from_cbor(cbor).output_descriptors[0].descriptor()
                elif self.qr_type == QRType.BYTES__UR:
                    raw = Bytes.from_cbor(cbor).data
                    descriptor = DecodeQR.multisig_setup_file_to_descriptor(
                        raw.decode("utf-8")
                    )
                    return descriptor
            else:
                return self.decoder.get_wallet_descriptor()


    def get_percent_complete(self, weight_mixed_frames: bool = False) -> int:
        if not self.decoder:
            return 0

        if self.qr_type in [
            QRType.PSBT__UR2, QRType.OUTPUT__UR, QRType.ACCOUNT__UR,
            QRType.BYTES__UR, QRType.ETH_SIGN_REQUEST,
        ]:
            return int(
                self.decoder.estimated_percent_complete(
                    weight_mixed_frames=weight_mixed_frames
                ) * 100
            )

        elif self.qr_type in [QRType.PSBT__SPECTER]:
            if self.decoder.total_segments is None:
                return 0
            return int(
                (self.decoder.collected_segments / self.decoder.total_segments) * 100
            )

        elif self.decoder.total_segments == 1:
            return 100 if self.decoder.complete else 0

        return 0


    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_complete(self) -> bool:
        return self.complete

    @property
    def is_invalid(self) -> bool:
        return self.qr_type == QRType.INVALID

    @property
    def is_psbt(self) -> bool:
        return self.qr_type in [
            QRType.PSBT__UR2, QRType.PSBT__SPECTER,
            QRType.PSBT__BASE64, QRType.PSBT__BASE43,
        ]

    @property
    def is_seed(self):
        return self.qr_type in [
            QRType.SEED__SEEDQR, QRType.SEED__COMPACTSEEDQR,
            QRType.SEED__UR2, QRType.SEED__MNEMONIC,
            QRType.SEED__FOUR_LETTER_MNEMONIC,
        ]

    @property
    def is_slip39_share(self) -> bool:
        return self.qr_type == QRType.SEED__SLIP39

    @property
    def is_xprv(self) -> bool:
        return self.qr_type == QRType.SEED__XPRV

    @property
    def is_json(self):
        return self.qr_type in [QRType.SETTINGS, QRType.JSON]

    @property
    def is_address(self):
        return self.qr_type == QRType.BITCOIN_ADDRESS

    @property
    def is_sign_message(self):
        return self.qr_type == QRType.SIGN_MESSAGE

    @property
    def is_time(self):
        return self.qr_type == QRType.SET_TIME

    @property
    def is_wif(self):
        return self.qr_type == QRType.WIF

    @property
    def is_bip38(self):
        return self.qr_type == QRType.BIP38

    @property
    def is_wallet_descriptor(self):
        check = self.qr_type in [
            QRType.WALLET__SPECTER, QRType.WALLET__UR,
            QRType.WALLET__CONFIGFILE, QRType.WALLET__GENERIC,
            QRType.OUTPUT__UR,
        ]
        if self.qr_type in [QRType.BYTES__UR]:
            cbor = self.decoder.result_message().cbor
            raw = Bytes.from_cbor(cbor).data
            data = raw.decode("utf-8").lower()
            check = 'policy:' in data and "format:" in data and "derivation:" in data
        return check

    @property
    def is_settings(self):
        return self.qr_type == QRType.SETTINGS

    @property
    def is_encrypted_seedqr(self) -> bool:
        return self.qr_type == QRType.SEED__ENCRYPTEDQR


    # ------------------------------------------------------------------
    # Static helpers (без изменений)
    # ------------------------------------------------------------------

    @staticmethod
    def extract_qr_data(image, is_binary: bool = False) -> str | None:
        if image is None:
            return None
        barcodes = pyzbar.decode(image, symbols=[ZBarSymbol.QRCODE], binary=is_binary)
        for barcode in barcodes:
            return barcode.data

    @staticmethod
    def detect_segment_type(s, wordlist_language_code=None):
        try:
            if type(s) == bytes:
                s = s.decode('utf-8')

            if re.search("^UR:CRYPTO-PSBT/", s, re.IGNORECASE):
                return QRType.PSBT__UR2
            elif re.search("^UR:CRYPTO-OUTPUT/", s, re.IGNORECASE):
                return QRType.OUTPUT__UR
            elif re.search("^UR:CRYPTO-ACCOUNT/", s, re.IGNORECASE):
                return QRType.ACCOUNT__UR
            elif re.search(r'^p(\d+)of(\d+) ([A-Za-z0-9+\/=]+$)', s, re.IGNORECASE):
                return QRType.PSBT__SPECTER
            elif re.search("^UR:BYTES/", s, re.IGNORECASE):
                return QRType.BYTES__UR
            elif re.search("^UR:ETH-SIGN-REQUEST/", s, re.IGNORECASE):
                # Три дублирующихся elif в оригинале схлопнуты в один
                return QRType.ETH_SIGN_REQUEST
            elif DecodeQR.is_base64_psbt(s):
                return QRType.PSBT__BASE64

            desc_str = s.replace("\n", "").replace(" ", "")
            if re.search(r'^p(\d+)of(\d+) ', s, re.IGNORECASE):
                return QRType.WALLET__SPECTER
            elif re.search(r'^\{\"label\".*\"descriptor\"\:.*', desc_str, re.IGNORECASE):
                return QRType.WALLET__SPECTER
            elif "multisig setup file" in s.lower():
                return QRType.WALLET__CONFIGFILE
            elif "sortedmulti" in s:
                return QRType.WALLET__GENERIC

            if re.search(r'\d{48,96}', s):
                return QRType.SEED__SEEDQR
            elif DecodeQR.is_bitcoin_address(s):
                return QRType.BITCOIN_ADDRESS
            elif s.startswith("signmessage"):
                return QRType.SIGN_MESSAGE

            if s.startswith("settings::"):
                return QRType.SETTINGS

            if re.match(r'^oT(\d{12}(\.\d{2})?|0)$', s):
                return QRType.SET_TIME

            wordlist = Seed.get_wordlist(wordlist_language_code)
            try:
                _4LETTER_WORDLIST = [word[:4].strip() for word in wordlist]
            except Exception:
                _4LETTER_WORDLIST = []

            from importlib import import_module
            slip39_wordlist = import_module("shamir_mnemonic.wordlist").WORDLIST

            if all(x in wordlist for x in s.strip().split(" ")):
                return QRType.SEED__MNEMONIC
            elif all(x in _4LETTER_WORDLIST for x in s.strip().split(" ")):
                return QRType.SEED__FOUR_LETTER_MNEMONIC
            elif all(x in slip39_wordlist for x in s.strip().lower().split(" ")):
                return QRType.SEED__SLIP39
            elif DecodeQR.is_base43_psbt(s):
                return QRType.PSBT__BASE43

            try:
                ec.PrivateKey.from_wif(s.strip())
                return QRType.WIF
            except Exception:
                pass

            try:
                hdkey = bip32.HDKey.from_string(s.strip())
                if hdkey.is_private:
                    return QRType.SEED__XPRV
            except Exception:
                pass

            try:
                from seedsigner.models.bip38 import BIP38Key
                BIP38Key(s.strip())
                return QRType.BIP38
            except Exception:
                pass

        except UnicodeDecodeError:
            pass

        if not isinstance(s, bytes):
            try:
                s = s.encode()
            except UnicodeError:
                raise Exception("Conversion to bytes failed")

        if len(s) in (16, 20, 24, 28, 32):
            try:
                bitstream = ""
                for b in s:
                    bitstream += bin(b).lstrip('0b').zfill(8)
                return QRType.SEED__COMPACTSEEDQR
            except Exception:
                pass
        else:
            from seedsigner.models.encryption import EncryptedQRCode
            from seedsigner.helpers.base43 import base43_decode
            encrypted_qr = EncryptedQRCode()
            public_data = None
            try:
                if isinstance(s, bytes):
                    s = s.decode('utf-8')
                data_bytes = base43_decode(s)
                public_data = encrypted_qr.public_data(data_bytes)
            except Exception:
                pass
            if not public_data:
                public_data = encrypted_qr.public_data(s)
            if public_data:
                from seedsigner.models.encryptedqr import EncryptedQR
                encryptedqr = EncryptedQR(
                    encrypted_qr=encrypted_qr, public_data=public_data
                )
                from seedsigner.controller import Controller
                Controller.get_instance().storage2.set_encryptedqr(encryptedqr)
                return QRType.SEED__ENCRYPTEDQR

        return QRType.INVALID

    @staticmethod
    def is_base64(s):
        try:
            return base64.b64encode(base64.b64decode(s)) == s.encode('ascii')
        except Exception:
            return False

    @staticmethod
    def is_base64_psbt(s):
        try:
            if DecodeQR.is_base64(s):
                psbt.PSBT.parse(a2b_base64(s))
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def is_base43_psbt(s):
        try:
            psbt.PSBT.parse(DecodeQR.base43_decode(s))
            return True
        except Exception:
            return False

    @staticmethod
    def base43_decode(s):
        chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
        if isinstance(s, bytes):
            v = s
        if isinstance(s, str):
            v = s.encode('ascii')
        elif isinstance(s, bytearray):
            v = bytes(s)
        long_value = 0
        power_of_base = 1
        for c in v[::-1]:
            digit = chars.find(bytes([c]))
            if digit == -1:
                raise Exception(f'Forbidden character {c} for base 43')
            long_value += digit * power_of_base
            power_of_base *= 43
        result = bytearray()
        while long_value >= 256:
            div, mod = divmod(long_value, 256)
            result.append(mod)
            long_value = div
        result.append(long_value)
        nPad = 0
        for c in v:
            if c == chars[0]:
                nPad += 1
            else:
                break
        result.extend(b'\x00' * nPad)
        result.reverse()
        return bytes(result)

    @staticmethod
    def is_bitcoin_address(s):
        if re.search(r'^bitcoin\:.*', s, re.IGNORECASE):
            return True
        elif re.search(
            r'^((bc1|tb1|bcr|[123]|[mn])[a-zA-HJ-NP-Z0-9]{25,62})$', s, re.IGNORECASE
        ):
            return True
        return False

    @staticmethod
    def multisig_setup_file_to_descriptor(text) -> str:
        lines = text.split('\n')
        m = n = 0
        xpubs = []
        x = 0
        derivation = ''
        descriptor = ''

        for l in lines:
            if l.find('#') == 0:
                continue
            l = l.strip()
            if ':' not in l:
                continue
            label, value = l.split(':', 1)
            label = label.strip().lower()
            value = value.strip()

            if label == 'policy':
                try:
                    match = re.search(r'(\d+)\D*(\d+)', value)
                    m = int(match.group(1))
                    n = int(match.group(2))
                except Exception:
                    raise Exception("Policy line not supported")
            elif label == 'derivation':
                derivation = value
            elif label == 'format':
                if value.lower() in ['p2wsh', 'p2sh-p2wsh', 'p2wsh-p2sh']:
                    script_type = value.lower()
            elif len(label) == 8:
                if len(xpubs) == 0:
                    xpubs = [None] * n
                xpubs[x] = {'xfp': label, 'key': value}
                x += 1

        if None in xpubs or len(xpubs) != n:
            raise Exception("bad or missing xpub")
        if m <= 0 or m > 9 or n <= 0 or n > 9:
            raise Exception("bad or missing policy")
        if len(derivation) == 0:
            raise Exception("bad or missing derivation path")
        if script_type not in ['p2wsh', 'p2sh-p2wsh', 'p2wsh-p2sh']:
            raise Exception("bad or missing script format")

        if script_type == "p2wsh":
            script_open = "wsh(sortedmulti(" + str(m)
            script_close = "))"
        elif script_type in ["p2sh-p2wsh", 'p2wsh-p2sh']:
            script_open = "sh(wsh(sortedmulti(" + str(m)
            script_close = ")))"

        descriptor = script_open
        for xp in xpubs:
            if derivation[0] == 'm':
                derivation = derivation[1:]
            derivation = derivation.replace("'", "h")
            descriptor += ',[' + xp['xfp'] + derivation + "]" + xp['key'] + "/{0,1}/*"
        descriptor += script_close
        return descriptor


# ---------------------------------------------------------------------------
# Все decoder-классы ниже — без изменений относительно оригинала
# ---------------------------------------------------------------------------

class BaseQrDecoder:
    def __init__(self):
        self.total_segments = None
        self.collected_segments = 0
        self.complete = False

    @property
    def is_complete(self) -> bool:
        return self.complete

    def add(self, segment, qr_type):
        raise Exception("Not implemented in child class")

    def get_qr_data(self) -> dict:
        raise Exception("get_qr_data must be implemented in decoder child class")


class BaseSingleFrameQrDecoder(BaseQrDecoder):
    def __init__(self):
        super().__init__()
        self.total_segments = 1


class BaseAnimatedQrDecoder(BaseQrDecoder):
    def __init__(self):
        super().__init__()
        self.segments = []

    def current_segment_num(self, segment) -> int:
        raise Exception("Not implemented in child class")

    def total_segment_nums(self, segment) -> int:
        raise Exception("Not implemented in child class")

    def parse_segment(self, segment) -> str:
        raise Exception("Not implemented in child class")

    @property
    def is_valid(self) -> bool:
        return True

    def add(self, segment, qr_type=None):
        if self.total_segments is None:
            self.total_segments = self.total_segment_nums(segment)
            self.segments = [None] * self.total_segments
        elif self.total_segments != self.total_segment_nums(segment):
            raise Exception('Segment total changed unexpectedly')

        if self.segments[self.current_segment_num(segment) - 1] is None:
            self.segments[self.current_segment_num(segment) - 1] = self.parse_segment(segment)
            self.collected_segments += 1
            if self.total_segments == self.collected_segments:
                if self.is_valid:
                    self.complete = True
                    return DecodeQRStatus.COMPLETE
                else:
                    return DecodeQRStatus.INVALID
            return DecodeQRStatus.PART_COMPLETE
        return DecodeQRStatus.PART_EXISTING


class SpecterPsbtQrDecoder(BaseAnimatedQrDecoder):
    def get_base64_data(self) -> str:
        base64_data = "".join(self.segments)
        if self.complete and DecodeQR.is_base64(base64_data):
            return base64_data
        return None

    def get_data(self):
        base64_data = self.get_base64_data()
        if base64_data is not None:
            return a2b_base64(base64_data)
        return None

    def current_segment_num(self, segment) -> int:
        m = re.search(r'^p(\d+)of(\d+) ', segment, re.IGNORECASE)
        return int(m.group(1)) if m else None

    def total_segment_nums(self, segment) -> int:
        m = re.search(r'^p(\d+)of(\d+) ', segment, re.IGNORECASE)
        return int(m.group(2)) if m else None

    def parse_segment(self, segment) -> str:
        return segment.split(" ")[-1].strip()


class Base64PsbtQrDecoder(BaseSingleFrameQrDecoder):
    def add(self, segment, qr_type=QRType.PSBT__BASE64):
        if DecodeQR.is_base64(segment):
            self.complete = True
            self.data = segment
            self.collected_segments = 1
            return DecodeQRStatus.COMPLETE
        return DecodeQRStatus.INVALID

    def get_base64_data(self) -> str:
        return self.data

    def get_data(self):
        base64_data = self.get_base64_data()
        if base64_data is not None:
            return a2b_base64(base64_data)
        return None


class Base43PsbtQrDecoder(BaseSingleFrameQrDecoder):
    def add(self, segment, qr_type=QRType.PSBT__BASE43):
        if DecodeQR.is_base43_psbt(segment):
            self.complete = True
            self.data = DecodeQR.base43_decode(segment)
            self.collected_segments = 1
            return DecodeQRStatus.COMPLETE
        return DecodeQRStatus.INVALID

    def get_data(self):
        return self.data


class SeedQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self, wordlist_language_code):
        super().__init__()
        self.seed_phrase = []
        self.wordlist_language_code = wordlist_language_code
        self.wordlist = Seed.get_wordlist(wordlist_language_code)
        self.word_to_index = {word: idx for idx, word in enumerate(self.wordlist)}
        self.seed_type = "bip39"

    def add(self, segment, qr_type=QRType.SEED__SEEDQR):
        if qr_type == QRType.SEED__SEEDQR:
            try:
                self.seed_phrase = []
                if len(segment) % 4 != 0:
                    return DecodeQRStatus.INVALID
                num_words = int(len(segment) / 4)
                for i in range(num_words):
                    index = int(segment[i * 4:(i * 4) + 4])
                    self.seed_phrase.append(self.wordlist[index])
                if len(self.seed_phrase) > 0:
                    if not self.has_valid_word_count():
                        return DecodeQRStatus.INVALID
                    self.seed_type = "bip39"
                    self.complete = True
                    self.collected_segments = 1
                    return DecodeQRStatus.COMPLETE
                return DecodeQRStatus.INVALID
            except Exception:
                return DecodeQRStatus.INVALID

        if qr_type == QRType.SEED__COMPACTSEEDQR:
            try:
                self.seed_phrase = bip39.mnemonic_from_bytes(segment).split()
                if not self.has_valid_word_count():
                    return DecodeQRStatus.INVALID
                self.seed_type = "bip39"
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
                return DecodeQRStatus.INVALID

        elif qr_type == QRType.SEED__MNEMONIC:
            try:
                seed_phrase_list = segment.strip().split(" ")
                if not len(seed_phrase_list) in (12, 15, 18, 21, 24):
                    return DecodeQRStatus.INVALID

                is_valid_bip39 = False
                try:
                    Seed(seed_phrase_list, passphrase="",
                         wordlist_language_code=self.wordlist_language_code)
                    is_valid_bip39 = True
                except Exception:
                    pass

                is_valid_aezeed = (
                    len(seed_phrase_list) == 24 and
                    aezeed_has_valid_checksum(seed_phrase_list, self.word_to_index)
                )

                if is_valid_aezeed and is_valid_bip39:
                    self.seed_type = "ambiguous"
                elif is_valid_aezeed:
                    self.seed_type = "aezeed"
                elif is_valid_bip39:
                    self.seed_type = "bip39"
                else:
                    return DecodeQRStatus.INVALID

                self.seed_phrase = seed_phrase_list
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception:
                return DecodeQRStatus.INVALID

        elif qr_type == QRType.SEED__FOUR_LETTER_MNEMONIC:
            try:
                seed_phrase_list = segment.strip().split(" ")
                _4LETTER_WORDLIST = [word[:4].strip() for word in self.wordlist]
                words = [self.wordlist[_4LETTER_WORDLIST.index(s)] for s in seed_phrase_list]
                seed = Seed(words, passphrase="",
                            wordlist_language_code=self.wordlist_language_code)
                if not seed:
                    return DecodeQRStatus.INVALID
                self.seed_phrase = words
                if not self.has_valid_word_count():
                    return DecodeQRStatus.INVALID
                self.seed_type = "bip39"
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception:
                return DecodeQRStatus.INVALID

        return DecodeQRStatus.INVALID

    def get_seed_phrase(self):
        return self.seed_phrase[:] if self.complete else []

    def get_seed_type(self):
        return self.seed_type if self.complete else None

    def has_valid_word_count(self):
        return len(self.seed_phrase) in (12, 15, 18, 21, 24)


class Slip39ShareDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.share = None

    def add(self, segment, qr_type=QRType.SEED__SLIP39):
        if qr_type == QRType.SEED__SLIP39:
            try:
                if isinstance(segment, bytes):
                    segment = segment.decode("utf-8")
                segment = segment.lower()
                from shamir_mnemonic import Share as Slip39Share
                Slip39Share.from_mnemonic(segment)
                self.share = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception:
                pass
        return DecodeQRStatus.INVALID

    def get_share(self):
        return self.share


class XprvQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.xprv = None

    def add(self, segment, qr_type=QRType.SEED__XPRV):
        if qr_type == QRType.SEED__XPRV:
            try:
                key = bip32.HDKey.from_string(segment.strip())
                if not key.is_private:
                    return DecodeQRStatus.INVALID
                self.xprv = segment.strip()
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception:
                return DecodeQRStatus.INVALID
        return DecodeQRStatus.INVALID

    def get_xprv(self):
        return self.xprv


class SettingsQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.data = None

    def add(self, segment, qr_type=QRType.SETTINGS):
        if not segment.startswith("settings::"):
            raise Exception("Invalid SettingsQR data")
        self.data = segment
        self.complete = True
        self.collected_segments = 1
        return DecodeQRStatus.COMPLETE


class SignMessageQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.message = None
        self.derivation_path = None

    def add(self, segment, qr_type=QRType.SIGN_MESSAGE):
        parts = segment.split()
        self.derivation_path = parts[1].replace("h", "'")
        fmt = parts[2].split(":")[0]
        self.message = segment.split(f"{fmt}:")[1]
        if fmt != "ascii":
            logger.info(f"Sign message: Unsupported format: {fmt}")
            return DecodeQRStatus.INVALID
        self.complete = True
        self.collected_segments = 1
        return DecodeQRStatus.COMPLETE

    def get_qr_data(self) -> dict:
        return dict(derivation_path=self.derivation_path, message=self.message)


class BitcoinAddressQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.address = None
        self.address_type = None

    def add(self, segment, qr_type=QRType.BITCOIN_ADDRESS):
        address_match = re.search(
            r'^((bc1q|tb1q|bcrt1q|bc1p|tb1p|bcrt1p|[123]|[mn])[a-zA-HJ-NP-Z0-9]{25,64})',
            segment.split(":")[-1], re.IGNORECASE
        )
        if address_match is not None:
            self.address = address_match.group(1)
            self.complete = True
            self.collected_segments = 1
            addr_prefix = address_match.group(2).lower()

            prefix_map = {
                "1":     (SettingsConstants.LEGACY_P2PKH,   SettingsConstants.MAINNET),
                "m":     (SettingsConstants.LEGACY_P2PKH,   SettingsConstants.TESTNET),
                "n":     (SettingsConstants.LEGACY_P2PKH,   SettingsConstants.TESTNET),
                "3":     (SettingsConstants.NESTED_SEGWIT,  SettingsConstants.MAINNET),
                "2":     (SettingsConstants.NESTED_SEGWIT,  SettingsConstants.TESTNET),
                "bc1q":  (SettingsConstants.NATIVE_SEGWIT,  SettingsConstants.MAINNET),
                "tb1q":  (SettingsConstants.NATIVE_SEGWIT,  SettingsConstants.TESTNET),
                "bcrt1q":(SettingsConstants.NATIVE_SEGWIT,  SettingsConstants.REGTEST),
                "bc1p":  (SettingsConstants.TAPROOT,        SettingsConstants.MAINNET),
                "tb1p":  (SettingsConstants.TAPROOT,        SettingsConstants.TESTNET),
                "bcrt1p":(SettingsConstants.TAPROOT,        SettingsConstants.REGTEST),
            }
            self.address_type = prefix_map.get(addr_prefix)

            if self.address_type and self.address_type[0] in [
                SettingsConstants.NATIVE_SEGWIT, SettingsConstants.TAPROOT
            ]:
                self.address = self.address.lower()
            return DecodeQRStatus.COMPLETE

        logger.debug(f"Invalid address: {segment}")
        return DecodeQRStatus.INVALID

    def get_address(self):
        return self.address

    def get_address_type(self):
        return self.address_type or "Unknown"


class SpecterWalletQrDecoder(BaseAnimatedQrDecoder):
    def validate_json(self) -> bool:
        try:
            json.loads("".join(self.segments))
            return True
        except json.decoder.JSONDecodeError:
            return False

    @property
    def is_valid(self):
        if self.validate_json():
            data = json.loads("".join(self.segments))
            return "descriptor" in data
        return False

    def get_wallet_descriptor(self) -> str | None:
        if self.is_valid:
            return json.loads("".join(self.segments))['descriptor']
        return None

    def current_segment_num(self, segment) -> int:
        m = re.search(r'^p(\d+)of(\d+) ', segment, re.IGNORECASE)
        return int(m.group(1)) if m else 1

    def total_segment_nums(self, segment) -> int:
        m = re.search(r'^p(\d+)of(\d+) ', segment, re.IGNORECASE)
        return int(m.group(2)) if m else 1

    def parse_segment(self, segment) -> str:
        try:
            return re.search(r'^p(\d+)of(\d+) (.+$)', segment, re.IGNORECASE).group(3)
        except Exception:
            return segment


class GenericWalletQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.descriptor = None

    def add(self, segment, qr_type=QRType.WALLET__GENERIC):
        from embit.descriptor import Descriptor
        try:
            Descriptor.from_string(segment)
            self.descriptor = segment
            self.complete = True
            return DecodeQRStatus.COMPLETE
        except Exception as e:
            logger.info(repr(e), exc_info=True)
        return DecodeQRStatus.INVALID

    def get_wallet_descriptor(self):
        return self.descriptor


class MultiSigConfigFileQRDecoder(GenericWalletQrDecoder):
    def add(self, segment, qr_type=QRType.WALLET__CONFIGFILE):
        descriptor = DecodeQR.multisig_setup_file_to_descriptor(segment)
        return super().add(descriptor, qr_type=QRType.WALLET__CONFIGFILE)


class PassphraseQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.passphrase = None

    def add(self, segment, qr_type=QRType.PASSPHRASE):
        if qr_type == QRType.PASSPHRASE:
            try:
                self.passphrase = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_passphrase(self):
        return self.passphrase


class EncryptionKeyQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.encryption_key = None

    def add(self, segment, qr_type=QRType.ENCRYPTION_KEY):
        if qr_type == QRType.ENCRYPTION_KEY:
            try:
                self.encryption_key = segment
                from seedsigner.controller import Controller
                encryptedqr = Controller.get_instance().storage2.encryptedqr
                if encryptedqr:
                    encryptedqr.set_encryption_key(self.encryption_key)
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_encryption_key(self):
        return self.encryption_key


class WifQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.wif = None

    def add(self, segment, qr_type=QRType.WIF):
        if qr_type == QRType.WIF:
            try:
                ec.PrivateKey.from_wif(segment)
                self.wif = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_wif(self):
        return self.wif


class Bip38QrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.bip38 = None

    def add(self, segment, qr_type=QRType.BIP38):
        if qr_type == QRType.BIP38:
            try:
                from seedsigner.models.bip38 import BIP38Key
                BIP38Key(segment)
                self.bip38 = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_bip38(self):
        return self.bip38


class EncryptedQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.public_data = None
        self.seed_phrase = []
        self.xprv = None

    def add(self, segment, qr_type=QRType.SEED__ENCRYPTEDQR, encryption_key=None):
        if qr_type == QRType.SEED__ENCRYPTEDQR:
            try:
                from seedsigner.controller import Controller
                controller = Controller.get_instance()
                encryptedqr = controller.storage2.encryptedqr
                if encryptedqr:
                    encrypted_qr = encryptedqr.encrypted_qr
                    self.public_data = encryptedqr.public_data
                else:
                    from seedsigner.models.encryption import EncryptedQRCode
                    from seedsigner.helpers.base43 import base43_decode
                    encrypted_qr = EncryptedQRCode()
                    self.public_data = None
                    try:
                        if isinstance(segment, bytes):
                            segment = segment.decode('utf-8')
                        data_bytes = base43_decode(segment)
                        self.public_data = encrypted_qr.public_data(data_bytes)
                    except Exception:
                        pass
                    if not self.public_data:
                        self.public_data = encrypted_qr.public_data(segment)
                    if not self.public_data:
                        raise Exception("Encrypted QR code is invalid.")
                    from seedsigner.models.encryptedqr import EncryptedQR
                    encryptedqr = EncryptedQR(
                        encrypted_qr=encrypted_qr, public_data=self.public_data
                    )
                    controller.storage2.set_encryptedqr(encryptedqr)

                if encryption_key:
                    word_bytes = encrypted_qr.decrypt(encryption_key)
                    if not word_bytes:
                        return DecodeQRStatus.WRONG_KEY
                    try:
                        self.seed_phrase = bip39.mnemonic_from_bytes(word_bytes).split()
                        self.xprv = None
                    except Exception:
                        candidate = word_bytes.decode("utf-8", errors="ignore").strip()
                        hdkey = bip32.HDKey.from_string(candidate)
                        if not hdkey.is_private:
                            return DecodeQRStatus.INVALID
                        self.seed_phrase = []
                        self.xprv = candidate
                else:
                    self.seed_phrase = []
                    self.xprv = None

                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_public_data(self):
        return self.public_data

    def get_seed_phrase(self):
        return self.seed_phrase[:]

    def get_xprv(self):
        return self.xprv


class TextQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.text = None

    def add(self, segment, qr_type=QRType.TEXT):
        if qr_type == QRType.TEXT:
            try:
                self.text = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_text(self):
        return self.text


class TimeQrDecoder(BaseSingleFrameQrDecoder):
    def __init__(self):
        super().__init__()
        self.time_str = None

    def add(self, segment, qr_type=QRType.SET_TIME):
        if qr_type == QRType.SET_TIME:
            try:
                self.time_str = segment
                self.complete = True
                self.collected_segments = 1
                return DecodeQRStatus.COMPLETE
            except Exception as e:
                logger.exception(repr(e))
        return DecodeQRStatus.INVALID

    def get_time(self):
        if self.time_str is None:
            return None
        data = self.time_str[2:]
        if data == "0":
            return None
        if "." in data:
            data = data.split(".")[0]
        try:
            yy = int(data[0:2]) + 2000
            mm = int(data[2:4])
            dd = int(data[4:6])
            hh = int(data[6:8])
            mi = int(data[8:10])
            ss = int(data[10:12])
            return datetime(yy, mm, dd, hh, mi, ss)
        except Exception:
            return None
