from dataclasses import dataclass
from seedsigner.views.view import View, MainMenuView, Destination
from seedsigner.gui.screens.screen import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    ButtonOption,
    QRDisplayScreen,
    LargeIconStatusScreen,
)
from seedsigner.gui.components import (
    GUIConstants,
    IconTextLine,
    FormattedAddress,
    SeedSignerIconConstants,
    FontAwesomeIconConstants,
)


# ── Экспорт xpub в Rabby ──────────────────────────────────────────────────────

class EvmExportXpubView(View):
    """Показывает анимированный UR:CRYPTO-HDKEY QR для импорта в Rabby."""

    def __init__(self, seed_num: int, account: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.account = account

    def run(self):
        from seedsigner.models.evm_sign import build_eth_hdkey_ur
        from seedsigner.models.encode_qr import UrFountainQrEncoder

        seed = self.controller.get_seed(self.seed_num)
        ur_encoder = build_eth_hdkey_ur(
            mnemonic=seed.mnemonic_str,
            passphrase=seed.passphrase,
            account=self.account,
        )

        from seedsigner.models.settings import Settings, SettingsConstants
        display_config = Settings.get_instance().get_value(
            SettingsConstants.SETTING__DISPLAY_CONFIGURATION, default_if_none=True)
        if display_config.startswith("desktop"):
            # Desktop: save animated GIF and open it
            enc = UrFountainQrEncoder(ur_encoder=ur_encoder)
            frames = []
            for _ in range(enc.seq_len()):
                img = enc.next_part_image(300, 300, border=4, background_color="ffffff")
                frames.append(img)
            gif_path = "/tmp/rabby_connect.gif"
            frames[0].save(
                gif_path,
                save_all=True,
                append_images=frames[1:],
                loop=0,
                duration=200,
            )
            import subprocess
            subprocess.Popen(["xdg-open", gif_path])
            self.run_screen(
                ButtonListScreen,
                title="Connect Rabby",
                button_data=[ButtonOption("Done")],
                show_back_button=True,
            )
        else:
            self.run_screen(
                QRDisplayScreen,
                qr_encoder=UrFountainQrEncoder(ur_encoder=ur_encoder),
            )

        return Destination(MainMenuView)


# ── Сканирование транзакции ───────────────────────────────────────────────────

class EvmScanTransactionView(View):
    """
    Запускает сканер для UR:ETH-SIGN-REQUEST от Rabby.
    Сохраняет seed_num в controller для передачи в EvmReviewTransactionView.
    """

    def __init__(self, seed_num: int):
        super().__init__()
        self.seed_num = seed_num

    def run(self):
        from seedsigner.views.scan_views import ScanView

        # Сохраняем seed_num чтобы EvmReviewTransactionView знал какой seed использовать
        self.controller.evm_seed_num = self.seed_num

        return Destination(ScanView, skip_current_view=True)


# ── Просмотр деталей транзакции ───────────────────────────────────────────────

@dataclass
class EvmTransactionReviewScreen(ButtonListScreen):
    network_str: str = ""
    value_str:   str = ""
    fee_str:     str = ""
    to_address:  str = ""
    is_bottom_list: bool = True
    show_back_button: bool = True

    def __post_init__(self):
        self.title = "Review TX"
        self.button_data = [
            ButtonOption("Sign"),
            ButtonOption("Reject"),
        ]
        super().__post_init__()

        y = self.top_nav.height + GUIConstants.COMPONENT_PADDING

        for label, value, icon in [
            ("Network", self.network_str, SeedSignerIconConstants.DERIVATION),
            ("Amount",  self.value_str,   FontAwesomeIconConstants.CIRCLE),
            ("Max fee", self.fee_str,     FontAwesomeIconConstants.CIRCLE),
        ]:
            self.components.append(IconTextLine(
                icon_name=icon,
                icon_color=GUIConstants.INFO_COLOR,
                label_text=label,
                value_text=value,
                screen_x=GUIConstants.COMPONENT_PADDING,
                screen_y=y,
            ))
            y = self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING

        self.components.append(FormattedAddress(
            address=self.to_address,
            screen_x=GUIConstants.COMPONENT_PADDING,
            width=self.canvas_width - 2 * GUIConstants.COMPONENT_PADDING,
            screen_y=y,
        ))


class EvmReviewTransactionView(View):

    def __init__(self):
        super().__init__()

    def run(self):
        from seedsigner.models.evm_sign import decode_eth_sign_request, sign_evm_transaction, build_eth_signature_ur
        from seedsigner.models.evm_transaction import parse_transaction, wei_to_eth, gwei, chain_name

        # Получаем данные из controller
        cbor = getattr(self.controller, 'eth_sign_request_cbor', None)
        seed_num = getattr(self.controller, 'evm_seed_num', 0)

        if not cbor:
            return Destination(EvmErrorView, view_args={"error": "No sign request data"})

        try:
            sign_request = decode_eth_sign_request(cbor)
            tx = parse_transaction(sign_request['sign_data'])
        except Exception as e:
            return Destination(EvmErrorView, view_args={"error": str(e)})

        # Комиссия
        if tx['type'] == 2:
            fee_str = f"{gwei(tx['max_fee'])} max"
        else:
            fee_str = gwei(tx['gas_price'])

        selected = self.run_screen(
            EvmTransactionReviewScreen,
            network_str=chain_name(tx['chain_id']),
            value_str=wei_to_eth(tx['value_wei']),
            fee_str=fee_str,
            to_address=tx['to'] or "Contract",
        )

        if selected == RET_CODE__BACK_BUTTON or selected == 1:
            return Destination(MainMenuView)

        # Подписываем
        seed = self.controller.get_seed(seed_num)
        try:
            signature = sign_evm_transaction(
                sign_data=sign_request['sign_data'],
                derivation_path=sign_request['derivation_path'],
                mnemonic=seed.mnemonic_str,
                passphrase=seed.passphrase,
                chain_id=tx['chain_id'],
                data_type=sign_request['data_type'],
            )
        except Exception as e:
            return Destination(EvmErrorView, view_args={"error": str(e)})

        # Показываем QR с подписью
        ur_encoder = build_eth_signature_ur(
            request_id=sign_request['request_id'],
            signature=signature,
        )

        from seedsigner.models.encode_qr import UrFountainQrEncoder
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=UrFountainQrEncoder(ur_encoder=ur_encoder),
        )

        # Чистим данные из controller
        self.controller.eth_sign_request_cbor = None
        self.controller.evm_seed_num = None

        return Destination(MainMenuView)


# ── Ошибка ────────────────────────────────────────────────────────────────────

class EvmErrorView(View):

    def __init__(self, error: str):
        super().__init__()
        self.error = error

    def run(self):
        self.run_screen(
            LargeIconStatusScreen,
            title="EVM Error",
            text=self.error[:80],
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView)
