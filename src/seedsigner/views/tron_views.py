from dataclasses import dataclass
from seedsigner.models.tron import derive_tron_addresses
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.views.view import View, MainMenuView, Destination
from seedsigner.gui.screens.screen import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    ButtonOption,
    QRDisplayScreen,
)
from seedsigner.gui.components import (
    GUIConstants,
    IconTextLine,
    FormattedAddress,
    SeedSignerIconConstants,
)


@dataclass
class TronAddressDetailScreen(ButtonListScreen):
    derivation_path: str = ""
    address: str = ""
    is_bottom_list: bool = True
    show_back_button: bool = False

    def __post_init__(self):
        self.title = "TRX Address"
        self.button_data = [
            ButtonOption("Show QR"),
            ButtonOption("Back"),
        ]
        super().__post_init__()

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text="Path",
            value_text=self.derivation_path,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(FormattedAddress(
            address=self.address,
            screen_x=GUIConstants.COMPONENT_PADDING,
            width=self.canvas_width - 2 * GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))


class TronAddressExplorerView(View):

    def __init__(self, seed_num: int, account: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.account = account

    def run(self):
        seed = self.controller.get_seed(self.seed_num)
        addresses = derive_tron_addresses(
            mnemonic=seed.mnemonic_str,
            passphrase=seed.passphrase,
            account=self.account,
            count=10,
        )

        button_data = [
            ButtonOption(f"{a['index']}  {a['address'][:10]}...{a['address'][-6:]}")
            for a in addresses
        ]

        selected = self.run_screen(
            ButtonListScreen,
            title="TRX Addresses",
            button_data=button_data,
            is_bottom_list=True,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(MainMenuView)

        return Destination(
            TronAddressDetailView,
            view_args={
                "seed_num": self.seed_num,
                "account": self.account,
                "address_index": selected,
                "addresses": addresses,
            }
        )


class TronAddressDetailView(View):

    def __init__(self, seed_num: int, account: int, address_index: int, addresses: list):
        super().__init__()
        self.seed_num = seed_num
        self.account = account
        self.address_index = address_index
        self.addresses = addresses

    def run(self):
        entry = self.addresses[self.address_index]

        selected = self.run_screen(
            TronAddressDetailScreen,
            derivation_path=entry["path"],
            address=entry["address"],
        )

        if selected == RET_CODE__BACK_BUTTON or selected == 1:
            return Destination(
                TronAddressExplorerView,
                view_args={"seed_num": self.seed_num, "account": self.account}
            )

        # Show QR
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=entry["address"]),
        )

        return Destination(TronAddressDetailView, view_args={
            "seed_num": self.seed_num,
            "account": self.account,
            "address_index": self.address_index,
            "addresses": self.addresses,
        })
