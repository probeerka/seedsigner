from dataclasses import dataclass
from seedsigner.models.ethereum import derive_ethereum_addresses
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
class EthereumAddressDetailScreen(ButtonListScreen):
    derivation_path: str = ""
    address: str = ""
    is_bottom_list: bool = True
    show_back_button: bool = True

    def __post_init__(self):
        self.title = "ETH Address"
        self.button_data = [
            ButtonOption("Show QR"),
            # ButtonOption("Back"),
        ]
        super().__post_init__()

        # Путь деривации
        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text="Path",
            value_text=self.derivation_path,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        # Полный адрес через FormattedAddress (как в SeedAddressVerificationScreen)
        self.components.append(FormattedAddress(
            address=self.address,
            screen_x=GUIConstants.COMPONENT_PADDING,
            width=self.canvas_width - 2 * GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))


class EthereumAddressExplorerView(View):

    def __init__(self, seed_num: int, account: int = 0):
        super().__init__()
        self.seed_num = seed_num
        self.account = account

    def run(self):
        seed = self.controller.get_seed(self.seed_num)
        addresses = derive_ethereum_addresses(
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
            title="ETH Addresses",
            button_data=button_data,
            is_bottom_list=True,

        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(MainMenuView)

        return Destination(
            EthereumAddressDetailView,
            view_args={
                "seed_num": self.seed_num,
                "account": self.account,
                "address_index": selected,
                "addresses": addresses,
            }
        )


class EthereumAddressDetailView(View):

    def __init__(self, seed_num: int, account: int, address_index: int, addresses: list):
        super().__init__()
        self.seed_num = seed_num
        self.account = account
        self.address_index = address_index
        self.addresses = addresses

    def run(self):
        entry = self.addresses[self.address_index]
        address = entry["address"]
        path = entry["path"]

        selected = self.run_screen(
            EthereumAddressDetailScreen,
            derivation_path=path,
            address=address,
        )

        if selected == RET_CODE__BACK_BUTTON or selected == 1:
            return Destination(
                EthereumAddressExplorerView,
                view_args={"seed_num": self.seed_num, "account": self.account}
            )

        # selected == 0: Show QR
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=address),
        )

        return Destination(
            EthereumAddressDetailView,
            view_args={
                "seed_num": self.seed_num,
                "account": self.account,
                "address_index": self.address_index,
                "addresses": self.addresses,
            }
        )
