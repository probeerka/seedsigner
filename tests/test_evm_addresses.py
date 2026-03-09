"""Tests for ETH and TRX address derivation and EVM signing."""
from base import BaseTest
from seedsigner.models.ethereum import derive_ethereum_addresses
from seedsigner.models.tron import derive_tron_addresses
from evm_transaction import (
    parse_transaction, _rlp_encode_item, wei_to_eth, chain_name
)

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


class TestEthereumAddresses(BaseTest):
    @classmethod
    def setup_class(cls):
        super().setup_class()

    def test_eth_address_derivation(self):
        """First ETH address for standard mnemonic should match known value."""
        addrs = derive_ethereum_addresses(MNEMONIC)
        assert len(addrs) == 5
        assert addrs[0]["address"] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        assert addrs[0]["index"] == 0
        assert addrs[0]["path"] == "m/44'/60'/0'/0/0"

    def test_eth_address_format(self):
        """ETH addresses should be EIP-55 checksummed 42-char strings."""
        addrs = derive_ethereum_addresses(MNEMONIC)
        for a in addrs:
            assert a["address"].startswith("0x")
            assert len(a["address"]) == 42

    def test_eth_address_count(self):
        """Should derive requested number of addresses."""
        addrs = derive_ethereum_addresses(MNEMONIC, count=5)
        assert len(addrs) == 5


class TestTronAddresses(BaseTest):
    @classmethod
    def setup_class(cls):
        super().setup_class()

    def test_trx_address_format(self):
        """TRX addresses should start with T and be 34 chars."""
        addrs = derive_tron_addresses(MNEMONIC)
        assert len(addrs) > 0
        for a in addrs:
            assert a["address"].startswith("T")
            assert len(a["address"]) == 34

    def test_trx_derivation_path(self):
        """TRX should use m/44'/195'/0'/0/i path."""
        addrs = derive_tron_addresses(MNEMONIC)
        assert addrs[0]["path"] == "m/44'/195'/0'/0/0"


class TestEvmTransaction(BaseTest):
    @classmethod
    def setup_class(cls):
        super().setup_class()

    def test_parse_legacy_tx(self):
        """Should parse legacy (type 0) transaction."""
        to_addr = bytes.fromhex("9858EfFD232B4033E47d90003D41EC34EcaEda94")
        raw = _rlp_encode_item([0, 20*10**9, 21000, to_addr, 10**15, b'', 1, 0, 0])
        tx = parse_transaction(raw)
        assert tx["type"] == 0
        assert tx["chain_id"] == 1
        assert tx["gas_limit"] == 21000
        assert tx["to"].lower() == "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    def test_wei_to_eth(self):
        assert wei_to_eth(0) == "0 ETH"
        assert "ETH" in wei_to_eth(10**18)

    def test_chain_name(self):
        assert chain_name(1) == "Ethereum"
        assert chain_name(137) == "Polygon"

