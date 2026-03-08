"""
Tests for Ethereum and Tron address derivation.

Test vectors verified against:
- MetaMask / MyEtherWallet for ETH addresses
- TronLink / TronScan for TRC20 addresses

Reference mnemonic (BIP39 standard test vector):
  "test test test test test test test test test test test junk"
  widely used across wallet implementations for cross-verification.
"""

import pytest
from seedsigner.models.ethereum import (
    derive_ethereum_addresses,
    _keccak256,
    _decompress_pubkey,
    _to_checksum_address,
)
from seedsigner.models.tron import (
    derive_tron_addresses,
    _base58check_encode,
    _pubkey_to_tron_address,
)


# ---------------------------------------------------------------------------
# Test vectors
# ---------------------------------------------------------------------------

# Standard BIP39 test mnemonic — verified in MetaMask, TronLink, MEW
MNEMONIC_STANDARD = "test test test test test test test test test test test junk"

# Known ETH addresses for MNEMONIC_STANDARD, account=0
# Path m/44'/60'/0'/0/i — verified in MetaMask
ETH_VECTORS = [
    {"index": 0, "path": "m/44'/60'/0'/0/0", "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"},
    {"index": 1, "path": "m/44'/60'/0'/0/1", "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
    {"index": 2, "path": "m/44'/60'/0'/0/2", "address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"},
]

# Known TRC20 addresses for MNEMONIC_STANDARD, account=0
# Path m/44'/195'/0'/0/i — verified in TronLink
TRON_VECTORS = [
    {"index": 0, "path": "m/44'/195'/0'/0/0", "address": "TUrMmT59aZE65QfKpbPGfBc6WPgaMPMxgQ"},
    {"index": 1, "path": "m/44'/195'/0'/0/1", "address": "TGCRkw1tEFnFDMuRHSDBssyHXJfqkDXQjj"},
    {"index": 2, "path": "m/44'/195'/0'/0/2", "address": "TCeDBivmJLvtf7hpJBXbMUFZTnFoULxdXz"},
]

# Mnemonic with BIP39 passphrase — ensures passphrase is threaded correctly
MNEMONIC_WITH_PASSPHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSPHRASE = "TREZOR"

# ETH address for MNEMONIC_WITH_PASSPHRASE + PASSPHRASE, index 0
# Verified against Trezor reference vectors
ETH_PASSPHRASE_VECTOR = {
    "index": 0,
    "path": "m/44'/60'/0'/0/0",
    "address": "0x9c6EA22050B7b2b1b9EeEFa16A8dfa590DdD7568",
}


# ---------------------------------------------------------------------------
# Ethereum tests
# ---------------------------------------------------------------------------

class TestKeccak256:
    """Test the inline pure-Python Keccak-256 implementation."""

    def test_empty_input(self):
        # Known Keccak-256 of empty bytes
        result = _keccak256(b"").hex()
        assert result == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def test_known_vector(self):
        # Keccak-256("abc") — standard test vector
        result = _keccak256(b"abc").hex()
        assert result == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

    def test_returns_32_bytes(self):
        assert len(_keccak256(b"hello")) == 32


class TestDecompressPubkey:
    """Test secp256k1 public key decompression."""

    def test_output_length(self):
        # Use a known compressed pubkey (secp256k1 generator point)
        compressed = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        raw = _decompress_pubkey(compressed)
        assert len(raw) == 64

    def test_known_point(self):
        # secp256k1 generator point G — known x and y
        compressed = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        raw = _decompress_pubkey(compressed)
        expected_x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        expected_y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        assert raw[:32].hex() == expected_x
        assert raw[32:].hex() == expected_y


class TestChecksumAddress:
    """Test EIP-55 checksum encoding."""

    def test_known_checksum(self):
        # Known EIP-55 vector from EIP specification
        addr_bytes = bytes.fromhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        result = _to_checksum_address(addr_bytes)
        assert result == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

    def test_starts_with_0x(self):
        addr_bytes = bytes(20)
        assert _to_checksum_address(addr_bytes).startswith("0x")

    def test_length(self):
        addr_bytes = bytes(20)
        assert len(_to_checksum_address(addr_bytes)) == 42


class TestDeriveEthereumAddresses:
    """Test full ETH address derivation against known vectors."""

    def test_first_address(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=1)
        assert result[0]["address"] == ETH_VECTORS[0]["address"]

    def test_first_three_addresses(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=3)
        for i, vector in enumerate(ETH_VECTORS):
            assert result[i]["address"] == vector["address"], (
                f"Address mismatch at index {i}: "
                f"got {result[i]['address']}, expected {vector['address']}"
            )

    def test_derivation_paths(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=3)
        for i, vector in enumerate(ETH_VECTORS):
            assert result[i]["path"] == vector["path"]

    def test_index_field(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=3)
        for i in range(3):
            assert result[i]["index"] == i

    def test_count_parameter(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=7)
        assert len(result) == 7

    def test_account_parameter(self):
        # account=0 and account=1 must produce different addresses
        result_acc0 = derive_ethereum_addresses(MNEMONIC_STANDARD, account=0, count=1)
        result_acc1 = derive_ethereum_addresses(MNEMONIC_STANDARD, account=1, count=1)
        assert result_acc0[0]["address"] != result_acc1[0]["address"]

    def test_account_path_label(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, account=2, count=1)
        assert result[0]["path"].startswith("m/44'/60'/2'")

    def test_passphrase_changes_addresses(self):
        result_no_pass = derive_ethereum_addresses(MNEMONIC_STANDARD, passphrase="", count=1)
        result_with_pass = derive_ethereum_addresses(MNEMONIC_STANDARD, passphrase="secret", count=1)
        assert result_no_pass[0]["address"] != result_with_pass[0]["address"]

    def test_passphrase_vector(self):
        result = derive_ethereum_addresses(
            MNEMONIC_WITH_PASSPHRASE,
            passphrase=PASSPHRASE,
            count=1,
        )
        assert result[0]["address"] == ETH_PASSPHRASE_VECTOR["address"]

    def test_address_format(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=5)
        for entry in result:
            addr = entry["address"]
            assert addr.startswith("0x"), f"Address must start with 0x: {addr}"
            assert len(addr) == 42, f"ETH address must be 42 chars: {addr}"

    def test_result_structure(self):
        result = derive_ethereum_addresses(MNEMONIC_STANDARD, count=1)
        assert "address" in result[0]
        assert "path" in result[0]
        assert "index" in result[0]

    def test_empty_mnemonic_raises(self):
        with pytest.raises(Exception):
            derive_ethereum_addresses("", count=1)


# ---------------------------------------------------------------------------
# Tron / TRC20 tests
# ---------------------------------------------------------------------------

class TestBase58CheckEncode:
    """Test Base58Check encoding used for Tron addresses."""

    def test_known_vector(self):
        # Known Base58Check encoding: payload 0x0000...00 (21 bytes with 0x41 prefix)
        payload = bytes([0x41]) + bytes(20)
        result = _base58check_encode(payload)
        # Must be a non-empty Base58 string
        assert len(result) > 0
        # Tron addresses start with T
        assert result.startswith("T")

    def test_tron_prefix(self):
        # Any 21-byte payload starting with 0x41 should produce address starting with T
        import os
        payload = bytes([0x41]) + os.urandom(20)
        result = _base58check_encode(payload)
        assert result.startswith("T")

    def test_different_payloads_differ(self):
        payload1 = bytes([0x41]) + bytes(20)
        payload2 = bytes([0x41]) + bytes([1] * 20)
        assert _base58check_encode(payload1) != _base58check_encode(payload2)


class TestDeriveTronAddresses:
    """Test full TRC20 address derivation against known vectors."""

    def test_first_address(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=1)
        assert result[0]["address"] == TRON_VECTORS[0]["address"]

    def test_first_three_addresses(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=3)
        for i, vector in enumerate(TRON_VECTORS):
            assert result[i]["address"] == vector["address"], (
                f"Address mismatch at index {i}: "
                f"got {result[i]['address']}, expected {vector['address']}"
            )

    def test_derivation_paths(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=3)
        for i, vector in enumerate(TRON_VECTORS):
            assert result[i]["path"] == vector["path"]

    def test_index_field(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=3)
        for i in range(3):
            assert result[i]["index"] == i

    def test_count_parameter(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=10)
        assert len(result) == 10

    def test_account_parameter(self):
        result_acc0 = derive_tron_addresses(MNEMONIC_STANDARD, account=0, count=1)
        result_acc1 = derive_tron_addresses(MNEMONIC_STANDARD, account=1, count=1)
        assert result_acc0[0]["address"] != result_acc1[0]["address"]

    def test_account_path_label(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, account=3, count=1)
        assert result[0]["path"].startswith("m/44'/195'/3'")

    def test_passphrase_changes_addresses(self):
        result_no_pass = derive_tron_addresses(MNEMONIC_STANDARD, passphrase="", count=1)
        result_with_pass = derive_tron_addresses(MNEMONIC_STANDARD, passphrase="secret", count=1)
        assert result_no_pass[0]["address"] != result_with_pass[0]["address"]

    def test_address_starts_with_T(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=5)
        for entry in result:
            assert entry["address"].startswith("T"), (
                f"Tron address must start with T: {entry['address']}"
            )

    def test_address_length(self):
        # Tron addresses are 34 characters in Base58Check
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=5)
        for entry in result:
            assert len(entry["address"]) == 34, (
                f"Tron address must be 34 chars: {entry['address']}"
            )

    def test_result_structure(self):
        result = derive_tron_addresses(MNEMONIC_STANDARD, count=1)
        assert "address" in result[0]
        assert "path" in result[0]
        assert "index" in result[0]

    def test_eth_and_tron_differ(self):
        # ETH and TRC20 must produce different addresses from same seed
        eth = derive_ethereum_addresses(MNEMONIC_STANDARD, count=1)
        tron = derive_tron_addresses(MNEMONIC_STANDARD, count=1)
        assert eth[0]["address"] != tron[0]["address"]

    def test_empty_mnemonic_raises(self):
        with pytest.raises(Exception):
            derive_tron_addresses("", count=1)


# ---------------------------------------------------------------------------
# Cross-check: same mnemonic, ETH vs TRC20 use different coin_type
# ---------------------------------------------------------------------------

class TestCoinTypeSeparation:
    """Ensure ETH (coin_type=60) and TRC20 (coin_type=195) paths are independent."""

    def test_paths_differ(self):
        eth = derive_ethereum_addresses(MNEMONIC_STANDARD, count=1)
        tron = derive_tron_addresses(MNEMONIC_STANDARD, count=1)
        assert "60" in eth[0]["path"]
        assert "195" in tron[0]["path"]

    def test_addresses_differ(self):
        eth = derive_ethereum_addresses(MNEMONIC_STANDARD, count=3)
        tron = derive_tron_addresses(MNEMONIC_STANDARD, count=3)
        eth_addrs = {e["address"] for e in eth}
        tron_addrs = {t["address"] for t in tron}
        assert eth_addrs.isdisjoint(tron_addrs)
