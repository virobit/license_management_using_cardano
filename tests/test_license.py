"""Tests for cardano_license.core module.

Wallet generation, key derivation, encrypted storage,
SQLite metadata, balance/UTXO querying, convenience functions,
signature token minting, balance, and transfer,
validity token minting, checking, renewal, and revocation,
document signing, verification, and work product management.
"""

import os
import json
import asyncio
import pytest
import aiosqlite
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from tests.conftest import TEST_DB, TEST_WALLET_DIR


# Fixtures (patch_paths, setup_db) are in conftest.py

import cardano_license
import cardano_license.core as cardano_license_core
from pycardano import (
    Value,
    Address,
    PaymentSigningKey,
    PaymentVerificationKey,
    ScriptPubkey,
    MultiAsset,
    AssetName,
    Asset,
)


# ── Key Derivation Tests ──────────────────────────────────────────

class TestKeyDerivation:
    def test_generate_mnemonic(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        words = mnemonic.split()
        assert len(words) == 24

    def test_derive_keys_from_mnemonic(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        assert "payment_sk" in keys
        assert "payment_vk" in keys
        assert "payment_key_hash" in keys
        assert "stake_sk" in keys
        assert "stake_vk" in keys
        assert "stake_key_hash" in keys
        assert "base_address" in keys
        assert "enterprise_address" in keys
        assert "network" in keys

    def test_address_format_testnet(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()

        with patch.object(cardano_license_core, "CARDANO_NETWORK", "testnet"):
            keys = cardano_license.derive_keys_from_mnemonic(mnemonic)
            assert keys["base_address"].startswith("addr_test1")
            assert keys["enterprise_address"].startswith("addr_test1")

    def test_address_format_mainnet(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()

        with patch.object(cardano_license_core, "CARDANO_NETWORK", "mainnet"):
            keys = cardano_license.derive_keys_from_mnemonic(mnemonic)
            assert keys["base_address"].startswith("addr1")
            assert not keys["base_address"].startswith("addr_test")

    def test_deterministic_derivation(self):
        """Same mnemonic produces same keys."""
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys1 = cardano_license.derive_keys_from_mnemonic(mnemonic)
        keys2 = cardano_license.derive_keys_from_mnemonic(mnemonic)

        assert keys1["payment_key_hash"] == keys2["payment_key_hash"]
        assert keys1["stake_key_hash"] == keys2["stake_key_hash"]
        assert keys1["base_address"] == keys2["base_address"]

    def test_different_mnemonics_different_keys(self):
        from pycardano import HDWallet
        m1 = HDWallet.generate_mnemonic()
        m2 = HDWallet.generate_mnemonic()
        k1 = cardano_license.derive_keys_from_mnemonic(m1)
        k2 = cardano_license.derive_keys_from_mnemonic(m2)

        assert k1["payment_key_hash"] != k2["payment_key_hash"]
        assert k1["base_address"] != k2["base_address"]

    def test_key_hash_is_hex(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        # 28-byte hash = 56 hex chars
        assert len(keys["payment_key_hash"]) == 56
        assert len(keys["stake_key_hash"]) == 56
        # Valid hex
        int(keys["payment_key_hash"], 16)
        int(keys["stake_key_hash"], 16)


# ── Encrypted Key File Tests ──────────────────────────────────────

class TestEncryptedKeys:
    def test_save_wallet_keys(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        path = cardano_license.save_wallet_keys(
            "test_wallet", mnemonic, keys["payment_sk"], keys["stake_sk"]
        )

        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert data["label"] == "test_wallet"
        assert "mnemonic_enc" in data
        assert "payment_sk_enc" in data
        assert "stake_sk_enc" in data
        # Encrypted values should not contain the mnemonic in plain text
        assert mnemonic not in data["mnemonic_enc"]

    def test_load_wallet_keys_roundtrip(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        cardano_license.save_wallet_keys(
            "roundtrip_test", mnemonic, keys["payment_sk"], keys["stake_sk"]
        )

        loaded = cardano_license.load_wallet_keys("roundtrip_test")

        assert loaded["mnemonic"] == mnemonic
        assert loaded["payment_key_hash"] == keys["payment_key_hash"]
        assert loaded["stake_key_hash"] == keys["stake_key_hash"]
        assert loaded["base_address"] == keys["base_address"]
        assert loaded["label"] == "roundtrip_test"

    def test_load_nonexistent_wallet(self):
        with pytest.raises(FileNotFoundError):
            cardano_license.load_wallet_keys("nonexistent")

    def test_wallet_dir_created(self):
        from pycardano import HDWallet
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        cardano_license.save_wallet_keys(
            "dir_test", mnemonic, keys["payment_sk"], keys["stake_sk"]
        )
        assert TEST_WALLET_DIR.exists()


# ── SQLite Metadata Tests ─────────────────────────────────────────

class TestSQLiteMetadata:
    @pytest.mark.asyncio
    async def test_store_wallet_metadata(self):
        wallet_id = await cardano_license.store_wallet_metadata(
            wallet_type="authority",
            address="addr_test1qtest123",
            public_key_hash="aabbccdd" * 7,
            label="test_auth",
        )
        assert wallet_id is not None
        assert wallet_id > 0

    @pytest.mark.asyncio
    async def test_get_wallet_by_label(self):
        await cardano_license.store_wallet_metadata(
            wallet_type="licensee",
            address="addr_test1qlabel_test",
            public_key_hash="11223344" * 7,
            label="my_licensee",
        )
        wallet = await cardano_license.get_wallet_by_label("my_licensee")
        assert wallet is not None
        assert wallet["wallet_type"] == "licensee"
        assert wallet["address"] == "addr_test1qlabel_test"

    @pytest.mark.asyncio
    async def test_get_wallet_by_label_not_found(self):
        wallet = await cardano_license.get_wallet_by_label("nonexistent")
        assert wallet is None

    @pytest.mark.asyncio
    async def test_get_wallet_by_address(self):
        await cardano_license.store_wallet_metadata(
            wallet_type="signer",
            address="addr_test1qaddr_lookup",
            public_key_hash="55667788" * 7,
            label="signer1",
        )
        wallet = await cardano_license.get_wallet_by_address("addr_test1qaddr_lookup")
        assert wallet is not None
        assert wallet["label"] == "signer1"

    @pytest.mark.asyncio
    async def test_list_wallets(self):
        await cardano_license.store_wallet_metadata(
            "authority", "addr_test1qa", "aa" * 28, label="auth1"
        )
        await cardano_license.store_wallet_metadata(
            "licensee", "addr_test1qb", "bb" * 28, label="lic1"
        )
        wallets = await cardano_license.list_wallets()
        assert len(wallets) == 2

    @pytest.mark.asyncio
    async def test_list_wallets_by_type(self):
        await cardano_license.store_wallet_metadata(
            "authority", "addr_test1qa2", "cc" * 28, label="auth2"
        )
        await cardano_license.store_wallet_metadata(
            "licensee", "addr_test1qb2", "dd" * 28, label="lic2"
        )
        auths = await cardano_license.list_wallets(wallet_type="authority")
        assert len(auths) == 1
        assert auths[0]["wallet_type"] == "authority"

    @pytest.mark.asyncio
    async def test_invalid_wallet_type(self):
        with pytest.raises(ValueError, match="Invalid wallet_type"):
            await cardano_license.store_wallet_metadata(
                "invalid", "addr_test1qx", "ee" * 28
            )

    @pytest.mark.asyncio
    async def test_upsert_on_conflict(self):
        await cardano_license.store_wallet_metadata(
            "authority", "addr_test1qupsert", "ff" * 28, label="original"
        )
        await cardano_license.store_wallet_metadata(
            "licensee", "addr_test1qupsert", "ff" * 28, label="updated"
        )
        wallet = await cardano_license.get_wallet_by_address("addr_test1qupsert")
        assert wallet["wallet_type"] == "licensee"
        assert wallet["label"] == "updated"


# ── Network Configuration Tests ───────────────────────────────────

class TestNetworkConfig:
    def test_get_network_testnet(self):
        from pycardano import Network
        with patch.object(cardano_license_core, "CARDANO_NETWORK", "testnet"):
            assert cardano_license_core._get_network() == Network.TESTNET

    def test_get_network_mainnet(self):
        from pycardano import Network
        with patch.object(cardano_license_core, "CARDANO_NETWORK", "mainnet"):
            assert cardano_license_core._get_network() == Network.MAINNET

    def test_blockfrost_url_testnet(self):
        with patch.object(cardano_license_core, "CARDANO_NETWORK", "testnet"):
            url = cardano_license_core._get_blockfrost_url()
            assert "preprod" in url

    def test_blockfrost_url_mainnet(self):
        with patch.object(cardano_license_core, "CARDANO_NETWORK", "mainnet"):
            url = cardano_license_core._get_blockfrost_url()
            assert "mainnet" in url

    def test_blockfrost_url_preview(self):
        with patch.object(cardano_license_core, "CARDANO_NETWORK", "preview"):
            url = cardano_license_core._get_blockfrost_url()
            assert "preview" in url

    def test_get_chain_context_no_project_id(self):
        with patch.object(cardano_license_core, "BLOCKFROST_PROJECT_ID", ""):
            with pytest.raises(ValueError, match="BLOCKFROST_PROJECT_ID"):
                cardano_license.get_chain_context()

    @patch("cardano_license.core.BlockFrostChainContext")
    def test_get_chain_context_with_project_id(self, mock_bfcc):
        mock_bfcc.return_value = MagicMock()
        with patch.object(cardano_license_core, "BLOCKFROST_PROJECT_ID", "test_id_123"):
            ctx = cardano_license.get_chain_context()
            assert ctx is not None
            mock_bfcc.assert_called_once()


# ── Wallet Generation Convenience Tests ───────────────────────────

class TestWalletGeneration:
    @pytest.mark.asyncio
    async def test_generate_wallet(self):
        result = await cardano_license.generate_wallet("authority", "gen_test")

        assert result["wallet_type"] == "authority"
        assert result["label"] == "gen_test"
        assert result["base_address"].startswith("addr_test1")
        assert len(result["mnemonic"].split()) == 24
        assert result["wallet_id"] > 0

        # Verify stored in DB
        wallet = await cardano_license.get_wallet_by_label("gen_test")
        assert wallet is not None
        assert wallet["address"] == result["base_address"]

    @pytest.mark.asyncio
    async def test_generate_wallet_saves_keys(self):
        result = await cardano_license.generate_wallet("licensee", "keysave_test")
        key_file = TEST_WALLET_DIR / "keysave_test.json"
        assert key_file.exists()

    @pytest.mark.asyncio
    async def test_generate_wallet_no_save(self):
        result = await cardano_license.generate_wallet(
            "observer", "nosave_test", save_keys=False
        )
        key_file = TEST_WALLET_DIR / "nosave_test.json"
        assert not key_file.exists()
        # But metadata still in DB
        wallet = await cardano_license.get_wallet_by_label("nosave_test")
        assert wallet is not None

    @pytest.mark.asyncio
    async def test_generate_wallet_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid wallet_type"):
            await cardano_license.generate_wallet("admin", "bad_type")

    @pytest.mark.asyncio
    async def test_create_authority_wallet(self):
        result = await cardano_license.create_authority_wallet("my_authority")
        assert result["wallet_type"] == "authority"
        assert result["label"] == "my_authority"

    @pytest.mark.asyncio
    async def test_create_licensee_wallet(self):
        result = await cardano_license.create_licensee_wallet("my_licensee")
        assert result["wallet_type"] == "licensee"
        assert result["label"] == "my_licensee"

    @pytest.mark.asyncio
    async def test_generate_and_load_roundtrip(self):
        """Generate wallet, then load keys and verify match."""
        result = await cardano_license.generate_wallet("signer", "roundtrip")
        loaded = cardano_license.load_wallet_keys("roundtrip")

        assert loaded["mnemonic"] == result["mnemonic"]
        assert loaded["base_address"] == result["base_address"]
        assert loaded["payment_key_hash"] == result["payment_key_hash"]


# ── Balance/UTXO Query Tests (mocked) ────────────────────────────

class TestBalanceQueries:
    def _make_mock_utxo(self, lovelace=5_000_000, has_assets=False):
        """Create a mock UTXO object."""
        mock_utxo = MagicMock()
        mock_utxo.input.transaction_id.to_primitive.return_value.hex.return_value = "aabb" * 8
        mock_utxo.input.index = 0

        if has_assets:
            mock_value = MagicMock(spec=Value)
            mock_value.coin = lovelace

            mock_policy_id = MagicMock()
            mock_policy_id.to_primitive.return_value.hex.return_value = "cc" * 28

            mock_asset_name = MagicMock()
            mock_asset_name.to_primitive.return_value.hex.return_value = "4d79546f6b656e"

            mock_value.multi_asset = {mock_policy_id: {mock_asset_name: 100}}
            mock_utxo.output.amount = mock_value
        else:
            mock_utxo.output.amount = lovelace

        return mock_utxo

    @patch.object(cardano_license_core, "get_chain_context")
    def test_query_balance_lovelace_only(self, mock_ctx):
        ctx = MagicMock()
        ctx.utxos.return_value = [self._make_mock_utxo(5_000_000)]
        mock_ctx.return_value = ctx

        bal = cardano_license.query_balance("addr_test1q123")
        assert bal["lovelace"] == 5_000_000
        assert bal["ada"] == 5.0
        assert bal["utxo_count"] == 1
        assert bal["native_assets"] == {}

    @patch.object(cardano_license_core, "get_chain_context")
    def test_query_balance_with_native_assets(self, mock_ctx):
        ctx = MagicMock()
        ctx.utxos.return_value = [self._make_mock_utxo(2_000_000, has_assets=True)]
        mock_ctx.return_value = ctx

        bal = cardano_license.query_balance("addr_test1q456")
        assert bal["lovelace"] == 2_000_000
        assert bal["ada"] == 2.0
        assert len(bal["native_assets"]) == 1

    @patch.object(cardano_license_core, "get_chain_context")
    def test_query_balance_empty(self, mock_ctx):
        ctx = MagicMock()
        ctx.utxos.return_value = []
        mock_ctx.return_value = ctx

        bal = cardano_license.query_balance("addr_test1qempty")
        assert bal["lovelace"] == 0
        assert bal["ada"] == 0.0
        assert bal["utxo_count"] == 0

    @patch.object(cardano_license_core, "get_chain_context")
    def test_query_balance_multiple_utxos(self, mock_ctx):
        ctx = MagicMock()
        ctx.utxos.return_value = [
            self._make_mock_utxo(3_000_000),
            self._make_mock_utxo(7_000_000),
        ]
        mock_ctx.return_value = ctx

        bal = cardano_license.query_balance("addr_test1qmulti")
        assert bal["lovelace"] == 10_000_000
        assert bal["ada"] == 10.0
        assert bal["utxo_count"] == 2

    @patch.object(cardano_license_core, "get_chain_context")
    def test_query_utxos(self, mock_ctx):
        ctx = MagicMock()
        ctx.utxos.return_value = [self._make_mock_utxo(5_000_000)]
        mock_ctx.return_value = ctx

        utxos = cardano_license.query_utxos("addr_test1q789")
        assert len(utxos) == 1
        assert utxos[0]["lovelace"] == 5_000_000
        assert "tx_hash" in utxos[0]
        assert "index" in utxos[0]

    @pytest.mark.asyncio
    async def test_get_wallet_balance_not_found(self):
        with pytest.raises(ValueError, match="Wallet not found"):
            await cardano_license.get_wallet_balance("nonexistent")

    @pytest.mark.asyncio
    async def test_get_wallet_utxos_not_found(self):
        with pytest.raises(ValueError, match="Wallet not found"):
            await cardano_license.get_wallet_utxos("nonexistent")

    @pytest.mark.asyncio
    @patch.object(cardano_license_core, "query_balance")
    async def test_get_wallet_balance_by_label(self, mock_qb):
        mock_qb.return_value = {"lovelace": 1_000_000, "ada": 1.0}
        await cardano_license.store_wallet_metadata(
            "authority", "addr_test1qbaltest", "aa" * 28, label="bal_test"
        )
        result = await cardano_license.get_wallet_balance("bal_test")
        mock_qb.assert_called_once_with("addr_test1qbaltest")

    @pytest.mark.asyncio
    @patch.object(cardano_license_core, "query_utxos")
    async def test_get_wallet_utxos_by_label(self, mock_qu):
        mock_qu.return_value = [{"tx_hash": "abc", "index": 0, "lovelace": 5000000}]
        await cardano_license.store_wallet_metadata(
            "licensee", "addr_test1qutxotest", "bb" * 28, label="utxo_test"
        )
        result = await cardano_license.get_wallet_utxos("utxo_test")
        mock_qu.assert_called_once_with("addr_test1qutxotest")


# ── Status Tests ──────────────────────────────────────────────────

class TestStatus:
    @pytest.mark.asyncio
    async def test_get_cardano_status(self):
        status = await cardano_license.get_cardano_status()
        assert "network" in status
        assert "blockfrost_configured" in status
        assert "wallet_count" in status
        assert "wallets_by_type" in status
        assert set(status["wallets_by_type"].keys()) == set(cardano_license.WALLET_TYPES)

    @pytest.mark.asyncio
    async def test_status_counts_wallets(self):
        await cardano_license.generate_wallet("authority", "stat_auth", save_keys=False)
        await cardano_license.generate_wallet("licensee", "stat_lic", save_keys=False)

        status = await cardano_license.get_cardano_status()
        assert status["wallet_count"] == 2
        assert status["wallets_by_type"]["authority"] == 1
        assert status["wallets_by_type"]["licensee"] == 1

    @pytest.mark.asyncio
    async def test_status_includes_license_count(self):
        status = await cardano_license.get_cardano_status()
        assert "license_count" in status
        assert "licenses_by_status" in status
        assert status["license_count"] == 0


# ── Minting Policy Tests ─────────────────────────────────────────

class TestMintingPolicy:
    def test_create_minting_policy(self):
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)
        policy = cardano_license.create_minting_policy(vk)

        assert isinstance(policy, ScriptPubkey)
        assert policy.hash() is not None

    def test_policy_bound_to_key(self):
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)
        policy = cardano_license.create_minting_policy(vk)

        assert policy.key_hash == vk.hash()

    def test_different_keys_different_policies(self):
        sk1 = PaymentSigningKey.generate()
        vk1 = PaymentVerificationKey.from_signing_key(sk1)
        sk2 = PaymentSigningKey.generate()
        vk2 = PaymentVerificationKey.from_signing_key(sk2)

        p1 = cardano_license.create_minting_policy(vk1)
        p2 = cardano_license.create_minting_policy(vk2)

        assert p1.hash() != p2.hash()

    def test_same_key_same_policy(self):
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)

        p1 = cardano_license.create_minting_policy(vk)
        p2 = cardano_license.create_minting_policy(vk)

        assert p1.hash() == p2.hash()

    def test_policy_hash_is_script_hash(self):
        from pycardano.hash import ScriptHash
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)
        policy = cardano_license.create_minting_policy(vk)

        assert isinstance(policy.hash(), ScriptHash)

    def test_policy_hash_hex_length(self):
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)
        policy = cardano_license.create_minting_policy(vk)

        # Script hash = 28 bytes = 56 hex chars
        hex_str = policy.hash().to_primitive().hex()
        assert len(hex_str) == 56


# ── CIP-25 Metadata Tests ────────────────────────────────────────

SAMPLE_LICENSE_METADATA = {
    "license_type": "professional_engineer",
    "licensee_name": "Jane Doe",
    "issuing_authority": "State Board of Engineers",
    "issue_date": "2026-01-15",
    "expiry_date": "2028-01-15",
    "jurisdiction": "California",
    "license_number": "PE-2026-12345",
}


class TestCIP25Metadata:
    def _get_test_policy_id(self):
        sk = PaymentSigningKey.generate()
        vk = PaymentVerificationKey.from_signing_key(sk)
        policy = cardano_license.create_minting_policy(vk)
        return policy.hash()

    def test_build_cip25_metadata_structure(self):
        policy_id = self._get_test_policy_id()
        result = cardano_license.build_cip25_metadata(
            policy_id, "LICPE202612345", SAMPLE_LICENSE_METADATA
        )

        assert 721 in result
        policy_hex = policy_id.to_primitive().hex()
        assert policy_hex in result[721]
        assert "LICPE202612345" in result[721][policy_hex]

    def test_build_cip25_metadata_fields(self):
        policy_id = self._get_test_policy_id()
        result = cardano_license.build_cip25_metadata(
            policy_id, "LICPE202612345", SAMPLE_LICENSE_METADATA
        )

        policy_hex = policy_id.to_primitive().hex()
        token_data = result[721][policy_hex]["LICPE202612345"]

        assert token_data["name"] == "LICPE202612345"
        assert token_data["license_type"] == "professional_engineer"
        assert token_data["licensee_name"] == "Jane Doe"
        assert token_data["issuing_authority"] == "State Board of Engineers"
        assert token_data["issue_date"] == "2026-01-15"
        assert token_data["expiry_date"] == "2028-01-15"
        assert token_data["jurisdiction"] == "California"
        assert token_data["license_number"] == "PE-2026-12345"

    def test_build_cip25_with_image(self):
        policy_id = self._get_test_policy_id()
        meta = {**SAMPLE_LICENSE_METADATA, "image": "ipfs://QmTestHash123"}
        result = cardano_license.build_cip25_metadata(policy_id, "LIC001", meta)

        policy_hex = policy_id.to_primitive().hex()
        assert result[721][policy_hex]["LIC001"]["image"] == "ipfs://QmTestHash123"

    def test_build_cip25_with_description(self):
        policy_id = self._get_test_policy_id()
        meta = {**SAMPLE_LICENSE_METADATA, "description": "Professional Engineering License"}
        result = cardano_license.build_cip25_metadata(policy_id, "LIC001", meta)

        policy_hex = policy_id.to_primitive().hex()
        assert result[721][policy_hex]["LIC001"]["description"] == "Professional Engineering License"

    def test_build_cip25_missing_required_field(self):
        policy_id = self._get_test_policy_id()
        incomplete = {k: v for k, v in SAMPLE_LICENSE_METADATA.items() if k != "license_number"}

        with pytest.raises(ValueError, match="Missing required.*license_number"):
            cardano_license.build_cip25_metadata(policy_id, "LIC001", incomplete)

    def test_build_cip25_missing_multiple_fields(self):
        policy_id = self._get_test_policy_id()
        with pytest.raises(ValueError, match="Missing required"):
            cardano_license.build_cip25_metadata(policy_id, "LIC001", {})

    def test_cip25_label_constant(self):
        assert cardano_license.CIP25_METADATA_LABEL == 721


# ── Token Name Generation Tests ───────────────────────────────────

class TestTokenNameGeneration:
    def test_basic_license_number(self):
        assert cardano_license_core._generate_token_name("PE-2026-12345") == "LICPE202612345"

    def test_alphanumeric_only(self):
        assert cardano_license_core._generate_token_name("A/B.C-D") == "LICABCD"

    def test_truncation_at_32_bytes(self):
        long_number = "A" * 40
        result = cardano_license_core._generate_token_name(long_number)
        assert len(result) <= 32
        assert result.startswith("LIC")

    def test_empty_license_number(self):
        result = cardano_license_core._generate_token_name("")
        assert result == "LIC"

    def test_special_chars_stripped(self):
        result = cardano_license_core._generate_token_name("PE#2026@12345!")
        assert result == "LICPE202612345"


# ── License DB Record Tests ───────────────────────────────────────

class TestLicenseDBRecords:
    @pytest.mark.asyncio
    async def test_store_license_record(self):
        license_id = await cardano_license_core._store_license_record(
            token_name="LICPE001",
            policy_id="aa" * 28,
            licensee_address="addr_test1qlic",
            authority_address="addr_test1qauth",
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="ff" * 32,
            license_type="professional_engineer",
            valid_from="2026-01-15",
            valid_until="2028-01-15",
        )
        assert license_id > 0

    @pytest.mark.asyncio
    async def test_get_license_by_id(self):
        lid = await cardano_license_core._store_license_record(
            token_name="LICPE002",
            policy_id="bb" * 28,
            licensee_address="addr_test1qlic2",
            authority_address="addr_test1qauth2",
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="ee" * 32,
        )

        lic = await cardano_license.get_license_by_id(lid)
        assert lic is not None
        assert lic["token_name"] == "LICPE002"
        assert lic["status"] == "active"
        assert lic["policy_id"] == "bb" * 28

    @pytest.mark.asyncio
    async def test_get_license_by_id_not_found(self):
        lic = await cardano_license.get_license_by_id(99999)
        assert lic is None

    @pytest.mark.asyncio
    async def test_get_license_by_tx_hash(self):
        tx_hash = "dd" * 32
        await cardano_license_core._store_license_record(
            token_name="LICPE003",
            policy_id="cc" * 28,
            licensee_address="addr_test1qlic3",
            authority_address="addr_test1qauth3",
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash=tx_hash,
        )

        lic = await cardano_license.get_license_by_tx_hash(tx_hash)
        assert lic is not None
        assert lic["token_name"] == "LICPE003"

    @pytest.mark.asyncio
    async def test_get_license_by_tx_hash_not_found(self):
        lic = await cardano_license.get_license_by_tx_hash("0000" * 16)
        assert lic is None

    @pytest.mark.asyncio
    async def test_list_licenses_all(self):
        await cardano_license_core._store_license_record(
            "LIC1", "aa" * 28, "addr1", "auth1", {}, "tx1"
        )
        await cardano_license_core._store_license_record(
            "LIC2", "bb" * 28, "addr2", "auth2", {}, "tx2"
        )

        lics = await cardano_license.list_licenses()
        assert len(lics) == 2

    @pytest.mark.asyncio
    async def test_list_licenses_by_status(self):
        await cardano_license_core._store_license_record(
            "LIC3", "cc" * 28, "addr3", "auth3", {}, "tx3"
        )

        active = await cardano_license.list_licenses(status="active")
        assert len(active) == 1
        assert active[0]["token_name"] == "LIC3"

        revoked = await cardano_license.list_licenses(status="revoked")
        assert len(revoked) == 0

    @pytest.mark.asyncio
    async def test_list_licenses_by_licensee(self):
        await cardano_license_core._store_license_record(
            "LIC4", "dd" * 28, "addr_specific", "auth4", {}, "tx4"
        )
        await cardano_license_core._store_license_record(
            "LIC5", "ee" * 28, "addr_other", "auth5", {}, "tx5"
        )

        lics = await cardano_license.list_licenses(licensee_address="addr_specific")
        assert len(lics) == 1
        assert lics[0]["token_name"] == "LIC4"

    @pytest.mark.asyncio
    async def test_list_licenses_by_authority(self):
        await cardano_license_core._store_license_record(
            "LIC6", "ff" * 28, "addr6", "auth_target", {}, "tx6"
        )
        lics = await cardano_license.list_licenses(authority_address="auth_target")
        assert len(lics) == 1

    @pytest.mark.asyncio
    async def test_license_metadata_stored_as_json(self):
        await cardano_license_core._store_license_record(
            "LIC7", "aa" * 28, "addr7", "auth7",
            SAMPLE_LICENSE_METADATA, "tx7",
        )
        lic = await cardano_license.get_license_by_tx_hash("tx7")
        stored_meta = json.loads(lic["metadata_json"])
        assert stored_meta["licensee_name"] == "Jane Doe"
        assert stored_meta["license_number"] == "PE-2026-12345"

    @pytest.mark.asyncio
    async def test_license_valid_dates(self):
        await cardano_license_core._store_license_record(
            "LIC8", "bb" * 28, "addr8", "auth8", {},
            "tx8", "professional", "2026-01-01", "2028-12-31",
        )
        lic = await cardano_license.get_license_by_tx_hash("tx8")
        assert lic["valid_from"] == "2026-01-01"
        assert lic["valid_until"] == "2028-12-31"


# ── Mint License NFT Integration Tests (mocked chain) ────────────

def _make_valid_testnet_address():
    """Generate a valid testnet enterprise address for test fixtures."""
    sk = PaymentSigningKey.generate()
    vk = PaymentVerificationKey.from_signing_key(sk)
    from pycardano import Network
    return str(Address(vk.hash(), network=Network.TESTNET))


class TestMintLicenseNFT:
    @pytest.fixture
    async def authority_wallet(self):
        """Generate an authority wallet for minting tests."""
        return await cardano_license.generate_wallet("authority", "mint_authority")

    @pytest.fixture
    def licensee_address(self):
        return _make_valid_testnet_address()

    @pytest.fixture
    def mock_chain_context(self):
        """Mock the Blockfrost chain context for transaction building."""
        mock_ctx = MagicMock()
        mock_ctx.utxos.return_value = []
        return mock_ctx

    @pytest.mark.asyncio
    async def test_mint_license_nft_success(self, authority_wallet, licensee_address):
        """Test full minting flow with mocked chain context."""
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ab" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        assert result["status"] == "active"
        assert result["policy_id"]  # non-empty
        assert result["token_name"] == "LICPE202612345"
        assert result["tx_hash"] == "ab" * 32
        assert result["licensee_address"] == licensee_address
        assert result["metadata"] == SAMPLE_LICENSE_METADATA
        assert result["license_id"] > 0

    @pytest.mark.asyncio
    async def test_mint_stores_db_record(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "cd" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        # Verify DB record
        lic = await cardano_license.get_license_by_id(result["license_id"])
        assert lic is not None
        assert lic["token_name"] == "LICPE202612345"
        assert lic["mint_tx_hash"] == "cd" * 32
        assert lic["status"] == "active"
        assert lic["license_type"] == "professional_engineer"
        assert lic["valid_from"] == "2026-01-15"
        assert lic["valid_until"] == "2028-01-15"

    @pytest.mark.asyncio
    async def test_mint_builds_correct_multiasset(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ef" * 32

        captured_builder_state = {}

        class FakeBuilder:
            def __init__(self, ctx):
                self._mint = None
                self._native_scripts = None
                self.auxiliary_data = None

            def add_input_address(self, addr):
                return self

            def add_minting_script(self, script):
                captured_builder_state["script"] = script
                return self

            def add_output(self, output):
                captured_builder_state["output"] = output
                return self

            @property
            def mint(self):
                return self._mint

            @mint.setter
            def mint(self, value):
                self._mint = value
                captured_builder_state["mint"] = value

            def build_and_sign(self, signing_keys, change_address):
                return mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", FakeBuilder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        # Verify minting script is ScriptPubkey
        assert isinstance(captured_builder_state["script"], ScriptPubkey)

        # Verify mint is MultiAsset with quantity 1
        mint_ma = captured_builder_state["mint"]
        assert isinstance(mint_ma, MultiAsset)
        total_minted = 0
        for policy_id, assets in mint_ma.items():
            for asset_name, qty in assets.items():
                total_minted += qty
        assert total_minted == 1

    @pytest.mark.asyncio
    async def test_mint_attaches_cip25_metadata(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "11" * 32

        captured = {}

        class FakeBuilder:
            def __init__(self, ctx):
                self._mint = None
                self._auxiliary_data = None

            def add_input_address(self, addr):
                return self

            def add_minting_script(self, script):
                return self

            def add_output(self, output):
                return self

            @property
            def mint(self):
                return self._mint

            @mint.setter
            def mint(self, value):
                self._mint = value

            @property
            def auxiliary_data(self):
                return self._auxiliary_data

            @auxiliary_data.setter
            def auxiliary_data(self, value):
                self._auxiliary_data = value
                captured["aux_data"] = value

            def build_and_sign(self, signing_keys, change_address):
                return mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", FakeBuilder):
            await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        from pycardano import AuxiliaryData
        assert "aux_data" in captured
        assert captured["aux_data"] is not None

    @pytest.mark.asyncio
    async def test_mint_missing_metadata_fields(self, authority_wallet, licensee_address):
        incomplete = {"license_type": "professional"}

        with pytest.raises(ValueError, match="Missing required"):
            await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                incomplete,
            )

    @pytest.mark.asyncio
    async def test_mint_wallet_not_found(self, licensee_address):
        with pytest.raises(FileNotFoundError):
            await cardano_license.mint_license_nft(
                "nonexistent_wallet",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

    @pytest.mark.asyncio
    async def test_mint_with_image_uri(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "22" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()
        meta_with_image = {
            **SAMPLE_LICENSE_METADATA,
            "image": "ipfs://QmImageHash123456",
        }

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                meta_with_image,
            )

        assert result["metadata"]["image"] == "ipfs://QmImageHash123456"

    @pytest.mark.asyncio
    async def test_mint_chain_submission_failure(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "33" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()
        mock_ctx.submit_tx.side_effect = Exception("Transaction rejected by node")

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            with pytest.raises(Exception, match="Transaction rejected"):
                await cardano_license.mint_license_nft(
                    "mint_authority",
                    licensee_address,
                    SAMPLE_LICENSE_METADATA,
                )

    @pytest.mark.asyncio
    async def test_mint_policy_id_hex_format(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "44" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        # Policy ID should be 56 hex chars (28 bytes)
        assert len(result["policy_id"]) == 56
        int(result["policy_id"], 16)  # Valid hex

    @pytest.mark.asyncio
    async def test_mint_asset_name_hex(self, authority_wallet, licensee_address):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "55" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_license_nft(
                "mint_authority",
                licensee_address,
                SAMPLE_LICENSE_METADATA,
            )

        # asset_name_hex should be valid hex encoding of UTF-8 token name
        decoded = bytes.fromhex(result["asset_name_hex"]).decode("utf-8")
        assert decoded == "LICPE202612345"


# ── Signature Token Name Generation Tests ─────────────────────────

class TestSigTokenNameGeneration:
    def test_basic_sig_token_name(self):
        assert cardano_license_core._generate_sig_token_name(1) == "SIG1_0"

    def test_sig_token_name_with_batch(self):
        assert cardano_license_core._generate_sig_token_name(42, 3) == "SIG42_3"

    def test_sig_token_name_truncation(self):
        result = cardano_license_core._generate_sig_token_name(999999999999999999999)
        assert len(result) <= 32
        assert result.startswith("SIG")


# ── Signature Token DB Record Tests ──────────────────────────────

class TestSignatureTokenDBRecords:
    @pytest.mark.asyncio
    async def test_store_signature_token_record(self):
        token_id = await cardano_license_core._store_signature_token_record(
            policy_id="aa" * 28,
            token_name="SIG1_0",
            licensee_address="addr_test1qsig",
            license_ref=1,
            quantity=10,
            mint_tx_hash="ff" * 32,
        )
        assert token_id > 0

    @pytest.mark.asyncio
    async def test_get_signature_token_by_id(self):
        token_id = await cardano_license_core._store_signature_token_record(
            policy_id="bb" * 28,
            token_name="SIG2_0",
            licensee_address="addr_test1qsig2",
            license_ref=2,
            quantity=5,
            mint_tx_hash="ee" * 32,
        )

        token = await cardano_license.get_signature_token_by_id(token_id)
        assert token is not None
        assert token["token_name"] == "SIG2_0"
        assert token["quantity"] == 5
        assert token["status"] == "minted"

    @pytest.mark.asyncio
    async def test_get_signature_token_by_id_not_found(self):
        token = await cardano_license.get_signature_token_by_id(99999)
        assert token is None

    @pytest.mark.asyncio
    async def test_list_signature_tokens_all(self):
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", "addr1", 1, 5, "tx1"
        )
        await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG2_0", "addr2", 2, 10, "tx2"
        )
        tokens = await cardano_license.list_signature_tokens()
        assert len(tokens) == 2

    @pytest.mark.asyncio
    async def test_list_signature_tokens_by_licensee(self):
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", "addr_specific", 1, 5, "tx1"
        )
        await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG2_0", "addr_other", 2, 10, "tx2"
        )
        tokens = await cardano_license.list_signature_tokens(
            licensee_address="addr_specific"
        )
        assert len(tokens) == 1
        assert tokens[0]["token_name"] == "SIG1_0"

    @pytest.mark.asyncio
    async def test_list_signature_tokens_by_license_ref(self):
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", "addr1", 1, 5, "tx1"
        )
        await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG2_0", "addr2", 2, 10, "tx2"
        )
        tokens = await cardano_license.list_signature_tokens(license_ref=1)
        assert len(tokens) == 1
        assert tokens[0]["license_ref"] == 1

    @pytest.mark.asyncio
    async def test_list_signature_tokens_by_status(self):
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", "addr1", 1, 5, "tx1"
        )
        tokens = await cardano_license.list_signature_tokens(status="minted")
        assert len(tokens) == 1

        burned = await cardano_license.list_signature_tokens(status="burned")
        assert len(burned) == 0


# ── Signature Balance Tests ──────────────────────────────────────

class TestSignatureBalance:
    @pytest.mark.asyncio
    async def test_get_signature_balance_empty(self):
        await cardano_license.store_wallet_metadata(
            "licensee", "addr_test1qbal_empty", "aa" * 28, label="bal_empty"
        )
        balance = await cardano_license.get_signature_balance("bal_empty")
        assert balance["total_tokens"] == 0
        assert balance["by_license"] == {}
        assert balance["token_records"] == []

    @pytest.mark.asyncio
    async def test_get_signature_balance_with_tokens(self):
        addr = "addr_test1qbal_tokens"
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "bb" * 28, label="bal_tokens"
        )
        # Create a license record first
        lic_id = await cardano_license_core._store_license_record(
            "LIC1", "cc" * 28, addr, "auth_addr", {}, "tx_lic",
            license_type="professional",
        )
        # Store signature tokens
        await cardano_license_core._store_signature_token_record(
            "dd" * 28, "SIG1_0", addr, lic_id, 10, "tx_sig1"
        )

        balance = await cardano_license.get_signature_balance("bal_tokens")
        assert balance["total_tokens"] == 10
        assert balance["by_license"][lic_id] == 10
        assert len(balance["token_records"]) == 1

    @pytest.mark.asyncio
    async def test_get_signature_balance_multiple_licenses(self):
        addr = "addr_test1qbal_multi"
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "cc" * 28, label="bal_multi"
        )
        lic1 = await cardano_license_core._store_license_record(
            "LIC1", "dd" * 28, addr, "auth", {}, "tx1",
            license_type="professional",
        )
        lic2 = await cardano_license_core._store_license_record(
            "LIC2", "ee" * 28, addr, "auth", {}, "tx2",
            license_type="engineering",
        )
        await cardano_license_core._store_signature_token_record(
            "ff" * 28, "SIG1_0", addr, lic1, 5, "tx_sig1"
        )
        await cardano_license_core._store_signature_token_record(
            "ff" * 28, "SIG2_0", addr, lic2, 3, "tx_sig2"
        )

        balance = await cardano_license.get_signature_balance("bal_multi")
        assert balance["total_tokens"] == 8
        assert balance["by_license"][lic1] == 5
        assert balance["by_license"][lic2] == 3

    @pytest.mark.asyncio
    async def test_get_signature_balance_filters_by_license_type(self):
        addr = "addr_test1qbal_filter"
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "dd" * 28, label="bal_filter"
        )
        lic1 = await cardano_license_core._store_license_record(
            "LIC1", "ee" * 28, addr, "auth", {}, "tx1",
            license_type="professional",
        )
        lic2 = await cardano_license_core._store_license_record(
            "LIC2", "ff" * 28, addr, "auth", {}, "tx2",
            license_type="engineering",
        )
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", addr, lic1, 5, "tx_sig1"
        )
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG2_0", addr, lic2, 3, "tx_sig2"
        )

        balance = await cardano_license.get_signature_balance(
            "bal_filter", license_type="professional"
        )
        assert balance["total_tokens"] == 5

    @pytest.mark.asyncio
    async def test_get_signature_balance_wallet_not_found(self):
        with pytest.raises(ValueError, match="Wallet not found"):
            await cardano_license.get_signature_balance("nonexistent")

    @pytest.mark.asyncio
    async def test_get_signature_balance_excludes_burned(self):
        addr = "addr_test1qbal_burn"
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "ee" * 28, label="bal_burn"
        )
        lic = await cardano_license_core._store_license_record(
            "LIC1", "ff" * 28, addr, "auth", {}, "tx1",
        )
        # Minted token
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", addr, lic, 10, "tx_sig1"
        )
        # Burned token (manually set status)
        tid = await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_1", addr, lic, 5, "tx_sig2"
        )
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_signature_tokens SET status = 'burned' WHERE id = ?",
                (tid,),
            )
            await db.commit()

        balance = await cardano_license.get_signature_balance("bal_burn")
        assert balance["total_tokens"] == 10


# ── Signature Token Transfer DB Tests ────────────────────────────

class TestSignatureTransferDB:
    @pytest.mark.asyncio
    async def test_record_signature_transfer_full(self):
        """Full record consumed when transferring equal quantity."""
        addr_from = "addr_test1qfrom"
        addr_to = "addr_test1qto"
        lic = await cardano_license_core._store_license_record(
            "LIC1", "aa" * 28, addr_from, "auth", {}, "tx_lic",
        )
        tid = await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG1_0", addr_from, lic, 5, "tx_mint"
        )
        source_rec = await cardano_license.get_signature_token_by_id(tid)

        await cardano_license_core._record_signature_transfer(
            source_records=[source_rec],
            to_address=addr_to,
            quantity=5,
            policy_id="bb" * 28,
            token_name="SIG1_0",
            license_ref=lic,
            tx_hash="tx_transfer",
        )

        # Source should be marked transferred
        updated = await cardano_license.get_signature_token_by_id(tid)
        assert updated["status"] == "transferred"

        # Recipient should have a new record
        tokens = await cardano_license.list_signature_tokens(
            licensee_address=addr_to
        )
        assert len(tokens) == 1
        assert tokens[0]["quantity"] == 5

    @pytest.mark.asyncio
    async def test_record_signature_transfer_partial(self):
        """Partial transfer reduces source quantity."""
        addr_from = "addr_test1qfrom2"
        addr_to = "addr_test1qto2"
        lic = await cardano_license_core._store_license_record(
            "LIC1", "aa" * 28, addr_from, "auth", {}, "tx_lic",
        )
        tid = await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG1_0", addr_from, lic, 10, "tx_mint"
        )
        source_rec = await cardano_license.get_signature_token_by_id(tid)

        await cardano_license_core._record_signature_transfer(
            source_records=[source_rec],
            to_address=addr_to,
            quantity=3,
            policy_id="bb" * 28,
            token_name="SIG1_0",
            license_ref=lic,
            tx_hash="tx_transfer2",
        )

        # Source should retain 7 tokens
        updated = await cardano_license.get_signature_token_by_id(tid)
        assert updated["quantity"] == 7
        assert updated["status"] == "minted"  # Not fully transferred

        # Recipient gets 3
        tokens = await cardano_license.list_signature_tokens(
            licensee_address=addr_to
        )
        assert len(tokens) == 1
        assert tokens[0]["quantity"] == 3


# ── Mint Signature Tokens Integration Tests (mocked chain) ───────

class TestMintSignatureTokens:
    @pytest.fixture
    async def authority_wallet(self):
        return await cardano_license.generate_wallet("authority", "sig_authority")

    @pytest.fixture
    async def licensee_with_license(self, authority_wallet):
        """Create a licensee wallet and a license for it."""
        addr = _make_valid_testnet_address()
        # Store licensee in DB
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "aa" * 28, label="sig_licensee"
        )
        # Create a license
        lic_id = await cardano_license_core._store_license_record(
            token_name="LICTEST",
            policy_id="bb" * 28,
            licensee_address=addr,
            authority_address=authority_wallet["base_address"],
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="cc" * 32,
            license_type="professional_engineer",
        )
        return {"address": addr, "license_id": lic_id}

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_success(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ab" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=10,
                license_ref=licensee_with_license["license_id"],
            )

        assert result["status"] == "minted"
        assert result["quantity"] == 10
        assert result["token_name"].startswith("SIG")
        assert result["tx_hash"] == "ab" * 32
        assert result["license_ref"] == licensee_with_license["license_id"]
        assert result["token_id"] > 0

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_stores_db_record(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "cd" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=5,
                license_ref=licensee_with_license["license_id"],
            )

        token = await cardano_license.get_signature_token_by_id(result["token_id"])
        assert token is not None
        assert token["quantity"] == 5
        assert token["status"] == "minted"
        assert token["mint_tx_hash"] == "cd" * 32

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_invalid_count(
        self, authority_wallet, licensee_with_license
    ):
        with pytest.raises(ValueError, match="token_count must be >= 1"):
            await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=0,
                license_ref=licensee_with_license["license_id"],
            )

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_negative_count(
        self, authority_wallet, licensee_with_license
    ):
        with pytest.raises(ValueError, match="token_count must be >= 1"):
            await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=-5,
                license_ref=licensee_with_license["license_id"],
            )

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_license_not_found(self, authority_wallet):
        with pytest.raises(ValueError, match="License not found"):
            await cardano_license.mint_signature_tokens(
                "sig_authority",
                "addr_test1qany",
                token_count=5,
                license_ref=99999,
            )

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_wallet_not_found(
        self, licensee_with_license
    ):
        with pytest.raises(FileNotFoundError):
            await cardano_license.mint_signature_tokens(
                "nonexistent_wallet",
                licensee_with_license["address"],
                token_count=5,
                license_ref=licensee_with_license["license_id"],
            )

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_builds_multiasset(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ef" * 32

        captured = {}

        class FakeBuilder:
            def __init__(self, ctx):
                self._mint = None
                self.auxiliary_data = None

            def add_input_address(self, addr):
                return self

            def add_minting_script(self, script):
                captured["script"] = script
                return self

            def add_output(self, output):
                return self

            @property
            def mint(self):
                return self._mint

            @mint.setter
            def mint(self, value):
                self._mint = value
                captured["mint"] = value

            def build_and_sign(self, signing_keys, change_address):
                return mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", FakeBuilder):
            await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=25,
                license_ref=licensee_with_license["license_id"],
            )

        # Verify mint quantity = 25 (fungible)
        mint_ma = captured["mint"]
        assert isinstance(mint_ma, MultiAsset)
        total_minted = 0
        for policy_id, assets in mint_ma.items():
            for asset_name, qty in assets.items():
                total_minted += qty
        assert total_minted == 25

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_policy_id_format(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "11" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_signature_tokens(
                "sig_authority",
                licensee_with_license["address"],
                token_count=1,
                license_ref=licensee_with_license["license_id"],
            )

        # Policy ID should be 56 hex chars
        assert len(result["policy_id"]) == 56
        int(result["policy_id"], 16)

    @pytest.mark.asyncio
    async def test_mint_signature_tokens_chain_failure(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "22" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()
        mock_ctx.submit_tx.side_effect = Exception("Transaction rejected")

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            with pytest.raises(Exception, match="Transaction rejected"):
                await cardano_license.mint_signature_tokens(
                    "sig_authority",
                    licensee_with_license["address"],
                    token_count=5,
                    license_ref=licensee_with_license["license_id"],
                )


# ── Transfer Signature Token Integration Tests (mocked chain) ────

class TestTransferSignatureToken:
    @pytest.fixture
    async def transfer_setup(self):
        """Set up sender wallet with signature tokens."""
        # Create sender wallet
        sender = await cardano_license.generate_wallet("authority", "xfer_sender")
        sender_addr = sender["base_address"]

        # Create license
        lic_id = await cardano_license_core._store_license_record(
            "LICXFER", "aa" * 28, sender_addr, sender_addr,
            {}, "tx_lic", "professional",
        )

        # Store signature tokens for sender
        await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG1_0", sender_addr, lic_id, 10, "tx_mint"
        )

        to_addr = _make_valid_testnet_address()
        return {
            "sender_label": "xfer_sender",
            "sender_addr": sender_addr,
            "to_address": to_addr,
            "license_id": lic_id,
        }

    @pytest.mark.asyncio
    async def test_transfer_signature_token_success(self, transfer_setup):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ab" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.transfer_signature_token(
                transfer_setup["sender_label"],
                transfer_setup["to_address"],
                license_ref=transfer_setup["license_id"],
                quantity=3,
            )

        assert result["status"] == "transferred"
        assert result["quantity"] == 3
        assert result["tx_hash"] == "ab" * 32

    @pytest.mark.asyncio
    async def test_transfer_insufficient_balance(self, transfer_setup):
        with pytest.raises(ValueError, match="Insufficient signature tokens"):
            await cardano_license.transfer_signature_token(
                transfer_setup["sender_label"],
                transfer_setup["to_address"],
                license_ref=transfer_setup["license_id"],
                quantity=100,  # More than 10 available
            )

    @pytest.mark.asyncio
    async def test_transfer_invalid_quantity(self, transfer_setup):
        with pytest.raises(ValueError, match="quantity must be >= 1"):
            await cardano_license.transfer_signature_token(
                transfer_setup["sender_label"],
                transfer_setup["to_address"],
                license_ref=transfer_setup["license_id"],
                quantity=0,
            )

    @pytest.mark.asyncio
    async def test_transfer_wallet_not_found(self):
        with pytest.raises(ValueError, match="Wallet not found"):
            await cardano_license.transfer_signature_token(
                "nonexistent",
                "addr_test1qany",
                license_ref=1,
            )

    @pytest.mark.asyncio
    async def test_transfer_updates_db_records(self, transfer_setup):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "cd" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            await cardano_license.transfer_signature_token(
                transfer_setup["sender_label"],
                transfer_setup["to_address"],
                license_ref=transfer_setup["license_id"],
                quantity=4,
            )

        # Sender should have 6 remaining
        balance = await cardano_license.get_signature_balance("xfer_sender")
        assert balance["total_tokens"] == 6

        # Recipient should have new record with 4
        recipient_tokens = await cardano_license.list_signature_tokens(
            licensee_address=transfer_setup["to_address"]
        )
        assert len(recipient_tokens) == 1
        assert recipient_tokens[0]["quantity"] == 4

    @pytest.mark.asyncio
    async def test_transfer_full_amount(self, transfer_setup):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ef" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            await cardano_license.transfer_signature_token(
                transfer_setup["sender_label"],
                transfer_setup["to_address"],
                license_ref=transfer_setup["license_id"],
                quantity=10,
            )

        # Sender should have 0 (record marked transferred)
        balance = await cardano_license.get_signature_balance("xfer_sender")
        assert balance["total_tokens"] == 0


# ── Status Tests with Signature Tokens ───────────────────────────

class TestStatusWithSignatureTokens:
    @pytest.mark.asyncio
    async def test_status_includes_signature_token_count(self):
        status = await cardano_license.get_cardano_status()
        assert "signature_token_count" in status
        assert "signature_tokens_total_qty" in status
        assert status["signature_token_count"] == 0
        assert status["signature_tokens_total_qty"] == 0

    @pytest.mark.asyncio
    async def test_status_counts_signature_tokens(self):
        await cardano_license_core._store_signature_token_record(
            "aa" * 28, "SIG1_0", "addr1", 1, 10, "tx1"
        )
        await cardano_license_core._store_signature_token_record(
            "bb" * 28, "SIG2_0", "addr2", 2, 5, "tx2"
        )

        status = await cardano_license.get_cardano_status()
        assert status["signature_token_count"] == 2
        assert status["signature_tokens_total_qty"] == 15


# ── Validity Token Name Generation Tests ─────────────────────────

class TestValidityTokenNameGeneration:
    def test_basic_validity_token_name(self):
        assert cardano_license_core._generate_validity_token_name(1) == "VAL1_0"

    def test_validity_token_name_with_seq(self):
        assert cardano_license_core._generate_validity_token_name(42, 3) == "VAL42_3"

    def test_validity_token_name_truncation(self):
        result = cardano_license_core._generate_validity_token_name(999999999999999999999)
        assert len(result) <= 32
        assert result.startswith("VAL")


# ── Validity Token DB Record Tests ───────────────────────────────

class TestValidityTokenDBRecords:
    @pytest.mark.asyncio
    async def test_store_validity_token_record(self):
        token_id = await cardano_license_core._store_validity_token_record(
            policy_id="aa" * 28,
            token_name="VAL1_0",
            licensee_address="addr_test1qval",
            license_ref=1,
            valid_until="2027-01-01",
            mint_tx_hash="ff" * 32,
        )
        assert token_id > 0

    @pytest.mark.asyncio
    async def test_get_validity_token_by_id(self):
        token_id = await cardano_license_core._store_validity_token_record(
            policy_id="bb" * 28,
            token_name="VAL2_0",
            licensee_address="addr_test1qval2",
            license_ref=2,
            valid_until="2028-06-15",
            mint_tx_hash="ee" * 32,
        )

        token = await cardano_license.get_validity_token_by_id(token_id)
        assert token is not None
        assert token["token_name"] == "VAL2_0"
        assert token["valid_until"] == "2028-06-15"
        assert token["status"] == "active"

    @pytest.mark.asyncio
    async def test_get_validity_token_by_id_not_found(self):
        token = await cardano_license.get_validity_token_by_id(99999)
        assert token is None

    @pytest.mark.asyncio
    async def test_list_validity_tokens_all(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr2", 2, "2028-01-01", "tx2"
        )
        tokens = await cardano_license.list_validity_tokens()
        assert len(tokens) == 2

    @pytest.mark.asyncio
    async def test_list_validity_tokens_by_licensee(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr_specific", 1, "2027-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr_other", 2, "2028-01-01", "tx2"
        )
        tokens = await cardano_license.list_validity_tokens(
            licensee_address="addr_specific"
        )
        assert len(tokens) == 1
        assert tokens[0]["token_name"] == "VAL1_0"

    @pytest.mark.asyncio
    async def test_list_validity_tokens_by_license_ref(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr2", 2, "2028-01-01", "tx2"
        )
        tokens = await cardano_license.list_validity_tokens(license_ref=1)
        assert len(tokens) == 1
        assert tokens[0]["license_ref"] == 1

    @pytest.mark.asyncio
    async def test_list_validity_tokens_by_status(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        tokens = await cardano_license.list_validity_tokens(status="active")
        assert len(tokens) == 1

        expired = await cardano_license.list_validity_tokens(status="expired")
        assert len(expired) == 0

    @pytest.mark.asyncio
    async def test_get_next_validity_seq_empty(self):
        seq = await cardano_license_core._get_next_validity_seq(1)
        assert seq == 0

    @pytest.mark.asyncio
    async def test_get_next_validity_seq_increments(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        seq = await cardano_license_core._get_next_validity_seq(1)
        assert seq == 1

        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_1", "addr1", 1, "2028-01-01", "tx2"
        )
        seq = await cardano_license_core._get_next_validity_seq(1)
        assert seq == 2


# ── Check Validity Tests ─────────────────────────────────────────

class TestCheckValidity:
    @pytest.mark.asyncio
    async def test_check_validity_no_token(self):
        result = await cardano_license.check_validity("addr_test1qnotoken", 1)
        assert result["is_valid"] is False
        assert result["reason"] == "no_validity_token"
        assert result["token"] is None

    @pytest.mark.asyncio
    async def test_check_validity_active_token(self):
        addr = "addr_test1qvalid"
        # Store a token with future expiry
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", addr, 1, "2099-12-31", "tx1"
        )

        result = await cardano_license.check_validity(addr, 1)
        assert result["is_valid"] is True
        assert result["valid_until"] == "2099-12-31"
        assert result["token_name"] == "VAL1_0"
        assert "reason" not in result

    @pytest.mark.asyncio
    async def test_check_validity_expired_token(self):
        addr = "addr_test1qexpired"
        # Store a token with past expiry
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", addr, 2, "2020-01-01", "tx2"
        )

        result = await cardano_license.check_validity(addr, 2)
        assert result["is_valid"] is False
        assert result["reason"] == "expired"
        assert result["valid_until"] == "2020-01-01"

    @pytest.mark.asyncio
    async def test_check_validity_picks_latest(self):
        addr = "addr_test1qlatest"
        # Multiple tokens for same license - should pick the one with latest valid_until
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", addr, 1, "2025-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_1", addr, 1, "2099-06-15", "tx2"
        )

        result = await cardano_license.check_validity(addr, 1)
        assert result["is_valid"] is True
        assert result["valid_until"] == "2099-06-15"
        assert result["token_name"] == "VAL1_1"

    @pytest.mark.asyncio
    async def test_check_validity_ignores_expired_status(self):
        addr = "addr_test1qstatuscheck"
        # Token with future date but expired status should not be picked
        tid = await cardano_license_core._store_validity_token_record(
            "cc" * 28, "VAL3_0", addr, 3, "2099-12-31", "tx3"
        )
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_validity_tokens SET status = 'expired' WHERE id = ?",
                (tid,),
            )
            await db.commit()

        result = await cardano_license.check_validity(addr, 3)
        assert result["is_valid"] is False
        assert result["reason"] == "no_validity_token"

    @pytest.mark.asyncio
    async def test_check_validity_wrong_license(self):
        addr = "addr_test1qwronglicense"
        await cardano_license_core._store_validity_token_record(
            "dd" * 28, "VAL4_0", addr, 4, "2099-12-31", "tx4"
        )

        result = await cardano_license.check_validity(addr, 999)
        assert result["is_valid"] is False
        assert result["reason"] == "no_validity_token"

    @pytest.mark.asyncio
    async def test_check_validity_wrong_address(self):
        await cardano_license_core._store_validity_token_record(
            "ee" * 28, "VAL5_0", "addr_test1qright", 5, "2099-12-31", "tx5"
        )

        result = await cardano_license.check_validity("addr_test1qwrong", 5)
        assert result["is_valid"] is False
        assert result["reason"] == "no_validity_token"


# ── Revoke Validity Token Tests ──────────────────────────────────

class TestRevokeValidityToken:
    @pytest.mark.asyncio
    async def test_revoke_active_token(self):
        tid = await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2099-12-31", "tx1"
        )

        result = await cardano_license.revoke_validity_token(tid)
        assert result["status"] == "revoked"

        # Verify in DB
        token = await cardano_license.get_validity_token_by_id(tid)
        assert token["status"] == "revoked"

    @pytest.mark.asyncio
    async def test_revoke_not_found(self):
        with pytest.raises(ValueError, match="Validity token not found"):
            await cardano_license.revoke_validity_token(99999)

    @pytest.mark.asyncio
    async def test_revoke_already_expired(self):
        tid = await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr2", 2, "2020-01-01", "tx2"
        )
        # Manually set to expired
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_validity_tokens SET status = 'expired' WHERE id = ?",
                (tid,),
            )
            await db.commit()

        with pytest.raises(ValueError, match="must be 'active'"):
            await cardano_license.revoke_validity_token(tid)

    @pytest.mark.asyncio
    async def test_revoke_makes_validity_invalid(self):
        addr = "addr_test1qrevoke"
        tid = await cardano_license_core._store_validity_token_record(
            "cc" * 28, "VAL3_0", addr, 3, "2099-12-31", "tx3"
        )

        # Valid before revocation
        check = await cardano_license.check_validity(addr, 3)
        assert check["is_valid"] is True

        # Revoke
        await cardano_license.revoke_validity_token(tid)

        # Invalid after revocation
        check = await cardano_license.check_validity(addr, 3)
        assert check["is_valid"] is False
        assert check["reason"] == "no_validity_token"


# ── Expire Active Validity Tokens Tests ──────────────────────────

class TestExpireActiveValidityTokens:
    @pytest.mark.asyncio
    async def test_expire_single_active_token(self):
        tid = await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2099-01-01", "tx1"
        )

        prev_id = await cardano_license_core._expire_active_validity_tokens("addr1", 1)
        assert prev_id == tid

        token = await cardano_license.get_validity_token_by_id(tid)
        assert token["status"] == "expired"

    @pytest.mark.asyncio
    async def test_expire_no_active_tokens(self):
        prev_id = await cardano_license_core._expire_active_validity_tokens("addr_none", 99)
        assert prev_id is None

    @pytest.mark.asyncio
    async def test_expire_multiple_active_tokens(self):
        tid1 = await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        tid2 = await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_1", "addr1", 1, "2028-01-01", "tx2"
        )

        prev_id = await cardano_license_core._expire_active_validity_tokens("addr1", 1)
        # Should return the one with latest valid_until
        assert prev_id == tid2

        # Both should be expired
        t1 = await cardano_license.get_validity_token_by_id(tid1)
        t2 = await cardano_license.get_validity_token_by_id(tid2)
        assert t1["status"] == "expired"
        assert t2["status"] == "expired"


# ── Mint Validity Token Integration Tests (mocked chain) ─────────

class TestMintValidityToken:
    @pytest.fixture
    async def authority_wallet(self):
        return await cardano_license.generate_wallet("authority", "val_authority")

    @pytest.fixture
    async def licensee_with_license(self, authority_wallet):
        addr = _make_valid_testnet_address()
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "aa" * 28, label="val_licensee"
        )
        lic_id = await cardano_license_core._store_license_record(
            token_name="LICVALTEST",
            policy_id="bb" * 28,
            licensee_address=addr,
            authority_address=authority_wallet["base_address"],
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="cc" * 32,
            license_type="professional_engineer",
        )
        return {"address": addr, "license_id": lic_id}

    @pytest.mark.asyncio
    async def test_mint_validity_token_success(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ab" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_validity_token(
                "val_authority",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="2027-12-31",
            )

        assert result["status"] == "active"
        assert result["valid_until"] == "2027-12-31"
        assert result["token_name"].startswith("VAL")
        assert result["tx_hash"] == "ab" * 32
        assert result["license_ref"] == licensee_with_license["license_id"]
        assert result["token_id"] > 0

    @pytest.mark.asyncio
    async def test_mint_validity_token_stores_db_record(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "cd" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_validity_token(
                "val_authority",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="2028-06-30",
            )

        token = await cardano_license.get_validity_token_by_id(result["token_id"])
        assert token is not None
        assert token["valid_until"] == "2028-06-30"
        assert token["status"] == "active"
        assert token["mint_tx_hash"] == "cd" * 32

    @pytest.mark.asyncio
    async def test_mint_validity_token_empty_valid_until(
        self, authority_wallet, licensee_with_license
    ):
        with pytest.raises(ValueError, match="valid_until must be a non-empty"):
            await cardano_license.mint_validity_token(
                "val_authority",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="",
            )

    @pytest.mark.asyncio
    async def test_mint_validity_token_license_not_found(self, authority_wallet):
        with pytest.raises(ValueError, match="License not found"):
            await cardano_license.mint_validity_token(
                "val_authority",
                "addr_test1qany",
                license_ref=99999,
                valid_until="2027-01-01",
            )

    @pytest.mark.asyncio
    async def test_mint_validity_token_wallet_not_found(
        self, licensee_with_license
    ):
        with pytest.raises(FileNotFoundError):
            await cardano_license.mint_validity_token(
                "nonexistent_wallet",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="2027-01-01",
            )

    @pytest.mark.asyncio
    async def test_mint_validity_token_policy_id_format(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ef" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.mint_validity_token(
                "val_authority",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="2027-12-31",
            )

        # Policy ID should be 56 hex chars (28 bytes)
        assert len(result["policy_id"]) == 56
        int(result["policy_id"], 16)  # Valid hex

    @pytest.mark.asyncio
    async def test_mint_validity_token_chain_failure(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "11" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()
        mock_ctx.submit_tx.side_effect = Exception("Transaction rejected")

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            with pytest.raises(Exception, match="Transaction rejected"):
                await cardano_license.mint_validity_token(
                    "val_authority",
                    licensee_with_license["address"],
                    license_ref=licensee_with_license["license_id"],
                    valid_until="2027-12-31",
                )

    @pytest.mark.asyncio
    async def test_mint_validity_token_builds_multiasset_qty_1(
        self, authority_wallet, licensee_with_license
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "22" * 32

        captured = {}

        class FakeBuilder:
            def __init__(self, ctx):
                self._mint = None
                self.auxiliary_data = None

            def add_input_address(self, addr):
                return self

            def add_minting_script(self, script):
                captured["script"] = script
                return self

            def add_output(self, output):
                return self

            @property
            def mint(self):
                return self._mint

            @mint.setter
            def mint(self, value):
                self._mint = value
                captured["mint"] = value

            def build_and_sign(self, signing_keys, change_address):
                return mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", FakeBuilder):
            await cardano_license.mint_validity_token(
                "val_authority",
                licensee_with_license["address"],
                license_ref=licensee_with_license["license_id"],
                valid_until="2027-12-31",
            )

        # Validity token is quantity 1 (non-fungible per issuance)
        mint_ma = captured["mint"]
        assert isinstance(mint_ma, MultiAsset)
        total_minted = 0
        for policy_id, assets in mint_ma.items():
            for asset_name, qty in assets.items():
                total_minted += qty
        assert total_minted == 1

    @pytest.mark.asyncio
    async def test_mint_validity_token_sequential_seq(
        self, authority_wallet, licensee_with_license
    ):
        """Multiple mints for same license get incrementing sequence numbers."""
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "33" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        lic_id = licensee_with_license["license_id"]
        addr = licensee_with_license["address"]

        results = []
        for i in range(3):
            with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
                 patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
                result = await cardano_license.mint_validity_token(
                    "val_authority", addr,
                    license_ref=lic_id,
                    valid_until=f"202{7+i}-12-31",
                )
            results.append(result)

        # Token names should have incrementing sequence
        assert results[0]["token_name"] == f"VAL{lic_id}_0"
        assert results[1]["token_name"] == f"VAL{lic_id}_1"
        assert results[2]["token_name"] == f"VAL{lic_id}_2"


# ── Renew Validity Tests (mocked chain) ──────────────────────────

class TestRenewValidity:
    @pytest.fixture
    async def authority_wallet(self):
        return await cardano_license.generate_wallet("authority", "renew_authority")

    @pytest.fixture
    async def licensee_with_license_and_validity(self, authority_wallet):
        addr = _make_valid_testnet_address()
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "aa" * 28, label="renew_licensee"
        )
        lic_id = await cardano_license_core._store_license_record(
            token_name="LICRENEW",
            policy_id="bb" * 28,
            licensee_address=addr,
            authority_address=authority_wallet["base_address"],
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="cc" * 32,
            license_type="professional_engineer",
        )
        # Mint an existing validity token
        old_tid = await cardano_license_core._store_validity_token_record(
            "dd" * 28, "VAL_OLD", addr, lic_id, "2026-12-31", "tx_old"
        )
        return {
            "address": addr,
            "license_id": lic_id,
            "old_validity_token_id": old_tid,
        }

    @pytest.mark.asyncio
    async def test_renew_validity_success(
        self, authority_wallet, licensee_with_license_and_validity
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ab" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        setup = licensee_with_license_and_validity

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.renew_validity(
                "renew_authority",
                setup["address"],
                license_ref=setup["license_id"],
                new_expiry="2027-12-31",
            )

        assert result["status"] == "active"
        assert result["valid_until"] == "2027-12-31"
        assert result["renewal"] is True
        assert result["previous_token_id"] == setup["old_validity_token_id"]
        assert result["token_id"] > 0

    @pytest.mark.asyncio
    async def test_renew_expires_old_token(
        self, authority_wallet, licensee_with_license_and_validity
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "cd" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        setup = licensee_with_license_and_validity

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            await cardano_license.renew_validity(
                "renew_authority",
                setup["address"],
                license_ref=setup["license_id"],
                new_expiry="2028-06-30",
            )

        # Old token should be expired
        old_token = await cardano_license.get_validity_token_by_id(
            setup["old_validity_token_id"]
        )
        assert old_token["status"] == "expired"

    @pytest.mark.asyncio
    async def test_renew_new_token_is_active(
        self, authority_wallet, licensee_with_license_and_validity
    ):
        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "ef" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        setup = licensee_with_license_and_validity

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.renew_validity(
                "renew_authority",
                setup["address"],
                license_ref=setup["license_id"],
                new_expiry="2029-01-01",
            )

        # Check validity should return the new token
        check = await cardano_license.check_validity(
            setup["address"], setup["license_id"]
        )
        assert check["is_valid"] is True
        assert check["valid_until"] == "2029-01-01"
        assert check["token_id"] == result["token_id"]

    @pytest.mark.asyncio
    async def test_renew_empty_expiry(
        self, authority_wallet, licensee_with_license_and_validity
    ):
        setup = licensee_with_license_and_validity
        with pytest.raises(ValueError, match="new_expiry must be a non-empty"):
            await cardano_license.renew_validity(
                "renew_authority",
                setup["address"],
                license_ref=setup["license_id"],
                new_expiry="",
            )

    @pytest.mark.asyncio
    async def test_renew_without_prior_token(self, authority_wallet):
        """Renewal works even if there's no prior validity token (first issuance)."""
        addr = _make_valid_testnet_address()
        await cardano_license.store_wallet_metadata(
            "licensee", addr, "ff" * 28, label="renew_first"
        )
        lic_id = await cardano_license_core._store_license_record(
            token_name="LICFIRST",
            policy_id="ee" * 28,
            licensee_address=addr,
            authority_address=authority_wallet["base_address"],
            metadata_json=SAMPLE_LICENSE_METADATA,
            mint_tx_hash="dd" * 32,
        )

        mock_tx = MagicMock()
        mock_tx.id.to_primitive.return_value.hex.return_value = "11" * 32

        mock_builder = MagicMock()
        mock_builder.add_input_address.return_value = mock_builder
        mock_builder.add_minting_script.return_value = mock_builder
        mock_builder.add_output.return_value = mock_builder
        mock_builder.build_and_sign.return_value = mock_tx

        mock_ctx = MagicMock()

        with patch.object(cardano_license_core, "get_chain_context", return_value=mock_ctx), \
             patch.object(cardano_license_core, "TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.renew_validity(
                "renew_authority",
                addr,
                license_ref=lic_id,
                new_expiry="2028-01-01",
            )

        assert result["renewal"] is True
        assert result["previous_token_id"] is None
        assert result["status"] == "active"


# ── Status Tests with Validity Tokens ────────────────────────────

class TestStatusWithValidityTokens:
    @pytest.mark.asyncio
    async def test_status_includes_validity_token_count(self):
        status = await cardano_license.get_cardano_status()
        assert "validity_token_count" in status
        assert "validity_tokens_by_status" in status
        assert status["validity_token_count"] == 0

    @pytest.mark.asyncio
    async def test_status_counts_validity_tokens(self):
        await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr2", 2, "2028-01-01", "tx2"
        )

        status = await cardano_license.get_cardano_status()
        assert status["validity_token_count"] == 2
        assert status["validity_tokens_by_status"]["active"] == 2

    @pytest.mark.asyncio
    async def test_status_validity_by_status(self):
        tid = await cardano_license_core._store_validity_token_record(
            "aa" * 28, "VAL1_0", "addr1", 1, "2027-01-01", "tx1"
        )
        await cardano_license_core._store_validity_token_record(
            "bb" * 28, "VAL2_0", "addr2", 2, "2028-01-01", "tx2"
        )
        # Expire one
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_validity_tokens SET status = 'expired' WHERE id = ?",
                (tid,),
            )
            await db.commit()

        status = await cardano_license.get_cardano_status()
        assert status["validity_token_count"] == 2
        assert status["validity_tokens_by_status"]["active"] == 1
        assert status["validity_tokens_by_status"]["expired"] == 1


# ── Document Signing Workflow Tests ──────────────────────────────

class TestStoreSignatureRecord:
    """Tests for _store_signature_record (DB layer)."""

    @pytest.mark.asyncio
    async def test_store_basic(self):
        sig_id = await cardano_license_core._store_signature_record(
            document_hash="abcd1234" * 8,
            signer_address="addr_signer1",
            license_ref=1,
            signature_tx_hash="tx_sign_001",
            signature_datum={"doc": "test"},
        )
        assert sig_id is not None
        assert sig_id > 0

    @pytest.mark.asyncio
    async def test_store_and_retrieve(self):
        sig_id = await cardano_license_core._store_signature_record(
            document_hash="abcd1234" * 8,
            signer_address="addr_signer1",
            license_ref=1,
            signature_tx_hash="tx_sign_002",
            signature_datum={"doc": "hash_test"},
        )
        sig = await cardano_license.get_signature_by_id(sig_id)
        assert sig is not None
        assert sig["document_hash"] == "abcd1234" * 8
        assert sig["signer_address"] == "addr_signer1"
        assert sig["license_ref"] == 1
        assert sig["signature_tx_hash"] == "tx_sign_002"

    @pytest.mark.asyncio
    async def test_store_multiple(self):
        for i in range(3):
            await cardano_license_core._store_signature_record(
                document_hash="samehash" * 8,
                signer_address=f"addr_signer{i}",
                license_ref=1,
                signature_tx_hash=f"tx_multi_{i}",
                signature_datum={"index": i},
            )
        sigs = await cardano_license.list_signatures(document_hash="samehash" * 8)
        assert len(sigs) == 3


class TestListSignatures:
    """Tests for list_signatures with various filters."""

    @pytest.mark.asyncio
    async def test_list_all(self):
        await cardano_license_core._store_signature_record("hash_a" * 11, "addr1", 1, "tx1", {})
        await cardano_license_core._store_signature_record("hash_b" * 11, "addr2", 2, "tx2", {})
        sigs = await cardano_license.list_signatures()
        assert len(sigs) == 2

    @pytest.mark.asyncio
    async def test_list_by_document(self):
        await cardano_license_core._store_signature_record("hash_c" * 11, "addr1", 1, "tx1", {})
        await cardano_license_core._store_signature_record("hash_d" * 11, "addr2", 2, "tx2", {})
        sigs = await cardano_license.list_signatures(document_hash="hash_c" * 11)
        assert len(sigs) == 1
        assert sigs[0]["document_hash"] == "hash_c" * 11

    @pytest.mark.asyncio
    async def test_list_by_signer(self):
        await cardano_license_core._store_signature_record("hash_e" * 11, "addr_x", 1, "tx1", {})
        await cardano_license_core._store_signature_record("hash_f" * 11, "addr_y", 2, "tx2", {})
        sigs = await cardano_license.list_signatures(signer_address="addr_x")
        assert len(sigs) == 1
        assert sigs[0]["signer_address"] == "addr_x"

    @pytest.mark.asyncio
    async def test_list_by_license_ref(self):
        await cardano_license_core._store_signature_record("hash_g" * 11, "addr1", 5, "tx1", {})
        await cardano_license_core._store_signature_record("hash_h" * 11, "addr2", 10, "tx2", {})
        sigs = await cardano_license.list_signatures(license_ref=5)
        assert len(sigs) == 1
        assert sigs[0]["license_ref"] == 5

    @pytest.mark.asyncio
    async def test_list_empty(self):
        sigs = await cardano_license.list_signatures(document_hash="nonexistent")
        assert sigs == []


class TestGetSignatureById:
    """Tests for get_signature_by_id."""

    @pytest.mark.asyncio
    async def test_found(self):
        sid = await cardano_license_core._store_signature_record(
            "hash_i" * 11, "addr1", 1, "tx_found", {"k": "v"}
        )
        sig = await cardano_license.get_signature_by_id(sid)
        assert sig is not None
        assert sig["signature_tx_hash"] == "tx_found"

    @pytest.mark.asyncio
    async def test_not_found(self):
        sig = await cardano_license.get_signature_by_id(99999)
        assert sig is None


class TestConsumeSignatureToken:
    """Tests for _consume_signature_token (internal DB helper)."""

    @pytest.mark.asyncio
    async def test_consume_one_of_many(self):
        """Consuming 1 from a record with quantity > 1 should decrement."""
        token_id = await cardano_license_core._store_signature_token_record(
            policy_id="aa" * 28,
            token_name="SIG1_0",
            licensee_address="addr_consume",
            license_ref=1,
            quantity=5,
            mint_tx_hash="tx_mint_consume",
        )
        await cardano_license_core._consume_signature_token(token_id, "tx_use_1")

        async with aiosqlite.connect(TEST_DB) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM blockchain_signature_tokens WHERE id = ?", (token_id,)
            )
            row = dict(await cursor.fetchone())
        assert row["quantity"] == 4
        assert row["status"] == "minted"

    @pytest.mark.asyncio
    async def test_consume_last(self):
        """Consuming the last token should mark as transferred."""
        token_id = await cardano_license_core._store_signature_token_record(
            policy_id="bb" * 28,
            token_name="SIG2_0",
            licensee_address="addr_consume2",
            license_ref=2,
            quantity=1,
            mint_tx_hash="tx_mint_last",
        )
        await cardano_license_core._consume_signature_token(token_id, "tx_use_last")

        async with aiosqlite.connect(TEST_DB) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM blockchain_signature_tokens WHERE id = ?", (token_id,)
            )
            row = dict(await cursor.fetchone())
        assert row["quantity"] == 0
        assert row["status"] == "transferred"
        assert row["burn_tx_hash"] == "tx_use_last"

    @pytest.mark.asyncio
    async def test_consume_nonexistent(self):
        """Consuming from nonexistent record should not error."""
        await cardano_license_core._consume_signature_token(99999, "tx_none")


class TestCreateWorkProduct:
    """Tests for create_work_product."""

    @pytest.mark.asyncio
    async def test_create_basic(self):
        result = await cardano_license.create_work_product(
            title="Test Document",
            document_hash="abcdef1234567890" * 4,
            required_signers=["addr_signer_a", "addr_signer_b"],
            wp_address="addr_contract_1",
        )
        assert result["work_product_id"] > 0
        assert result["title"] == "Test Document"
        assert result["status"] == "pending_signatures"
        assert len(result["required_signers"]) == 2

    @pytest.mark.asyncio
    async def test_create_without_wp_address_generates_wallet(self):
        result = await cardano_license.create_work_product(
            title="No Address WP",
            document_hash="1234567890abcdef" * 4,
            required_signers=["addr_a"],
        )
        # Now auto-generates a wallet when no wp_address provided
        assert result["wp_address"] is not None
        assert result["wp_address"].startswith("addr_test1")
        assert result["wallet_generated"] is True
        assert result["work_product_id"] > 0

    @pytest.mark.asyncio
    async def test_create_invalid_hash(self):
        with pytest.raises(ValueError, match="valid hex hash"):
            await cardano_license.create_work_product(
                title="Bad Hash",
                document_hash="short",
                required_signers=["addr_a"],
            )

    @pytest.mark.asyncio
    async def test_create_empty_signers(self):
        with pytest.raises(ValueError, match="at least one"):
            await cardano_license.create_work_product(
                title="No Signers",
                document_hash="abcdef1234567890" * 4,
                required_signers=[],
            )


class TestGetWorkProductStatus:
    """Tests for get_work_product_status."""

    @pytest.mark.asyncio
    async def test_get_basic(self):
        wp = await cardano_license.create_work_product(
            title="Status Test",
            document_hash="fedcba0987654321" * 4,
            required_signers=["addr_s1", "addr_s2"],
        )
        status = await cardano_license.get_work_product_status(wp["work_product_id"])
        assert status is not None
        assert status["title"] == "Status Test"
        assert status["status"] == "pending_signatures"
        assert status["signature_progress"] == "0/2"
        assert len(status["missing_signers"]) == 2

    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        status = await cardano_license.get_work_product_status(99999)
        assert status is None


class TestUpdateWorkProductSignatures:
    """Tests for _update_work_product_signatures."""

    @pytest.mark.asyncio
    async def test_partial_signature(self):
        doc_hash = "partialsig12345678" * 4
        wp = await cardano_license.create_work_product(
            title="Partial Sig Test",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s1", 1
        )

        status = await cardano_license.get_work_product_status(wp["work_product_id"])
        assert status["status"] == "partially_signed"
        assert status["signature_progress"] == "1/2"
        assert "addr_s2" in status["missing_signers"]

    @pytest.mark.asyncio
    async def test_full_signature(self):
        doc_hash = "fullsig123456789a" * 4
        wp = await cardano_license.create_work_product(
            title="Full Sig Test",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s1", 1
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s2", 2
        )

        status = await cardano_license.get_work_product_status(wp["work_product_id"])
        assert status["status"] == "fully_signed"
        assert status["signature_progress"] == "2/2"
        assert status["missing_signers"] == []

    @pytest.mark.asyncio
    async def test_no_matching_work_product(self):
        """Should not error if no work product matches the doc hash."""
        await cardano_license_core._update_work_product_signatures(
            "nonexistent_hash" * 4, "addr_x", 99
        )


class TestVerifySignature:
    """Tests for verify_signature."""

    @pytest.mark.asyncio
    async def test_verify_no_signatures(self):
        result = await cardano_license.verify_signature(
            contract_address="addr_contract",
            document_hash="nosigs1234567890" * 4,
        )
        assert result["is_verified"] is False
        assert result["signature_count"] == 0

    @pytest.mark.asyncio
    async def test_verify_with_signature_no_wp(self):
        """Verify passes when there are signatures and no work product."""
        doc_hash = "hassig12345678ab" * 4
        await cardano_license_core._store_signature_record(
            document_hash=doc_hash,
            signer_address="addr_verified",
            license_ref=1,
            signature_tx_hash="tx_verified_001",
            signature_datum={"test": True},
        )
        # Store a valid validity token for the signer
        await cardano_license_core._store_validity_token_record(
            policy_id="cc" * 28,
            token_name="VAL1_0",
            licensee_address="addr_verified",
            license_ref=1,
            valid_until="2099-12-31",
            mint_tx_hash="tx_val_check",
        )

        result = await cardano_license.verify_signature(
            contract_address="addr_contract",
            document_hash=doc_hash,
        )
        assert result["is_verified"] is True
        assert result["signature_count"] == 1
        assert result["signatures"][0]["signer_address"] == "addr_verified"

    @pytest.mark.asyncio
    async def test_verify_with_wp_missing_signers(self):
        """Verify fails when work product has missing signers."""
        doc_hash = "wpmissing1234567" * 4
        await cardano_license.create_work_product(
            title="Missing Signers",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
        )
        # Only one signer signed
        await cardano_license_core._store_signature_record(
            document_hash=doc_hash,
            signer_address="addr_s1",
            license_ref=1,
            signature_tx_hash="tx_partial_wp",
            signature_datum={},
        )
        # Add validity token for signer
        await cardano_license_core._store_validity_token_record(
            policy_id="dd" * 28,
            token_name="VALWP_0",
            licensee_address="addr_s1",
            license_ref=1,
            valid_until="2099-12-31",
            mint_tx_hash="tx_val_wp1",
        )

        result = await cardano_license.verify_signature(
            contract_address="addr_contract",
            document_hash=doc_hash,
        )
        assert result["is_verified"] is False
        assert result["signature_count"] == 1
        assert "work_product" in result
        assert "addr_s2" in result["work_product"]["missing_signers"]

    @pytest.mark.asyncio
    async def test_verify_with_wp_all_signed(self):
        """Verify passes when all required signers have signed."""
        doc_hash = "wpfull1234567890" * 4
        await cardano_license.create_work_product(
            title="All Signed",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
        )
        for addr in ["addr_s1", "addr_s2"]:
            await cardano_license_core._store_signature_record(
                document_hash=doc_hash,
                signer_address=addr,
                license_ref=1,
                signature_tx_hash=f"tx_full_{addr}",
                signature_datum={},
            )
            await cardano_license_core._store_validity_token_record(
                policy_id="ee" * 28,
                token_name=f"VAL_{addr}",
                licensee_address=addr,
                license_ref=1,
                valid_until="2099-12-31",
                mint_tx_hash=f"tx_val_{addr}",
            )

        result = await cardano_license.verify_signature(
            contract_address="addr_contract",
            document_hash=doc_hash,
        )
        assert result["is_verified"] is True
        assert result["signature_count"] == 2
        assert result["work_product"]["all_required_signed"] is True
        assert result["work_product"]["missing_signers"] == []

    @pytest.mark.asyncio
    async def test_verify_empty_hash_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            await cardano_license.verify_signature("addr", "")

    @pytest.mark.asyncio
    async def test_verify_marks_verified_at(self):
        """Verification should stamp verified_at on signature records."""
        doc_hash = "verifystamp12345" * 4
        sig_id = await cardano_license_core._store_signature_record(
            document_hash=doc_hash,
            signer_address="addr_stamp",
            license_ref=1,
            signature_tx_hash="tx_stamp_001",
            signature_datum={},
        )
        await cardano_license_core._store_validity_token_record(
            policy_id="ff" * 28,
            token_name="VALSTAMP_0",
            licensee_address="addr_stamp",
            license_ref=1,
            valid_until="2099-12-31",
            mint_tx_hash="tx_val_stamp",
        )

        result = await cardano_license.verify_signature("addr_contract", doc_hash)
        assert result["is_verified"] is True

        # Check verified_at was set
        sig = await cardano_license.get_signature_by_id(sig_id)
        assert sig["verified_at"] is not None


class TestSignDocument:
    """Tests for sign_document (full workflow with chain mock)."""

    @pytest.mark.asyncio
    async def test_sign_invalid_hash(self):
        with pytest.raises(ValueError, match="valid hex hash"):
            await cardano_license.sign_document(
                signer_wallet_label="test_signer",
                document_hash="short",
                contract_address="addr_contract",
                license_ref=1,
            )

    @pytest.mark.asyncio
    async def test_sign_empty_contract(self):
        with pytest.raises(ValueError, match="non-empty"):
            await cardano_license.sign_document(
                signer_wallet_label="test_signer",
                document_hash="abcd1234" * 8,
                contract_address="",
                license_ref=1,
            )

    @pytest.mark.asyncio
    async def test_sign_wallet_not_found(self):
        with pytest.raises(ValueError, match="Signer wallet not found"):
            await cardano_license.sign_document(
                signer_wallet_label="nonexistent_wallet",
                document_hash="abcd1234" * 8,
                contract_address="addr_contract",
                license_ref=1,
            )

    @pytest.mark.asyncio
    async def test_sign_license_not_found(self):
        """Should fail if license_ref doesn't exist."""
        # Create a wallet first
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                """INSERT INTO blockchain_wallets
                   (wallet_type, address, public_key_hash, network, label)
                   VALUES ('signer', 'addr_sign_lic', 'pkhash1', 'testnet', 'sign_lic_test')"""
            )
            await db.commit()

        with pytest.raises(ValueError, match="License not found"):
            await cardano_license.sign_document(
                signer_wallet_label="sign_lic_test",
                document_hash="abcd1234" * 8,
                contract_address="addr_contract",
                license_ref=9999,
            )

    @pytest.mark.asyncio
    async def test_sign_no_validity_token(self):
        """Should fail if signer lacks validity token."""
        # Create wallet and license
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                """INSERT INTO blockchain_wallets
                   (wallet_type, address, public_key_hash, network, label)
                   VALUES ('signer', 'addr_sign_noval', 'pkhash2', 'testnet', 'sign_noval')"""
            )
            await db.execute(
                """INSERT INTO blockchain_licenses
                   (token_name, policy_id, licensee_address, authority_address,
                    status, license_type)
                   VALUES ('LIC001', 'aabb' , 'addr_sign_noval', 'addr_auth',
                           'active', 'professional')"""
            )
            await db.commit()

        # Get the license id
        lic = (await cardano_license.list_licenses())[0]

        with pytest.raises(ValueError, match="valid validity token"):
            await cardano_license.sign_document(
                signer_wallet_label="sign_noval",
                document_hash="abcd1234" * 8,
                contract_address="addr_contract",
                license_ref=lic["id"],
            )

    @pytest.mark.asyncio
    async def test_sign_no_signature_tokens(self):
        """Should fail if signer lacks signature tokens."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                """INSERT INTO blockchain_wallets
                   (wallet_type, address, public_key_hash, network, label)
                   VALUES ('signer', 'addr_sign_nosig', 'pkhash3', 'testnet', 'sign_nosig')"""
            )
            await db.execute(
                """INSERT INTO blockchain_licenses
                   (token_name, policy_id, licensee_address, authority_address,
                    status, license_type)
                   VALUES ('LIC002', 'ccdd', 'addr_sign_nosig', 'addr_auth2',
                           'active', 'professional')"""
            )
            await db.commit()

        lic = (await cardano_license.list_licenses())[0]

        # Add validity token but no signature tokens
        await cardano_license_core._store_validity_token_record(
            policy_id="aa" * 28,
            token_name="VALSIG_0",
            licensee_address="addr_sign_nosig",
            license_ref=lic["id"],
            valid_until="2099-12-31",
            mint_tx_hash="tx_val_nosig",
        )

        with pytest.raises(ValueError, match="no signature tokens"):
            await cardano_license.sign_document(
                signer_wallet_label="sign_nosig",
                document_hash="abcd1234" * 8,
                contract_address="addr_contract",
                license_ref=lic["id"],
            )

    @pytest.mark.asyncio
    async def test_sign_full_workflow(self):
        """Full signing workflow with mocked chain context."""
        from pycardano import HDWallet

        # Generate a real wallet for signing key derivation
        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        signer_address = keys["base_address"]
        signer_label = "sign_full_test"

        # Save keys to disk
        cardano_license.save_wallet_keys(
            signer_label, mnemonic, keys["payment_sk"], keys["stake_sk"]
        )

        # Store wallet in DB
        await cardano_license.store_wallet_metadata(
            wallet_type="signer",
            address=signer_address,
            public_key_hash=keys["payment_key_hash"],
            label=signer_label,
        )

        # Create a license
        lic_id = await cardano_license_core._store_license_record(
            token_name="LICFULL",
            policy_id="ff" * 28,
            licensee_address=signer_address,
            authority_address="addr_authority_full",
            metadata_json={"test": True},
            mint_tx_hash="tx_mint_lic_full",
            license_type="professional",
        )

        # Mint signature tokens
        await cardano_license_core._store_signature_token_record(
            policy_id="ff" * 28,
            token_name="SIG_FULL_0",
            licensee_address=signer_address,
            license_ref=lic_id,
            quantity=5,
            mint_tx_hash="tx_mint_sig_full",
        )

        # Mint validity token
        await cardano_license_core._store_validity_token_record(
            policy_id="ff" * 28,
            token_name="VAL_FULL_0",
            licensee_address=signer_address,
            license_ref=lic_id,
            valid_until="2099-12-31",
            mint_tx_hash="tx_mint_val_full",
        )

        # Generate a real contract address for valid bech32
        contract_mnemonic = HDWallet.generate_mnemonic()
        contract_keys = cardano_license.derive_keys_from_mnemonic(contract_mnemonic)
        contract_addr = contract_keys["base_address"]

        doc_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # Mock chain context: submit_tx, utxos, build_and_sign
        mock_context = MagicMock()
        mock_context.utxos.return_value = []

        mock_signed_tx = MagicMock()
        mock_signed_tx.id.to_primitive.return_value.hex.return_value = "tx_doc_sign_001"

        mock_builder = MagicMock()
        mock_builder.build_and_sign.return_value = mock_signed_tx

        with patch("cardano_license.core.get_chain_context", return_value=mock_context), \
             patch("cardano_license.core.TransactionBuilder", return_value=mock_builder):

            result = await cardano_license.sign_document(
                signer_wallet_label=signer_label,
                document_hash=doc_hash,
                contract_address=contract_addr,
                license_ref=lic_id,
            )

        assert result["status"] == "signed"
        assert result["tx_hash"] == "tx_doc_sign_001"
        assert result["document_hash"] == doc_hash
        assert result["signer_address"] == signer_address
        assert result["signature_id"] > 0
        assert result["sig_token_used"] == "SIG_FULL_0"
        assert result["val_token_used"] == "VAL_FULL_0"

        # Verify signature was recorded in DB
        sig = await cardano_license.get_signature_by_id(result["signature_id"])
        assert sig is not None
        assert sig["document_hash"] == doc_hash
        assert sig["signature_tx_hash"] == "tx_doc_sign_001"

        # Verify signature token was consumed
        async with aiosqlite.connect(TEST_DB) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """SELECT * FROM blockchain_signature_tokens
                   WHERE licensee_address = ? AND license_ref = ?""",
                (signer_address, lic_id),
            )
            token = dict(await cursor.fetchone())
        assert token["quantity"] == 4  # Was 5, consumed 1

    @pytest.mark.asyncio
    async def test_sign_updates_work_product(self):
        """Signing should update work product status."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)
        signer_address = keys["base_address"]
        signer_label = "sign_wp_test"

        cardano_license.save_wallet_keys(
            signer_label, mnemonic, keys["payment_sk"], keys["stake_sk"]
        )
        await cardano_license.store_wallet_metadata(
            wallet_type="signer",
            address=signer_address,
            public_key_hash=keys["payment_key_hash"],
            label=signer_label,
        )

        lic_id = await cardano_license_core._store_license_record(
            token_name="LICWP", policy_id="ee" * 28,
            licensee_address=signer_address,
            authority_address="addr_auth_wp",
            metadata_json={}, mint_tx_hash="tx_lic_wp",
        )
        await cardano_license_core._store_signature_token_record(
            "ee" * 28, "SIG_WP_0", signer_address, lic_id, 3, "tx_sig_wp",
        )
        await cardano_license_core._store_validity_token_record(
            "ee" * 28, "VAL_WP_0", signer_address, lic_id,
            "2099-12-31", "tx_val_wp",
        )

        doc_hash = "wp_doc_hash_1234" * 4

        # Generate a valid contract address
        contract_mnemonic = HDWallet.generate_mnemonic()
        contract_keys = cardano_license.derive_keys_from_mnemonic(contract_mnemonic)
        contract_addr = contract_keys["base_address"]

        wp = await cardano_license.create_work_product(
            title="WP Signing Test",
            document_hash=doc_hash,
            required_signers=[signer_address],
        )

        mock_context = MagicMock()
        mock_signed_tx = MagicMock()
        mock_signed_tx.id.to_primitive.return_value.hex.return_value = "tx_wp_sign"
        mock_builder = MagicMock()
        mock_builder.build_and_sign.return_value = mock_signed_tx

        with patch("cardano_license.core.get_chain_context", return_value=mock_context), \
             patch("cardano_license.core.TransactionBuilder", return_value=mock_builder):
            result = await cardano_license.sign_document(
                signer_wallet_label=signer_label,
                document_hash=doc_hash,
                contract_address=contract_addr,
                license_ref=lic_id,
            )

        assert result["status"] == "signed"

        # Work product should now be fully signed
        wp_status = await cardano_license.get_work_product_status(wp["work_product_id"])
        assert wp_status["status"] == "fully_signed"
        assert wp_status["signature_progress"] == "1/1"


class TestSignDocumentMetadata:
    """Tests for signing metadata label constant."""

    def test_metadata_label(self):
        assert cardano_license.DOC_SIGN_METADATA_LABEL == 367


class TestStatusIncludesSignatures:
    """Tests for get_cardano_status including signature count."""

    @pytest.mark.asyncio
    async def test_status_signature_count(self):
        await cardano_license_core._store_signature_record(
            "hash_stat1234567" * 4, "addr1", 1, "tx1", {}
        )
        await cardano_license_core._store_signature_record(
            "hash_stat2345678" * 4, "addr2", 2, "tx2", {}
        )

        status = await cardano_license.get_cardano_status()
        assert status["document_signature_count"] == 2

    @pytest.mark.asyncio
    async def test_status_zero_signatures(self):
        status = await cardano_license.get_cardano_status()
        assert status["document_signature_count"] == 0


# ── Task #368: Work Product Wallet Management Tests ──────────────


class TestCreateWorkProductAutoWallet:
    """Tests for create_work_product with auto-wallet generation (#368)."""

    @pytest.mark.asyncio
    async def test_auto_generates_wallet(self):
        """create_work_product without wp_address generates a wallet."""
        result = await cardano_license.create_work_product(
            title="Auto Wallet Doc",
            document_hash="abcdef1234567890" * 4,
            required_signers=["addr_signer_a", "addr_signer_b"],
        )
        assert result["work_product_id"] > 0
        assert result["wp_address"] is not None
        assert result["wp_address"].startswith("addr_test1")
        assert result["wallet_generated"] is True
        assert result["status"] == "pending_signatures"

    @pytest.mark.asyncio
    async def test_auto_wallet_stored_in_db(self):
        """Auto-generated wallet should be stored in blockchain_wallets."""
        result = await cardano_license.create_work_product(
            title="WalletDB Test",
            document_hash="dbtest12345678ab" * 4,
            required_signers=["addr_s1"],
        )
        # Verify wallet exists in DB
        wallet = await cardano_license.get_wallet_by_address(result["wp_address"])
        assert wallet is not None
        assert wallet["wallet_type"] == "signer"

    @pytest.mark.asyncio
    async def test_explicit_address_no_wallet_gen(self):
        """Providing wp_address skips wallet generation."""
        result = await cardano_license.create_work_product(
            title="Explicit Address",
            document_hash="explicit12345678" * 4,
            required_signers=["addr_s1"],
            wp_address="addr_contract_explicit",
        )
        assert result["wp_address"] == "addr_contract_explicit"
        assert result["wallet_generated"] is False

    @pytest.mark.asyncio
    async def test_create_stores_required_signers(self):
        result = await cardano_license.create_work_product(
            title="Signers Test",
            document_hash="signers123456789" * 4,
            required_signers=["addr_a", "addr_b", "addr_c"],
        )
        assert len(result["required_signers"]) == 3
        assert "addr_a" in result["required_signers"]
        assert "addr_c" in result["required_signers"]

    @pytest.mark.asyncio
    async def test_create_invalid_hash_short(self):
        with pytest.raises(ValueError, match="valid hex hash"):
            await cardano_license.create_work_product(
                title="Bad", document_hash="short", required_signers=["a"],
            )

    @pytest.mark.asyncio
    async def test_create_invalid_hash_empty(self):
        with pytest.raises(ValueError, match="valid hex hash"):
            await cardano_license.create_work_product(
                title="Bad", document_hash="", required_signers=["a"],
            )

    @pytest.mark.asyncio
    async def test_create_empty_signers(self):
        with pytest.raises(ValueError, match="at least one"):
            await cardano_license.create_work_product(
                title="No Signers",
                document_hash="abcdef1234567890" * 4,
                required_signers=[],
            )

    @pytest.mark.asyncio
    async def test_create_empty_title(self):
        with pytest.raises(ValueError, match="non-empty"):
            await cardano_license.create_work_product(
                title="",
                document_hash="abcdef1234567890" * 4,
                required_signers=["addr_a"],
            )

    @pytest.mark.asyncio
    async def test_create_whitespace_title(self):
        with pytest.raises(ValueError, match="non-empty"):
            await cardano_license.create_work_product(
                title="   ",
                document_hash="abcdef1234567890" * 4,
                required_signers=["addr_a"],
            )

    @pytest.mark.asyncio
    async def test_unique_wallets_per_work_product(self):
        """Each work product gets its own wallet."""
        wp1 = await cardano_license.create_work_product(
            title="WP One",
            document_hash="unique1234567890" * 4,
            required_signers=["addr_s1"],
        )
        wp2 = await cardano_license.create_work_product(
            title="WP Two",
            document_hash="unique2345678901" * 4,
            required_signers=["addr_s2"],
        )
        assert wp1["wp_address"] != wp2["wp_address"]


class TestGetWorkProductStatusByAddress:
    """Tests for get_work_product_status with address lookup (#368)."""

    @pytest.mark.asyncio
    async def test_lookup_by_address(self):
        wp = await cardano_license.create_work_product(
            title="Address Lookup",
            document_hash="addrlookup12345" * 4,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_lookup_1",
        )
        status = await cardano_license.get_work_product_status(
            wp_address="addr_wp_lookup_1"
        )
        assert status is not None
        assert status["title"] == "Address Lookup"
        assert status["wp_address"] == "addr_wp_lookup_1"

    @pytest.mark.asyncio
    async def test_lookup_by_id(self):
        wp = await cardano_license.create_work_product(
            title="ID Lookup",
            document_hash="idlookup1234567" * 4,
            required_signers=["addr_s1"],
            wp_address="addr_wp_id_1",
        )
        status = await cardano_license.get_work_product_status(
            work_product_id=wp["work_product_id"]
        )
        assert status is not None
        assert status["work_product_id"] == wp["work_product_id"]

    @pytest.mark.asyncio
    async def test_lookup_nonexistent_address(self):
        status = await cardano_license.get_work_product_status(
            wp_address="addr_nonexistent"
        )
        assert status is None

    @pytest.mark.asyncio
    async def test_lookup_nonexistent_id(self):
        status = await cardano_license.get_work_product_status(work_product_id=99999)
        assert status is None

    @pytest.mark.asyncio
    async def test_lookup_requires_at_least_one(self):
        with pytest.raises(ValueError, match="Must provide"):
            await cardano_license.get_work_product_status()

    @pytest.mark.asyncio
    async def test_status_includes_signer_validity(self):
        wp = await cardano_license.create_work_product(
            title="Validity Check",
            document_hash="validcheck12345a" * 4,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_val",
        )
        status = await cardano_license.get_work_product_status(
            work_product_id=wp["work_product_id"]
        )
        assert "signer_validity" in status
        assert "addr_s1" in status["signer_validity"]
        assert status["signer_validity"]["addr_s1"]["has_signed"] is False
        assert status["signer_validity"]["addr_s1"]["signature_id"] is None

    @pytest.mark.asyncio
    async def test_status_after_partial_signing(self):
        doc_hash = "partial_addr12345" * 4
        wp = await cardano_license.create_work_product(
            title="Partial Status",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_partial",
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s1", 42
        )
        status = await cardano_license.get_work_product_status(
            wp_address="addr_wp_partial"
        )
        assert status["status"] == "partially_signed"
        assert status["signer_validity"]["addr_s1"]["has_signed"] is True
        assert status["signer_validity"]["addr_s1"]["signature_id"] == 42
        assert status["signer_validity"]["addr_s2"]["has_signed"] is False
        assert status["is_fully_signed"] is False

    @pytest.mark.asyncio
    async def test_status_is_fully_signed_flag(self):
        doc_hash = "fullysigned12345" * 4
        wp = await cardano_license.create_work_product(
            title="Fully Signed",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_wp_full",
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s1", 1
        )
        status = await cardano_license.get_work_product_status(
            wp_address="addr_wp_full"
        )
        assert status["is_fully_signed"] is True
        assert status["status"] == "fully_signed"


class TestGetWorkProductByAddress:
    """Tests for get_work_product_by_address convenience function (#368)."""

    @pytest.mark.asyncio
    async def test_basic_lookup(self):
        await cardano_license.create_work_product(
            title="By Address",
            document_hash="byaddress1234567" * 4,
            required_signers=["addr_a"],
            wp_address="addr_convenience_1",
        )
        result = await cardano_license.get_work_product_by_address("addr_convenience_1")
        assert result is not None
        assert result["title"] == "By Address"

    @pytest.mark.asyncio
    async def test_not_found(self):
        result = await cardano_license.get_work_product_by_address("addr_nope")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_address_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            await cardano_license.get_work_product_by_address("")


class TestFinalizeWorkProduct:
    """Tests for finalize_work_product (#368)."""

    @pytest.mark.asyncio
    async def test_finalize_fully_signed(self):
        doc_hash = "finalize1234567a" * 4
        wp = await cardano_license.create_work_product(
            title="Finalize Test",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_finalize",
        )
        # Add both signatures
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s2", 2)

        result = await cardano_license.finalize_work_product(
            wp_address="addr_wp_finalize"
        )
        assert result["status"] == "finalized"
        assert result["finalized_at"] is not None
        assert result["signature_count"] == 2
        assert result["work_product_id"] == wp["work_product_id"]

    @pytest.mark.asyncio
    async def test_finalize_by_id(self):
        doc_hash = "finalizeid12345a" * 4
        wp = await cardano_license.create_work_product(
            title="Finalize By ID",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_wp_fin_id",
        )
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)

        result = await cardano_license.finalize_work_product(
            work_product_id=wp["work_product_id"]
        )
        assert result["status"] == "finalized"

    @pytest.mark.asyncio
    async def test_finalize_missing_signatures(self):
        doc_hash = "finmissing12345a" * 4
        await cardano_license.create_work_product(
            title="Missing Sigs",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_missing",
        )
        # Only one of two signed
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)

        with pytest.raises(ValueError, match="missing signatures"):
            await cardano_license.finalize_work_product(
                wp_address="addr_wp_missing"
            )

    @pytest.mark.asyncio
    async def test_finalize_no_signatures(self):
        await cardano_license.create_work_product(
            title="No Sigs",
            document_hash="nosigsfinalize12" * 4,
            required_signers=["addr_s1"],
            wp_address="addr_wp_nosigs",
        )
        with pytest.raises(ValueError, match="missing signatures"):
            await cardano_license.finalize_work_product(
                wp_address="addr_wp_nosigs"
            )

    @pytest.mark.asyncio
    async def test_finalize_already_finalized(self):
        doc_hash = "alreadyfinal123a" * 4
        wp = await cardano_license.create_work_product(
            title="Already Final",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_wp_already",
        )
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)

        # Finalize once
        await cardano_license.finalize_work_product(wp_address="addr_wp_already")

        # Try to finalize again
        with pytest.raises(ValueError, match="already finalized"):
            await cardano_license.finalize_work_product(
                wp_address="addr_wp_already"
            )

    @pytest.mark.asyncio
    async def test_finalize_nonexistent(self):
        with pytest.raises(ValueError, match="not found"):
            await cardano_license.finalize_work_product(
                wp_address="addr_nonexistent"
            )

    @pytest.mark.asyncio
    async def test_finalize_requires_param(self):
        with pytest.raises(ValueError, match="Must provide"):
            await cardano_license.finalize_work_product()

    @pytest.mark.asyncio
    async def test_finalize_updates_db(self):
        doc_hash = "findb1234567890a" * 4
        wp = await cardano_license.create_work_product(
            title="DB Update Test",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_wp_dbupd",
        )
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)

        await cardano_license.finalize_work_product(wp_address="addr_wp_dbupd")

        # Verify DB was updated
        status = await cardano_license.get_work_product_status(
            work_product_id=wp["work_product_id"]
        )
        assert status["status"] == "finalized"
        assert status["finalized_at"] is not None

    @pytest.mark.asyncio
    async def test_finalize_rejected_wp(self):
        """Cannot finalize a rejected work product."""
        doc_hash = "rejectedwp12345a" * 4
        wp = await cardano_license.create_work_product(
            title="Rejected WP",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_wp_rejected",
        )
        # Manually set status to rejected
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_work_products SET status = 'rejected' WHERE id = ?",
                (wp["work_product_id"],),
            )
            await db.commit()

        with pytest.raises(ValueError, match="rejected"):
            await cardano_license.finalize_work_product(
                wp_address="addr_wp_rejected"
            )

    @pytest.mark.asyncio
    async def test_finalize_three_signers(self):
        doc_hash = "threesigners1234" * 4
        wp = await cardano_license.create_work_product(
            title="Three Signers",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2", "addr_s3"],
            wp_address="addr_wp_three",
        )
        # Add all three
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s2", 2)
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s3", 3)

        result = await cardano_license.finalize_work_product(
            wp_address="addr_wp_three"
        )
        assert result["status"] == "finalized"
        assert result["signature_count"] == 3


class TestListWorkProducts:
    """Tests for list_work_products (#368)."""

    @pytest.mark.asyncio
    async def test_list_empty(self):
        wps = await cardano_license.list_work_products()
        assert wps == []

    @pytest.mark.asyncio
    async def test_list_all(self):
        await cardano_license.create_work_product(
            title="WP One",
            document_hash="listall123456789" * 4,
            required_signers=["addr_a"],
            wp_address="addr_list_1",
        )
        await cardano_license.create_work_product(
            title="WP Two",
            document_hash="listall234567890" * 4,
            required_signers=["addr_b"],
            wp_address="addr_list_2",
        )
        wps = await cardano_license.list_work_products()
        assert len(wps) == 2

    @pytest.mark.asyncio
    async def test_list_filter_by_status(self):
        doc_hash = "listfilter12345a" * 4
        wp = await cardano_license.create_work_product(
            title="Filter Status",
            document_hash=doc_hash,
            required_signers=["addr_s1"],
            wp_address="addr_list_filter",
        )
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)
        await cardano_license.finalize_work_product(wp_address="addr_list_filter")

        await cardano_license.create_work_product(
            title="Still Pending",
            document_hash="pendingfilter123" * 4,
            required_signers=["addr_s2"],
            wp_address="addr_list_pending",
        )

        finalized = await cardano_license.list_work_products(status="finalized")
        assert len(finalized) == 1
        assert finalized[0]["title"] == "Filter Status"

        pending = await cardano_license.list_work_products(
            status="pending_signatures"
        )
        assert len(pending) == 1
        assert pending[0]["title"] == "Still Pending"

    @pytest.mark.asyncio
    async def test_list_filter_by_address(self):
        await cardano_license.create_work_product(
            title="Addr Filter",
            document_hash="addrfilter12345a" * 4,
            required_signers=["addr_a"],
            wp_address="addr_list_specific",
        )
        await cardano_license.create_work_product(
            title="Other",
            document_hash="other1234567890a" * 4,
            required_signers=["addr_b"],
            wp_address="addr_list_other",
        )
        wps = await cardano_license.list_work_products(
            wp_address="addr_list_specific"
        )
        assert len(wps) == 1
        assert wps[0]["title"] == "Addr Filter"

    @pytest.mark.asyncio
    async def test_list_includes_progress(self):
        doc_hash = "progress1234567a" * 4
        await cardano_license.create_work_product(
            title="Progress Check",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_list_progress",
        )
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)

        wps = await cardano_license.list_work_products()
        assert len(wps) == 1
        assert wps[0]["signature_progress"] == "1/2"
        assert len(wps[0]["missing_signers"]) == 1


class TestStatusIncludesWorkProducts:
    """Tests for get_cardano_status including work product counts (#368)."""

    @pytest.mark.asyncio
    async def test_status_work_product_count(self):
        await cardano_license.create_work_product(
            title="Status WP 1",
            document_hash="statuswp12345678" * 4,
            required_signers=["addr_a"],
            wp_address="addr_status_wp_1",
        )
        status = await cardano_license.get_cardano_status()
        assert "work_product_count" in status
        assert status["work_product_count"] >= 1
        assert "work_products_by_status" in status

    @pytest.mark.asyncio
    async def test_status_work_product_zero(self):
        status = await cardano_license.get_cardano_status()
        assert status["work_product_count"] == 0


class TestWorkProductEndToEnd:
    """End-to-end tests for work product lifecycle (#368)."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Create -> partial sign -> full sign -> finalize."""
        doc_hash = "lifecycle1234567" * 4

        # 1. Create with auto-wallet
        wp = await cardano_license.create_work_product(
            title="Full Lifecycle",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
        )
        assert wp["wallet_generated"] is True
        assert wp["status"] == "pending_signatures"

        # 2. Check initial status
        status = await cardano_license.get_work_product_status(
            wp_address=wp["wp_address"]
        )
        assert status["signature_progress"] == "0/2"
        assert not status["is_fully_signed"]

        # 3. First signer signs
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s1", 10
        )
        status = await cardano_license.get_work_product_status(
            wp_address=wp["wp_address"]
        )
        assert status["status"] == "partially_signed"
        assert status["signature_progress"] == "1/2"

        # 4. Finalize should fail (missing signer)
        with pytest.raises(ValueError, match="missing signatures"):
            await cardano_license.finalize_work_product(
                wp_address=wp["wp_address"]
            )

        # 5. Second signer signs
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_s2", 20
        )
        status = await cardano_license.get_work_product_status(
            wp_address=wp["wp_address"]
        )
        assert status["status"] == "fully_signed"
        assert status["is_fully_signed"] is True

        # 6. Finalize
        result = await cardano_license.finalize_work_product(
            wp_address=wp["wp_address"]
        )
        assert result["status"] == "finalized"
        assert result["signature_count"] == 2

        # 7. Verify finalized in DB
        final_status = await cardano_license.get_work_product_status(
            wp_address=wp["wp_address"]
        )
        assert final_status["status"] == "finalized"
        assert final_status["finalized_at"] is not None

    @pytest.mark.asyncio
    async def test_single_signer_lifecycle(self):
        doc_hash = "singlesigner1234" * 4
        wp = await cardano_license.create_work_product(
            title="Single Signer",
            document_hash=doc_hash,
            required_signers=["addr_solo"],
            wp_address="addr_wp_solo",
        )
        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_solo", 1
        )
        result = await cardano_license.finalize_work_product(
            wp_address="addr_wp_solo"
        )
        assert result["status"] == "finalized"
        assert result["signature_count"] == 1

    @pytest.mark.asyncio
    async def test_by_address_convenience_lifecycle(self):
        doc_hash = "convenience12345a" * 4
        wp = await cardano_license.create_work_product(
            title="Convenience",
            document_hash=doc_hash,
            required_signers=["addr_c1"],
            wp_address="addr_wp_conv",
        )
        # Use get_work_product_by_address
        status = await cardano_license.get_work_product_by_address("addr_wp_conv")
        assert status["title"] == "Convenience"

        await cardano_license_core._update_work_product_signatures(
            doc_hash, "addr_c1", 1
        )
        result = await cardano_license.finalize_work_product(
            wp_address="addr_wp_conv"
        )
        assert result["status"] == "finalized"

    @pytest.mark.asyncio
    async def test_duplicate_signer_ignored(self):
        """Same signer signing twice doesn't count double."""
        doc_hash = "dupsigner1234567" * 4
        wp = await cardano_license.create_work_product(
            title="Dup Signer",
            document_hash=doc_hash,
            required_signers=["addr_s1", "addr_s2"],
            wp_address="addr_wp_dup",
        )
        # addr_s1 signs twice
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 1)
        await cardano_license_core._update_work_product_signatures(doc_hash, "addr_s1", 2)

        status = await cardano_license.get_work_product_status(
            wp_address="addr_wp_dup"
        )
        # Still only partially signed because addr_s2 hasn't signed
        assert status["status"] == "partially_signed"
        assert "addr_s2" in status["missing_signers"]


# ── Plutus V2 Minting Policy Tests ─────────────────────────────
# Task #370: Authority-only minting policy with CBOR serialization

from pycardano import (
    TransactionBuilder,
    NativeScript,
    ScriptAll,
    PlutusV2Script,
    InvalidHereAfter,
    InvalidBefore,
)
from pycardano.hash import VerificationKeyHash, ScriptHash


# Helper: generate a deterministic 28-byte key hash
def _make_pkh(seed: int = 0) -> str:
    """Generate a test pubkey hash (28 bytes / 56 hex chars)."""
    return (f"{seed:02x}" * 28)[:56]


class TestPlutusV2MintingPolicyInit:
    """Test PlutusV2MintingPolicy construction."""

    def test_basic_creation(self):
        pkh = _make_pkh(1)
        policy = cardano_license.PlutusV2MintingPolicy(pkh)
        assert policy.authority_pubkey_hash == pkh
        assert policy.policy_id is not None
        assert len(policy.policy_cbor_hex) > 0
        assert policy.time_lock_after is None
        assert policy.time_lock_before is None

    def test_policy_id_is_deterministic(self):
        pkh = _make_pkh(2)
        p1 = cardano_license.PlutusV2MintingPolicy(pkh)
        p2 = cardano_license.PlutusV2MintingPolicy(pkh)
        assert p1.get_policy_id_hex() == p2.get_policy_id_hex()
        assert p1.policy_cbor_hex == p2.policy_cbor_hex

    def test_different_keys_different_policies(self):
        p1 = cardano_license.PlutusV2MintingPolicy(_make_pkh(1))
        p2 = cardano_license.PlutusV2MintingPolicy(_make_pkh(2))
        assert p1.get_policy_id_hex() != p2.get_policy_id_hex()

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            cardano_license.PlutusV2MintingPolicy("not_valid_hex_zz")

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="28 bytes"):
            cardano_license.PlutusV2MintingPolicy("aabbcc")  # 3 bytes

    def test_empty_hash_raises(self):
        with pytest.raises(ValueError, match="28 bytes"):
            cardano_license.PlutusV2MintingPolicy("")

    def test_native_script_is_scriptpubkey_without_timelocks(self):
        pkh = _make_pkh(3)
        policy = cardano_license.PlutusV2MintingPolicy(pkh)
        assert isinstance(policy.native_script, ScriptPubkey)

    def test_native_script_is_scriptall_with_time_lock_after(self):
        pkh = _make_pkh(4)
        policy = cardano_license.PlutusV2MintingPolicy(pkh, time_lock_after=50000)
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_after == 50000

    def test_native_script_is_scriptall_with_time_lock_before(self):
        pkh = _make_pkh(5)
        policy = cardano_license.PlutusV2MintingPolicy(pkh, time_lock_before=1000)
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_before == 1000

    def test_native_script_with_both_time_locks(self):
        pkh = _make_pkh(6)
        policy = cardano_license.PlutusV2MintingPolicy(
            pkh, time_lock_after=50000, time_lock_before=1000
        )
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_after == 50000
        assert policy.time_lock_before == 1000

    def test_get_policy_id_hex_format(self):
        pkh = _make_pkh(7)
        policy = cardano_license.PlutusV2MintingPolicy(pkh)
        pid_hex = policy.get_policy_id_hex()
        assert isinstance(pid_hex, str)
        assert len(pid_hex) == 56  # ScriptHash is 28 bytes
        bytes.fromhex(pid_hex)  # Should not raise

    def test_to_dict(self):
        pkh = _make_pkh(8)
        policy = cardano_license.PlutusV2MintingPolicy(pkh, time_lock_after=99999)
        d = policy.to_dict()
        assert d["authority_pubkey_hash"] == pkh
        assert d["policy_id"] == policy.get_policy_id_hex()
        assert d["policy_cbor_hex"] == policy.policy_cbor_hex
        assert d["time_lock_after"] == 99999
        assert d["time_lock_before"] is None
        assert "created_at" in d


class TestPlutusV2MintingPolicySerialization:
    """Test CBOR serialization, save/load, and reconstruction."""

    def test_cbor_round_trip(self):
        pkh = _make_pkh(10)
        original = cardano_license.PlutusV2MintingPolicy(pkh)
        restored = cardano_license.PlutusV2MintingPolicy.from_cbor_hex(
            original.policy_cbor_hex
        )
        assert restored.get_policy_id_hex() == original.get_policy_id_hex()
        assert restored.authority_pubkey_hash == pkh

    def test_cbor_round_trip_with_time_locks(self):
        pkh = _make_pkh(11)
        original = cardano_license.PlutusV2MintingPolicy(
            pkh, time_lock_after=50000, time_lock_before=1000
        )
        restored = cardano_license.PlutusV2MintingPolicy.from_cbor_hex(
            original.policy_cbor_hex
        )
        assert restored.get_policy_id_hex() == original.get_policy_id_hex()
        assert restored.authority_pubkey_hash == pkh
        assert restored.time_lock_after == original.time_lock_after
        assert restored.time_lock_before == original.time_lock_before

    def test_save_and_load_policy(self, tmp_path):
        """Test saving policy to disk and loading it back."""
        with patch.object(cardano_license_core, "POLICY_DIR", tmp_path):
            pkh = _make_pkh(12)
            policy = cardano_license.PlutusV2MintingPolicy(pkh)
            json_path = policy.save_policy("test_policy_12")

            assert json_path.exists()
            cbor_path = tmp_path / "test_policy_12.cbor"
            assert cbor_path.exists()

            loaded = cardano_license.PlutusV2MintingPolicy.load_policy("test_policy_12")
            assert loaded.get_policy_id_hex() == policy.get_policy_id_hex()
            assert loaded.authority_pubkey_hash == pkh

    def test_save_policy_json_content(self, tmp_path):
        with patch.object(cardano_license_core, "POLICY_DIR", tmp_path):
            pkh = _make_pkh(13)
            policy = cardano_license.PlutusV2MintingPolicy(pkh, time_lock_after=42000)
            policy.save_policy("test_json_13")

            with open(tmp_path / "test_json_13.json") as f:
                data = json.load(f)

            assert data["authority_pubkey_hash"] == pkh
            assert data["policy_id"] == policy.get_policy_id_hex()
            assert data["time_lock_after"] == 42000
            assert data["label"] == "test_json_13"

    def test_load_nonexistent_policy_raises(self, tmp_path):
        with patch.object(cardano_license_core, "POLICY_DIR", tmp_path):
            with pytest.raises(FileNotFoundError):
                cardano_license.PlutusV2MintingPolicy.load_policy("nonexistent")

    def test_save_cbor_matches_script(self, tmp_path):
        with patch.object(cardano_license_core, "POLICY_DIR", tmp_path):
            pkh = _make_pkh(14)
            policy = cardano_license.PlutusV2MintingPolicy(pkh)
            policy.save_policy("test_cbor_14")

            with open(tmp_path / "test_cbor_14.cbor", "rb") as f:
                cbor_bytes = f.read()

            assert cbor_bytes == bytes.fromhex(policy.policy_cbor_hex)

    def test_from_cbor_hex_invalid_raises(self):
        with pytest.raises(Exception):
            cardano_license.PlutusV2MintingPolicy.from_cbor_hex("deadbeef")


class TestBuildMintingPolicy:
    """Test the build_minting_policy() convenience function."""

    def test_basic_build(self):
        pkh = _make_pkh(20)
        policy = cardano_license.build_minting_policy(pkh)
        assert isinstance(policy, cardano_license.PlutusV2MintingPolicy)
        assert policy.authority_pubkey_hash == pkh
        assert policy.time_lock_after is None

    def test_build_with_time_locks(self):
        pkh = _make_pkh(21)
        policy = cardano_license.build_minting_policy(
            pkh, time_lock_after=100000, time_lock_before=5000
        )
        assert policy.time_lock_after == 100000
        assert policy.time_lock_before == 5000

    def test_build_invalid_hash_raises(self):
        with pytest.raises(ValueError):
            cardano_license.build_minting_policy("tooshort")


class TestAttachMintingPolicy:
    """Test the attach_minting_policy() function."""

    def test_attach_sets_native_scripts(self):
        pkh = _make_pkh(30)
        policy = cardano_license.build_minting_policy(pkh)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None
        builder.mint = None

        mint = MultiAsset()
        mint[policy.policy_id] = Asset({AssetName(b"LIC001"): 1})

        result = cardano_license.attach_minting_policy(builder, policy, mint)
        assert result is builder
        assert builder.native_scripts == [policy.native_script]
        assert builder.mint is mint

    def test_attach_appends_to_existing_scripts(self):
        pkh = _make_pkh(31)
        policy = cardano_license.build_minting_policy(pkh)

        existing_script = ScriptPubkey(VerificationKeyHash(bytes(28)))
        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = [existing_script]

        mint = MultiAsset()
        mint[policy.policy_id] = Asset({AssetName(b"TOK"): 5})

        cardano_license.attach_minting_policy(builder, policy, mint)
        assert len(builder.native_scripts) == 2
        assert builder.native_scripts[0] is existing_script
        assert builder.native_scripts[1] is policy.native_script

    def test_attach_sets_ttl_for_time_lock_after(self):
        pkh = _make_pkh(32)
        policy = cardano_license.build_minting_policy(pkh, time_lock_after=99999)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None

        mint = MultiAsset()
        cardano_license.attach_minting_policy(builder, policy, mint)
        assert builder.ttl == 99999

    def test_attach_sets_validity_start_for_time_lock_before(self):
        pkh = _make_pkh(33)
        policy = cardano_license.build_minting_policy(pkh, time_lock_before=5000)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None

        mint = MultiAsset()
        cardano_license.attach_minting_policy(builder, policy, mint)
        assert builder.validity_start == 5000

    def test_attach_with_valid_redeemer(self):
        pkh = _make_pkh(34)
        policy = cardano_license.build_minting_policy(pkh)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None

        mint = MultiAsset()
        # Should not raise
        cardano_license.attach_minting_policy(
            builder, policy, mint, redeemer_action=cardano_license.MintAction()
        )

    def test_attach_with_burn_redeemer(self):
        pkh = _make_pkh(35)
        policy = cardano_license.build_minting_policy(pkh)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None

        mint = MultiAsset()
        # Should not raise
        cardano_license.attach_minting_policy(
            builder, policy, mint, redeemer_action=cardano_license.BurnAction()
        )

    def test_attach_with_invalid_redeemer_raises(self):
        pkh = _make_pkh(36)
        policy = cardano_license.build_minting_policy(pkh)

        builder = MagicMock(spec=TransactionBuilder)
        builder.native_scripts = None

        mint = MultiAsset()
        with pytest.raises(ValueError, match="Invalid redeemer action"):
            cardano_license.attach_minting_policy(
                builder, policy, mint, redeemer_action="bad_redeemer"
            )


class TestValidateTokenMetadata:
    """Test validate_token_metadata_format()."""

    def test_valid_metadata(self):
        meta = {
            "name": "LIC001",
            "license_type": "professional",
            "issuing_authority": "Virobit",
            "issue_date": "2026-01-15",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is True
        assert errors == []

    def test_valid_metadata_with_all_fields(self):
        meta = {
            "name": "LIC002",
            "license_type": "engineering",
            "issuing_authority": "Virobit",
            "issue_date": "2026-01-15",
            "expiry_date": "2027-01-15",
            "licensee_name": "Alice",
            "jurisdiction": "US-NY",
            "license_number": "ENG-2026-001",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is True
        assert errors == []

    def test_missing_required_fields(self):
        meta = {"name": "LIC003"}
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is False
        assert any("Missing required" in e for e in errors)

    def test_missing_all_fields(self):
        is_valid, errors = cardano_license.validate_token_metadata_format({})
        assert is_valid is False
        assert any("Missing required" in e for e in errors)

    def test_name_too_long(self):
        meta = {
            "name": "A" * 40,  # 40 bytes > 32
            "license_type": "test",
            "issuing_authority": "Test",
            "issue_date": "2026-01-15",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is False
        assert any("exceeds" in e for e in errors)

    def test_name_at_limit(self):
        meta = {
            "name": "A" * 32,  # Exactly 32 bytes
            "license_type": "test",
            "issuing_authority": "Test",
            "issue_date": "2026-01-15",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is True

    def test_invalid_date_format(self):
        meta = {
            "name": "LIC004",
            "license_type": "test",
            "issuing_authority": "Test",
            "issue_date": "not-a-date",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is False
        assert any("not a valid ISO date" in e for e in errors)

    def test_valid_iso_date_with_timezone(self):
        meta = {
            "name": "LIC005",
            "license_type": "test",
            "issuing_authority": "Test",
            "issue_date": "2026-01-15T10:30:00Z",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is True

    def test_non_string_field_type(self):
        meta = {
            "name": 12345,  # Not a string
            "license_type": "test",
            "issuing_authority": "Test",
            "issue_date": "2026-01-15",
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is False
        assert any("must be a string" in e for e in errors)

    def test_multiple_errors(self):
        meta = {
            "name": 12345,  # Wrong type
            # missing license_type, issuing_authority, issue_date
        }
        is_valid, errors = cardano_license.validate_token_metadata_format(meta)
        assert is_valid is False
        assert len(errors) >= 2  # Missing fields + wrong type


class TestMintBurnActions:
    """Test MintAction and BurnAction PlutusData redeemers."""

    def test_mint_action_constr_id(self):
        assert cardano_license.MintAction.CONSTR_ID == 0

    def test_burn_action_constr_id(self):
        assert cardano_license.BurnAction.CONSTR_ID == 1

    def test_mint_action_serializes(self):
        action = cardano_license.MintAction()
        cbor = action.to_cbor_hex()
        assert isinstance(cbor, str)
        assert len(cbor) > 0

    def test_burn_action_serializes(self):
        action = cardano_license.BurnAction()
        cbor = action.to_cbor_hex()
        assert isinstance(cbor, str)
        assert len(cbor) > 0

    def test_different_constructors(self):
        mint = cardano_license.MintAction()
        burn = cardano_license.BurnAction()
        assert mint.to_cbor_hex() != burn.to_cbor_hex()


class TestAuthorityRegistry:
    """Test authority registration and querying (DB-backed)."""

    @pytest.fixture
    async def setup_policy_tables(self):
        """Ensure minting_policies table exists."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS blockchain_minting_policies (
                    policy_id TEXT PRIMARY KEY,
                    authority_address TEXT NOT NULL,
                    authority_pubkey_hash TEXT NOT NULL,
                    policy_cbor_hex TEXT NOT NULL,
                    policy_label TEXT,
                    script_type TEXT NOT NULL DEFAULT 'native_script'
                        CHECK(script_type IN ('native_script', 'plutus_v2')),
                    time_lock_after INTEGER,
                    time_lock_before INTEGER,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    deactivated_at TEXT
                )
            """)
            await db.commit()
        yield
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("DELETE FROM blockchain_minting_policies")
            await db.commit()

    @pytest.mark.asyncio
    async def test_is_registered_authority_true(self):
        """Authority wallet should be recognized."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network)
                VALUES ('authority', 'addr_auth_1', 'aabbcc', 'testnet')
            """)
            await db.commit()

        result = await cardano_license.is_registered_authority("addr_auth_1")
        assert result is True

    @pytest.mark.asyncio
    async def test_is_registered_authority_false(self):
        """Non-authority wallet should not be recognized."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network)
                VALUES ('licensee', 'addr_lic_1', 'ddeeff', 'testnet')
            """)
            await db.commit()

        result = await cardano_license.is_registered_authority("addr_lic_1")
        assert result is False

    @pytest.mark.asyncio
    async def test_is_registered_authority_nonexistent(self):
        result = await cardano_license.is_registered_authority("addr_doesnt_exist")
        assert result is False

    @pytest.mark.asyncio
    async def test_register_minting_authority(self, setup_policy_tables, tmp_path):
        """Test full registration flow: wallet → policy → DB."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        # Save wallet keys to temp dir
        with patch.object(cardano_license_core, "WALLET_DIR", tmp_path / "wallets"):
            cardano_license.save_wallet_keys(
                "test_auth_wallet",
                mnemonic,
                keys["payment_sk"],
                keys["stake_sk"],
            )

        # Register wallet in DB as authority
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network, label)
                VALUES ('authority', ?, ?, 'testnet', 'test_auth_wallet')
            """, (keys["base_address"], keys["payment_key_hash"]))
            await db.commit()

        # Register minting authority
        with patch.object(cardano_license_core, "WALLET_DIR", tmp_path / "wallets"), \
             patch.object(cardano_license_core, "POLICY_DIR", tmp_path / "policies"):
            result = await cardano_license.register_minting_authority("test_auth_wallet")

        assert result["authority_address"] == keys["base_address"]
        assert result["authority_pubkey_hash"] == keys["payment_key_hash"]
        assert len(result["policy_id"]) == 56
        assert len(result["policy_cbor_hex"]) > 0

    @pytest.mark.asyncio
    async def test_register_non_authority_raises(self, setup_policy_tables, tmp_path):
        """Registering a non-authority wallet should fail."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        with patch.object(cardano_license_core, "WALLET_DIR", tmp_path / "wallets"):
            cardano_license.save_wallet_keys(
                "test_lic_wallet", mnemonic, keys["payment_sk"], keys["stake_sk"]
            )

        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network, label)
                VALUES ('licensee', ?, ?, 'testnet', 'test_lic_wallet')
            """, (keys["base_address"], keys["payment_key_hash"]))
            await db.commit()

        with patch.object(cardano_license_core, "WALLET_DIR", tmp_path / "wallets"):
            with pytest.raises(ValueError, match="not 'authority'"):
                await cardano_license.register_minting_authority("test_lic_wallet")

    @pytest.mark.asyncio
    async def test_get_authority_policy(self, setup_policy_tables):
        """Test retrieving an authority's stored policy."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_minting_policies
                (policy_id, authority_address, authority_pubkey_hash,
                 policy_cbor_hex, policy_label, script_type, created_at)
                VALUES ('pol123', 'addr_auth_2', 'pkh_123', 'cbor_hex_abc',
                        'test_label', 'native_script', '2026-01-01T00:00:00')
            """)
            await db.commit()

        result = await cardano_license.get_authority_policy("addr_auth_2")
        assert result is not None
        assert result["policy_id"] == "pol123"
        assert result["policy_cbor_hex"] == "cbor_hex_abc"

    @pytest.mark.asyncio
    async def test_get_authority_policy_not_found(self, setup_policy_tables):
        result = await cardano_license.get_authority_policy("addr_no_policy")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_registered_authorities(self, setup_policy_tables):
        """Test listing all authority wallets with their policies."""
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network, label)
                VALUES ('authority', 'addr_a1', 'pkh_a1', 'testnet', 'auth_1')
            """)
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network, label)
                VALUES ('authority', 'addr_a2', 'pkh_a2', 'testnet', 'auth_2')
            """)
            await db.execute("""
                INSERT INTO blockchain_wallets (wallet_type, address, public_key_hash, network)
                VALUES ('licensee', 'addr_l1', 'pkh_l1', 'testnet')
            """)
            await db.execute("""
                INSERT INTO blockchain_minting_policies
                (policy_id, authority_address, authority_pubkey_hash,
                 policy_cbor_hex, policy_label, script_type, created_at)
                VALUES ('pol_a1', 'addr_a1', 'pkh_a1', 'cbor1',
                        'label_1', 'native_script', '2026-01-01T00:00:00')
            """)
            await db.commit()

        authorities = await cardano_license.list_registered_authorities()
        assert len(authorities) == 2  # Only authority wallets
        addrs = [a["address"] for a in authorities]
        assert "addr_a1" in addrs
        assert "addr_a2" in addrs
        assert "addr_l1" not in addrs

        # auth_1 has a policy, auth_2 does not
        for a in authorities:
            if a["address"] == "addr_a1":
                assert a["policy_id"] == "pol_a1"
            elif a["address"] == "addr_a2":
                assert a["policy_id"] is None


class TestPolicyIntegrationWithExistingMinting:
    """Test that the new policy system integrates with existing minting functions."""

    def test_create_minting_policy_backward_compat(self):
        """Existing create_minting_policy() still works."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)
        policy = cardano_license.create_minting_policy(keys["payment_vk"])
        assert isinstance(policy, ScriptPubkey)

    def test_new_policy_same_hash_as_old(self):
        """New PlutusV2MintingPolicy produces same policy_id as create_minting_policy()."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        old_policy = cardano_license.create_minting_policy(keys["payment_vk"])
        old_pid = old_policy.hash().to_primitive().hex()

        new_policy = cardano_license.build_minting_policy(keys["payment_key_hash"])
        new_pid = new_policy.get_policy_id_hex()

        assert old_pid == new_pid, (
            f"Policy IDs must match for backward compatibility: "
            f"old={old_pid}, new={new_pid}"
        )

    def test_policy_cbor_matches_native_script(self):
        """CBOR hex from PlutusV2MintingPolicy matches direct NativeScript serialization."""
        from pycardano import HDWallet

        mnemonic = HDWallet.generate_mnemonic()
        keys = cardano_license.derive_keys_from_mnemonic(mnemonic)

        direct = ScriptPubkey(keys["payment_vk"].hash())
        policy = cardano_license.build_minting_policy(keys["payment_key_hash"])

        assert policy.policy_cbor_hex == direct.to_cbor_hex()


# ── Signature Collection Validator Tests ─────────────────────────

# Helper: generate valid 28-byte hex PKH
def _make_pkh(seed: int = 0) -> str:
    """Generate a deterministic 28-byte hex PKH for testing."""
    return (f"{seed:02x}" * 28)[:56]


class TestSignerDatum:
    """Tests for SignerDatum PlutusData type."""

    def test_create_signer_datum(self):
        datum = cardano_license.SignerDatum(
            signer_pkh=bytes.fromhex(_make_pkh(1)),
            document_hash=bytes.fromhex("ab" * 32),
            deposit_slot=1000,
            sig_token_policy=bytes.fromhex(_make_pkh(2)),
            val_token_policy=bytes.fromhex(_make_pkh(3)),
            validity_expiry_slot=5000,
        )
        assert datum.CONSTR_ID == 0
        assert datum.deposit_slot == 1000
        assert datum.validity_expiry_slot == 5000

    def test_signer_datum_fields(self):
        pkh = _make_pkh(10)
        datum = cardano_license.SignerDatum(
            signer_pkh=bytes.fromhex(pkh),
            document_hash=bytes.fromhex("cd" * 32),
            deposit_slot=2000,
            sig_token_policy=bytes.fromhex(_make_pkh(20)),
            val_token_policy=bytes.fromhex(_make_pkh(30)),
            validity_expiry_slot=9000,
        )
        assert datum.signer_pkh.hex() == pkh
        assert datum.document_hash.hex() == "cd" * 32

    def test_signer_datum_to_cbor(self):
        datum = cardano_license.SignerDatum(
            signer_pkh=bytes.fromhex(_make_pkh(1)),
            document_hash=bytes.fromhex("ab" * 32),
            deposit_slot=1000,
            sig_token_policy=bytes.fromhex(_make_pkh(2)),
            val_token_policy=bytes.fromhex(_make_pkh(3)),
            validity_expiry_slot=5000,
        )
        cbor_hex = datum.to_cbor_hex()
        assert isinstance(cbor_hex, str)
        assert len(cbor_hex) > 0


class TestRedeemerTypes:
    """Tests for CollectRedeemer, FinalizeRedeemer, ReclaimRedeemer."""

    def test_collect_redeemer(self):
        r = cardano_license.CollectRedeemer()
        assert r.CONSTR_ID == 0

    def test_finalize_redeemer(self):
        r = cardano_license.FinalizeRedeemer()
        assert r.CONSTR_ID == 1

    def test_reclaim_redeemer(self):
        r = cardano_license.ReclaimRedeemer()
        assert r.CONSTR_ID == 2

    def test_redeemer_constr_ids_unique(self):
        ids = [
            cardano_license.CollectRedeemer.CONSTR_ID,
            cardano_license.FinalizeRedeemer.CONSTR_ID,
            cardano_license.ReclaimRedeemer.CONSTR_ID,
        ]
        assert len(set(ids)) == 3


class TestSignatureCollectionValidatorInit:
    """Tests for SignatureCollectionValidator construction."""

    def test_basic_construction(self):
        pkh1 = _make_pkh(1)
        pkh2 = _make_pkh(2)
        auth_pkh = _make_pkh(99)
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[pkh1, pkh2],
            authority_pkh=auth_pkh,
            document_hash="ab" * 32,
        )
        assert v.required_signers == [pkh1, pkh2]
        assert v.authority_pkh == auth_pkh
        assert v.document_hash == "ab" * 32

    def test_empty_signers_raises(self):
        with pytest.raises(ValueError, match="required_signers must contain"):
            cardano_license.SignatureCollectionValidator(
                required_signers=[],
                authority_pkh=_make_pkh(1),
                document_hash="ab" * 32,
            )

    def test_invalid_doc_hash_raises(self):
        with pytest.raises(ValueError, match="document_hash must be"):
            cardano_license.SignatureCollectionValidator(
                required_signers=[_make_pkh(1)],
                authority_pkh=_make_pkh(2),
                document_hash="abc",
            )

    def test_invalid_pkh_raises(self):
        with pytest.raises(ValueError):
            cardano_license.SignatureCollectionValidator(
                required_signers=["not_valid_hex"],
                authority_pkh=_make_pkh(1),
                document_hash="ab" * 32,
            )

    def test_invalid_authority_pkh_raises(self):
        with pytest.raises(ValueError):
            cardano_license.SignatureCollectionValidator(
                required_signers=[_make_pkh(1)],
                authority_pkh="short",
                document_hash="ab" * 32,
            )

    def test_script_hash_is_deterministic(self):
        args = dict(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v1 = cardano_license.SignatureCollectionValidator(**args)
        v2 = cardano_license.SignatureCollectionValidator(**args)
        assert v1.get_script_hash_hex() == v2.get_script_hash_hex()

    def test_validator_address_is_bech32(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        addr = v.get_validator_address()
        assert addr.startswith("addr_test1") or addr.startswith("addr1")

    def test_different_authorities_different_hashes(self):
        v1 = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(10),
            document_hash="ab" * 32,
        )
        v2 = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(20),
            document_hash="ab" * 32,
        )
        assert v1.get_script_hash_hex() != v2.get_script_hash_hex()

    def test_with_validity_slot_deadline(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=100000,
        )
        assert v.validity_slot_deadline == 100000

    def test_single_signer(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        assert len(v.required_signers) == 1

    def test_many_signers(self):
        signers = [_make_pkh(i) for i in range(10)]
        v = cardano_license.SignatureCollectionValidator(
            required_signers=signers,
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        assert len(v.required_signers) == 10


class TestValidatorSignerAuthorization:
    """Tests for validate_signer_authorized."""

    def test_authorized_signer(self):
        pkh = _make_pkh(1)
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[pkh, _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ok, msg = v.validate_signer_authorized(pkh)
        assert ok is True
        assert msg == "authorized"

    def test_unauthorized_signer(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ok, msg = v.validate_signer_authorized(_make_pkh(50))
        assert ok is False
        assert "not in required_signers" in msg


class TestValidatorValidityCheck:
    """Tests for validate_validity_not_expired."""

    def test_valid_token(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ok, msg = v.validate_validity_not_expired(5000, 1000)
        assert ok is True
        assert msg == "valid"

    def test_expired_token(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ok, msg = v.validate_validity_not_expired(500, 1000)
        assert ok is False
        assert "expired" in msg

    def test_exactly_at_slot(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ok, msg = v.validate_validity_not_expired(1000, 1000)
        assert ok is False  # expiry == current means expired

    def test_exceeds_deadline(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=3000,
        )
        ok, msg = v.validate_validity_not_expired(5000, 1000)
        assert ok is False
        assert "exceeds deadline" in msg

    def test_within_deadline(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=10000,
        )
        ok, msg = v.validate_validity_not_expired(5000, 1000)
        assert ok is True


class TestValidatorDepositValidation:
    """Tests for validate_deposit."""

    def _make_validator(self, signers=None, deadline=None):
        if signers is None:
            signers = [_make_pkh(1), _make_pkh(2)]
        return cardano_license.SignatureCollectionValidator(
            required_signers=signers,
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=deadline,
        )

    def test_valid_deposit(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(_make_pkh(1), 5000, 1000)
        assert ok is True
        assert errors == []

    def test_unauthorized_signer(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(_make_pkh(50), 5000, 1000)
        assert ok is False
        assert any("not in required_signers" in e for e in errors)

    def test_expired_validity(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(_make_pkh(1), 500, 1000)
        assert ok is False
        assert any("expired" in e for e in errors)

    def test_missing_sig_token(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(_make_pkh(1), 5000, 1000, has_sig_token=False)
        assert ok is False
        assert any("signature token" in e for e in errors)

    def test_missing_val_token(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(_make_pkh(1), 5000, 1000, has_val_token=False)
        assert ok is False
        assert any("validity token" in e for e in errors)

    def test_missing_both_tokens(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(
            _make_pkh(1), 5000, 1000,
            has_sig_token=False, has_val_token=False,
        )
        assert ok is False
        assert len(errors) >= 2

    def test_duplicate_deposit(self):
        v = self._make_validator()
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_abc"
        )
        ok, errors = v.validate_deposit(_make_pkh(1), 5000, 1500)
        assert ok is False
        assert any("already deposited" in e for e in errors)

    def test_multiple_errors(self):
        v = self._make_validator()
        ok, errors = v.validate_deposit(
            _make_pkh(50), 500, 1000,
            has_sig_token=False, has_val_token=False,
        )
        assert ok is False
        assert len(errors) == 4  # unauthorized + expired + no sig + no val


class TestValidatorRecordDeposit:
    """Tests for record_deposit."""

    def test_record_deposit_returns_datum(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        datum = v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        assert isinstance(datum, cardano_license.SignerDatum)
        assert datum.deposit_slot == 1000
        assert datum.validity_expiry_slot == 5000

    def test_record_deposit_updates_collected(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        assert _make_pkh(1) in v._collected_signers
        assert v._collected_signers[_make_pkh(1)]["tx_hash"] == "tx_001"

    def test_record_multiple_deposits(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2), _make_pkh(3)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        v.record_deposit(
            _make_pkh(2), 2000, _make_pkh(10), _make_pkh(20), 5000, "tx_002"
        )
        assert len(v._collected_signers) == 2


class TestValidatorFinalizationCheck:
    """Tests for check_finalization_ready."""

    def test_not_ready_no_deposits(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        ready, details = v.check_finalization_ready()
        assert ready is False
        assert details["total_required"] == 2
        assert details["total_collected"] == 0
        assert len(details["missing_signers"]) == 2
        assert details["progress"] == "0/2"

    def test_partially_ready(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        ready, details = v.check_finalization_ready()
        assert ready is False
        assert details["total_collected"] == 1
        assert details["progress"] == "1/2"

    def test_all_signers_deposited(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        v.record_deposit(
            _make_pkh(2), 2000, _make_pkh(10), _make_pkh(20), 5000, "tx_002"
        )
        ready, details = v.check_finalization_ready()
        assert ready is True
        assert details["total_collected"] == 2
        assert details["missing_signers"] == []
        assert details["progress"] == "2/2"

    def test_single_signer_ready(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        ready, details = v.check_finalization_ready()
        assert ready is True

    def test_extra_signers_tracked(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        # Manually inject an extra signer (shouldn't normally happen)
        v._collected_signers[_make_pkh(50)] = {"tx_hash": "tx_extra"}
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        ready, details = v.check_finalization_ready()
        assert ready is True
        assert len(details["extra_signers"]) == 1


class TestValidatorRedeemers:
    """Tests for redeemer building."""

    def test_collect_redeemer(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        r = v.build_collect_redeemer()
        assert r is not None

    def test_finalize_redeemer(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        r = v.build_finalize_redeemer()
        assert r is not None

    def test_reclaim_redeemer(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        r = v.build_reclaim_redeemer()
        assert r is not None


class TestValidatorSerialization:
    """Tests for to_dict, save_validator, load_validator."""

    def test_to_dict(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        d = v.to_dict()
        assert d["required_signers"] == [_make_pkh(1), _make_pkh(2)]
        assert d["authority_pkh"] == _make_pkh(99)
        assert d["document_hash"] == "ab" * 32
        assert "script_hash" in d
        assert "validator_address" in d
        assert "script_cbor_hex" in d

    def test_to_dict_with_collected_signers(self):
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        d = v.to_dict()
        assert _make_pkh(1) in d["collected_signers"]

    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)

        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=50000,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )

        json_path = v.save_validator("test_wp")
        assert json_path.exists()
        assert (tmp_path / "validator_test_wp.cbor").exists()

        loaded = cardano_license.SignatureCollectionValidator.load_validator("test_wp")
        assert loaded.required_signers == v.required_signers
        assert loaded.authority_pkh == v.authority_pkh
        assert loaded.document_hash == v.document_hash
        assert loaded.validity_slot_deadline == v.validity_slot_deadline
        assert _make_pkh(1) in loaded._collected_signers
        assert loaded.get_script_hash_hex() == v.get_script_hash_hex()

    def test_load_nonexistent_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        with pytest.raises(FileNotFoundError):
            cardano_license.SignatureCollectionValidator.load_validator("nonexistent")

    def test_save_creates_json_and_cbor(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        v = cardano_license.SignatureCollectionValidator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.save_validator("my_label")
        json_file = tmp_path / "validator_my_label.json"
        cbor_file = tmp_path / "validator_my_label.cbor"
        assert json_file.exists()
        assert cbor_file.exists()
        # Verify JSON content
        data = json.loads(json_file.read_text())
        assert data["label"] == "my_label"
        assert data["type"] == "signature_collection_validator"


class TestBuildSignatureValidator:
    """Tests for build_signature_validator convenience function."""

    def test_basic_build(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            document_hash="ab" * 32,
        )
        assert isinstance(v, cardano_license.SignatureCollectionValidator)
        assert v.authority_pkh == _make_pkh(1)  # defaults to first signer

    def test_explicit_authority(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        assert v.authority_pkh == _make_pkh(99)

    def test_placeholder_hash(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
        )
        assert v.document_hash == "0" * 64

    def test_with_deadline(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
            document_hash="ab" * 32,
            validity_slot_deadline=99999,
        )
        assert v.validity_slot_deadline == 99999

    def test_empty_signers_raises(self):
        with pytest.raises(ValueError):
            cardano_license.build_signature_validator(required_signers=[])


class TestValidateSignerDeposit:
    """Tests for validate_signer_deposit async function."""

    @pytest.mark.asyncio
    async def test_no_validator_deployed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        result = await cardano_license.validate_signer_deposit(
            work_product_id=9999,
            signer_pkh=_make_pkh(1),
            validity_expiry_slot=5000,
            current_slot=1000,
        )
        assert result["is_valid"] is False
        assert "No validator deployed" in result["errors"][0]

    @pytest.mark.asyncio
    async def test_valid_deposit_with_validator(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        # Deploy a validator for wp_42
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.save_validator("wp_42")

        result = await cardano_license.validate_signer_deposit(
            work_product_id=42,
            signer_pkh=_make_pkh(1),
            validity_expiry_slot=5000,
            current_slot=1000,
        )
        assert result["is_valid"] is True
        assert result["errors"] == []
        assert result["work_product_id"] == 42

    @pytest.mark.asyncio
    async def test_invalid_deposit_unauthorized(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.save_validator("wp_43")

        result = await cardano_license.validate_signer_deposit(
            work_product_id=43,
            signer_pkh=_make_pkh(50),
            validity_expiry_slot=5000,
            current_slot=1000,
        )
        assert result["is_valid"] is False


class TestCheckFinalizationReady:
    """Tests for check_finalization_ready async function."""

    @pytest.mark.asyncio
    async def test_no_validator(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        result = await cardano_license.check_finalization_ready(9999)
        assert result["is_ready"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_not_ready(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.save_validator("wp_44")

        result = await cardano_license.check_finalization_ready(44)
        assert result["is_ready"] is False
        assert result["progress"] == "0/2"

    @pytest.mark.asyncio
    async def test_ready_after_deposits(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1), _make_pkh(2)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        v.record_deposit(
            _make_pkh(2), 2000, _make_pkh(10), _make_pkh(20), 5000, "tx_002"
        )
        v.save_validator("wp_45")

        result = await cardano_license.check_finalization_ready(45)
        assert result["is_ready"] is True
        assert result["progress"] == "2/2"


class TestValidatorEndToEnd:
    """End-to-end tests for the signature collection validator flow."""

    def test_full_workflow(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)

        # Step 1: Build validator
        signers = [_make_pkh(1), _make_pkh(2), _make_pkh(3)]
        v = cardano_license.build_signature_validator(
            required_signers=signers,
            authority_pkh=_make_pkh(99),
            document_hash="deadbeef" * 8,
        )
        assert isinstance(v, cardano_license.SignatureCollectionValidator)

        # Step 2: Verify not ready
        ready, details = v.check_finalization_ready()
        assert ready is False
        assert details["total_required"] == 3

        # Step 3: Validate and record deposits
        for i in range(1, 4):
            pkh = _make_pkh(i)
            ok, errors = v.validate_deposit(pkh, 5000, 1000)
            assert ok is True, f"Signer {i} should be valid: {errors}"
            v.record_deposit(
                pkh, 1000 + i, _make_pkh(10), _make_pkh(20), 5000, f"tx_{i:03d}"
            )

        # Step 4: Verify ready
        ready, details = v.check_finalization_ready()
        assert ready is True
        assert details["total_collected"] == 3
        assert details["missing_signers"] == []

        # Step 5: Save and reload
        v.save_validator("e2e_test")
        loaded = cardano_license.SignatureCollectionValidator.load_validator("e2e_test")
        loaded_ready, loaded_details = loaded.check_finalization_ready()
        assert loaded_ready is True

    def test_reject_after_expiry(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
            validity_slot_deadline=3000,
        )

        # Valid deposit
        ok, errors = v.validate_deposit(_make_pkh(1), 2500, 1000)
        assert ok is True

        # Expired validity token
        ok, errors = v.validate_deposit(_make_pkh(1), 500, 1000)
        assert ok is False

        # Validity exceeds deadline
        ok, errors = v.validate_deposit(_make_pkh(1), 5000, 1000)
        assert ok is False

    def test_datum_serialization_roundtrip(self):
        v = cardano_license.build_signature_validator(
            required_signers=[_make_pkh(1)],
            authority_pkh=_make_pkh(99),
            document_hash="ab" * 32,
        )
        datum = v.record_deposit(
            _make_pkh(1), 1000, _make_pkh(10), _make_pkh(20), 5000, "tx_001"
        )
        # Datum should serialize to CBOR and back
        cbor = datum.to_cbor_hex()
        restored = cardano_license.SignerDatum.from_cbor(cbor)
        assert restored.signer_pkh == datum.signer_pkh
        assert restored.deposit_slot == datum.deposit_slot
        assert restored.validity_expiry_slot == datum.validity_expiry_slot


# ── Dues Enforcement Contract Tests (Task #372) ─────────────────

def _make_dues_pkh(seed: int = 0) -> str:
    """Generate a test pubkey hash (28 bytes / 56 hex chars)."""
    return (f"{seed:02x}" * 28)[:56]


class TestDuesContractDatum:
    def test_datum_creation(self):
        datum = cardano_license.DuesContractDatum(
            authority_pkh=bytes.fromhex(_make_dues_pkh(1)),
            annual_dues=50_000_000,
            license_ref=1,
            grace_period_slots=86400,
        )
        assert datum.annual_dues == 50_000_000
        assert datum.license_ref == 1
        assert datum.grace_period_slots == 86400

    def test_datum_cbor_roundtrip(self):
        datum = cardano_license.DuesContractDatum(
            authority_pkh=bytes.fromhex(_make_dues_pkh(1)),
            annual_dues=100_000_000,
            license_ref=42,
            grace_period_slots=172800,
        )
        cbor = datum.to_cbor_hex()
        restored = cardano_license.DuesContractDatum.from_cbor(cbor)
        assert restored.annual_dues == 100_000_000
        assert restored.license_ref == 42
        assert restored.grace_period_slots == 172800

    def test_datum_default_values(self):
        datum = cardano_license.DuesContractDatum()
        assert datum.authority_pkh == b""
        assert datum.annual_dues == 0
        assert datum.license_ref == 0
        assert datum.grace_period_slots == 0


class TestDuesRedeemers:
    def test_pay_dues_redeemer_constr(self):
        r = cardano_license.PayDuesRedeemer()
        assert r.CONSTR_ID == 0

    def test_revoke_validity_redeemer_constr(self):
        r = cardano_license.RevokeValidityRedeemer()
        assert r.CONSTR_ID == 1

    def test_pay_dues_cbor_roundtrip(self):
        r = cardano_license.PayDuesRedeemer()
        cbor = r.to_cbor_hex()
        restored = cardano_license.PayDuesRedeemer.from_cbor(cbor)
        assert restored.CONSTR_ID == 0

    def test_revoke_validity_cbor_roundtrip(self):
        r = cardano_license.RevokeValidityRedeemer()
        cbor = r.to_cbor_hex()
        restored = cardano_license.RevokeValidityRedeemer.from_cbor(cbor)
        assert restored.CONSTR_ID == 1


class TestDuesEnforcementContractInit:
    """Test DuesEnforcementContract construction and validation."""

    def test_valid_construction(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        assert c.authority_pkh == _make_dues_pkh(1)
        assert c.annual_dues_lovelace == 50_000_000
        assert c.license_ref == 1
        assert c.grace_period_slots == cardano_license.DEFAULT_GRACE_PERIOD_SLOTS

    def test_custom_grace_period(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=1_000_000,
            license_ref=1,
            grace_period_slots=172800,
        )
        assert c.grace_period_slots == 172800

    def test_invalid_pkh_too_short(self):
        with pytest.raises(ValueError, match="28 bytes"):
            cardano_license.DuesEnforcementContract(
                authority_pkh="aabb",
                authority_address="addr_test1qztest",
                annual_dues_lovelace=1_000_000,
                license_ref=1,
            )

    def test_invalid_pkh_bad_hex(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            cardano_license.DuesEnforcementContract(
                authority_pkh="zz" * 28,
                authority_address="addr_test1qztest",
                annual_dues_lovelace=1_000_000,
                license_ref=1,
            )

    def test_empty_authority_address(self):
        with pytest.raises(ValueError, match="authority_address"):
            cardano_license.DuesEnforcementContract(
                authority_pkh=_make_dues_pkh(1),
                authority_address="",
                annual_dues_lovelace=1_000_000,
                license_ref=1,
            )

    def test_dues_below_minimum(self):
        with pytest.raises(ValueError, match="annual_dues_lovelace must be >="):
            cardano_license.DuesEnforcementContract(
                authority_pkh=_make_dues_pkh(1),
                authority_address="addr_test1qztest",
                annual_dues_lovelace=999_999,
                license_ref=1,
            )

    def test_dues_exactly_minimum(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=1_000_000,
            license_ref=1,
        )
        assert c.annual_dues_lovelace == 1_000_000

    def test_dues_above_maximum(self):
        with pytest.raises(ValueError, match="annual_dues_lovelace must be <="):
            cardano_license.DuesEnforcementContract(
                authority_pkh=_make_dues_pkh(1),
                authority_address="addr_test1qztest",
                annual_dues_lovelace=10_000_000_001,
                license_ref=1,
            )

    def test_negative_license_ref(self):
        with pytest.raises(ValueError, match="license_ref must be positive"):
            cardano_license.DuesEnforcementContract(
                authority_pkh=_make_dues_pkh(1),
                authority_address="addr_test1qztest",
                annual_dues_lovelace=1_000_000,
                license_ref=0,
            )

    def test_negative_grace_period(self):
        with pytest.raises(ValueError, match="grace_period_slots must be >= 0"):
            cardano_license.DuesEnforcementContract(
                authority_pkh=_make_dues_pkh(1),
                authority_address="addr_test1qztest",
                annual_dues_lovelace=1_000_000,
                license_ref=1,
                grace_period_slots=-1,
            )

    def test_script_hash_hex(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        # ScriptHash = 28 bytes = 56 hex chars
        assert len(c.get_script_hash_hex()) == 56
        int(c.get_script_hash_hex(), 16)  # valid hex

    def test_contract_address_bech32(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        addr = c.get_contract_address()
        assert addr.startswith("addr_test1")

    def test_script_cbor_hex(self):
        c = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        cbor = c.get_script_cbor_hex()
        assert len(cbor) > 0
        bytes.fromhex(cbor)  # valid hex

    def test_deterministic_script_hash(self):
        c1 = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        c2 = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=100_000_000,
            license_ref=2,
        )
        # Same authority PKH → same script → same hash
        assert c1.get_script_hash_hex() == c2.get_script_hash_hex()

    def test_different_pkh_different_hash(self):
        c1 = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        c2 = cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(2),
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        assert c1.get_script_hash_hex() != c2.get_script_hash_hex()


class TestDuesPaymentValidation:
    """Test validate_payment and validate_renewal methods."""

    def _make_contract(self, dues=50_000_000, grace=86400):
        return cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qzauthority",
            annual_dues_lovelace=dues,
            license_ref=1,
            grace_period_slots=grace,
        )

    def test_valid_payment(self):
        c = self._make_contract()
        is_valid, errors = c.validate_payment(50_000_000, "addr_test1qzauthority")
        assert is_valid is True
        assert errors == []

    def test_overpayment_is_valid(self):
        c = self._make_contract()
        is_valid, errors = c.validate_payment(100_000_000, "addr_test1qzauthority")
        assert is_valid is True

    def test_underpayment(self):
        c = self._make_contract()
        is_valid, errors = c.validate_payment(49_999_999, "addr_test1qzauthority")
        assert is_valid is False
        assert any("lovelace < required" in e for e in errors)

    def test_wrong_recipient(self):
        c = self._make_contract()
        is_valid, errors = c.validate_payment(50_000_000, "addr_test1qzwrong")
        assert is_valid is False
        assert any("authority address" in e for e in errors)

    def test_underpayment_and_wrong_recipient(self):
        c = self._make_contract()
        is_valid, errors = c.validate_payment(1000, "addr_test1qzwrong")
        assert is_valid is False
        assert len(errors) == 2

    def test_renewal_valid(self):
        c = self._make_contract()
        is_valid, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address="addr_test1qzauthority",
            current_slot=1000,
            current_expiry_slot=900,  # expired but within grace
        )
        assert is_valid is True

    def test_renewal_past_grace_period(self):
        c = self._make_contract(grace=100)
        is_valid, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address="addr_test1qzauthority",
            current_slot=2000,
            current_expiry_slot=1000,  # 1000 slots past, grace=100
        )
        assert is_valid is False
        assert any("grace period" in e for e in errors)

    def test_renewal_within_grace_period(self):
        c = self._make_contract(grace=500)
        is_valid, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address="addr_test1qzauthority",
            current_slot=1400,
            current_expiry_slot=1000,  # 400 slots past, grace=500
        )
        assert is_valid is True

    def test_renewal_no_current_expiry(self):
        c = self._make_contract()
        is_valid, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address="addr_test1qzauthority",
            current_slot=1000,
            current_expiry_slot=None,  # No expiry known
        )
        assert is_valid is True


class TestDuesValidityForSigning:
    """Test check_validity_for_signing method."""

    def _make_contract(self):
        return cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qzauthority",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )

    def test_signing_before_expiry(self):
        c = self._make_contract()
        can_sign, reason = c.check_validity_for_signing(5000, 4000)
        assert can_sign is True
        assert reason == "valid"

    def test_signing_at_expiry(self):
        c = self._make_contract()
        can_sign, reason = c.check_validity_for_signing(5000, 5000)
        assert can_sign is False
        assert "expired" in reason

    def test_signing_after_expiry(self):
        c = self._make_contract()
        can_sign, reason = c.check_validity_for_signing(5000, 6000)
        assert can_sign is False
        assert "renew" in reason


class TestDuesGracePeriod:
    """Test check_in_grace_period method."""

    def _make_contract(self, grace=86400):
        return cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qzauthority",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            grace_period_slots=grace,
        )

    def test_not_expired_yet(self):
        c = self._make_contract()
        in_grace, remaining = c.check_in_grace_period(5000, 4000)
        assert in_grace is False
        assert remaining == 0

    def test_just_expired_in_grace(self):
        c = self._make_contract(grace=100)
        in_grace, remaining = c.check_in_grace_period(5000, 5050)
        assert in_grace is True
        assert remaining == 50

    def test_at_grace_boundary(self):
        c = self._make_contract(grace=100)
        in_grace, remaining = c.check_in_grace_period(5000, 5100)
        assert in_grace is True
        assert remaining == 0

    def test_past_grace_period(self):
        c = self._make_contract(grace=100)
        in_grace, remaining = c.check_in_grace_period(5000, 5101)
        assert in_grace is False
        assert remaining == 0

    def test_zero_grace_period(self):
        c = self._make_contract(grace=0)
        in_grace, remaining = c.check_in_grace_period(5000, 5000)
        assert in_grace is True
        assert remaining == 0

        in_grace, remaining = c.check_in_grace_period(5000, 5001)
        assert in_grace is False


class TestDuesContractSerialization:
    """Test to_dict, save_contract, load_contract."""

    def _make_contract(self):
        return cardano_license.DuesEnforcementContract(
            authority_pkh=_make_dues_pkh(1),
            authority_address="addr_test1qzauthority",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            grace_period_slots=172800,
        )

    def test_to_dict(self):
        c = self._make_contract()
        d = c.to_dict()
        assert d["authority_pkh"] == _make_dues_pkh(1)
        assert d["authority_address"] == "addr_test1qzauthority"
        assert d["annual_dues_lovelace"] == 50_000_000
        assert d["license_ref"] == 1
        assert d["grace_period_slots"] == 172800
        assert "script_hash" in d
        assert "contract_address" in d
        assert "script_cbor_hex" in d
        assert "created_at" in d

    def test_save_and_load_contract(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        c = self._make_contract()
        json_path = c.save_contract("test_dues")

        assert json_path.exists()
        assert (tmp_path / "dues_test_dues.cbor").exists()

        loaded = cardano_license.DuesEnforcementContract.load_contract("test_dues")
        assert loaded.authority_pkh == c.authority_pkh
        assert loaded.authority_address == c.authority_address
        assert loaded.annual_dues_lovelace == c.annual_dues_lovelace
        assert loaded.license_ref == c.license_ref
        assert loaded.grace_period_slots == c.grace_period_slots
        # Same script hash after round-trip
        assert loaded.get_script_hash_hex() == c.get_script_hash_hex()

    def test_load_nonexistent_contract(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        with pytest.raises(FileNotFoundError, match="Contract file not found"):
            cardano_license.DuesEnforcementContract.load_contract("nonexistent")

    def test_build_datum(self):
        c = self._make_contract()
        datum = c.build_datum()
        assert isinstance(datum, cardano_license.DuesContractDatum)
        assert datum.annual_dues == 50_000_000
        assert datum.license_ref == 1
        assert datum.grace_period_slots == 172800

    def test_build_pay_redeemer(self):
        c = self._make_contract()
        redeemer = c.build_pay_redeemer()
        from pycardano import Redeemer
        assert isinstance(redeemer, Redeemer)

    def test_build_revoke_redeemer(self):
        c = self._make_contract()
        redeemer = c.build_revoke_redeemer()
        from pycardano import Redeemer
        assert isinstance(redeemer, Redeemer)


class TestBuildDuesContract:
    """Test the build_dues_contract convenience function."""

    def test_build_with_explicit_pkh(self):
        c = cardano_license.build_dues_contract(
            authority_address="addr_test1qztest",
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            authority_pkh=_make_dues_pkh(1),
        )
        assert isinstance(c, cardano_license.DuesEnforcementContract)
        assert c.authority_pkh == _make_dues_pkh(1)
        assert c.annual_dues_lovelace == 50_000_000
        assert c.license_ref == 1

    def test_build_with_real_address_extracts_pkh(self):
        # Generate a real testnet address
        addr = _make_valid_testnet_address()
        c = cardano_license.build_dues_contract(
            authority_address=addr,
            annual_dues_lovelace=25_000_000,
            license_ref=2,
        )
        assert len(c.authority_pkh) == 56
        assert c.authority_address == addr

    def test_build_custom_grace_period(self):
        c = cardano_license.build_dues_contract(
            authority_address="addr_test1qztest",
            annual_dues_lovelace=1_000_000,
            license_ref=1,
            grace_period_slots=3600,
            authority_pkh=_make_dues_pkh(1),
        )
        assert c.grace_period_slots == 3600


# ── Dues Contract DB Record Tests ────────────────────────────────

class TestStoreDuesContract:
    @pytest.mark.asyncio
    async def test_store_dues_contract(self):
        cid = await cardano_license_core._store_dues_contract(
            authority_address="addr_test1qzauth",
            authority_pkh=_make_dues_pkh(1),
            license_ref=1,
            annual_dues_lovelace=50_000_000,
            grace_period_slots=86400,
            policy_id="aa" * 28,
            script_hash="aa" * 28,
            contract_address="addr_test1qzcontract",
            script_cbor_hex="ff" * 20,
        )
        assert cid > 0

    @pytest.mark.asyncio
    async def test_get_dues_contract(self):
        cid = await cardano_license_core._store_dues_contract(
            authority_address="addr_test1qzauth",
            authority_pkh=_make_dues_pkh(1),
            license_ref=1,
            annual_dues_lovelace=50_000_000,
            grace_period_slots=86400,
            policy_id="bb" * 28,
            script_hash="bb" * 28,
            contract_address="addr_test1qzcontract",
            script_cbor_hex="ff" * 20,
        )
        rec = await cardano_license.get_dues_contract(cid)
        assert rec is not None
        assert rec["annual_dues_lovelace"] == 50_000_000
        assert rec["status"] == "active"

    @pytest.mark.asyncio
    async def test_get_dues_contract_not_found(self):
        rec = await cardano_license.get_dues_contract(99999)
        assert rec is None

    @pytest.mark.asyncio
    async def test_get_dues_contract_for_license(self):
        await cardano_license_core._store_dues_contract(
            "addr_auth", _make_dues_pkh(1), 42, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_contract", "ff" * 20,
        )
        rec = await cardano_license.get_dues_contract_for_license(42)
        assert rec is not None
        assert rec["license_ref"] == 42

    @pytest.mark.asyncio
    async def test_get_dues_contract_for_license_not_found(self):
        rec = await cardano_license.get_dues_contract_for_license(99999)
        assert rec is None

    @pytest.mark.asyncio
    async def test_list_dues_contracts_all(self):
        await cardano_license_core._store_dues_contract(
            "addr1", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_c1", "ff" * 20,
        )
        await cardano_license_core._store_dues_contract(
            "addr2", _make_dues_pkh(2), 2, 100_000_000, 86400,
            "bb" * 28, "bb" * 28, "addr_c2", "ee" * 20,
        )
        contracts = await cardano_license.list_dues_contracts()
        assert len(contracts) == 2

    @pytest.mark.asyncio
    async def test_list_dues_contracts_by_status(self):
        await cardano_license_core._store_dues_contract(
            "addr1", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_c1", "ff" * 20,
        )
        active = await cardano_license.list_dues_contracts(status="active")
        assert len(active) == 1

        suspended = await cardano_license.list_dues_contracts(status="suspended")
        assert len(suspended) == 0

    @pytest.mark.asyncio
    async def test_list_dues_contracts_by_authority(self):
        await cardano_license_core._store_dues_contract(
            "addr_target", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_c1", "ff" * 20,
        )
        await cardano_license_core._store_dues_contract(
            "addr_other", _make_dues_pkh(2), 2, 50_000_000, 86400,
            "bb" * 28, "bb" * 28, "addr_c2", "ff" * 20,
        )
        contracts = await cardano_license.list_dues_contracts(
            authority_address="addr_target"
        )
        assert len(contracts) == 1


# ── Deploy Dues Contract Integration Tests ────────────────────────

class TestDeployDuesContract:
    @pytest.fixture
    async def deploy_setup(self, monkeypatch, tmp_path):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)
        wallet = await cardano_license.generate_wallet("authority", "dues_auth")
        lic_id = await cardano_license_core._store_license_record(
            "LICDUES", "aa" * 28, wallet["base_address"], wallet["base_address"],
            SAMPLE_LICENSE_METADATA, "tx_lic",
        )
        return {"wallet": wallet, "license_id": lic_id, "tmp_path": tmp_path}

    @pytest.mark.asyncio
    async def test_deploy_success(self, deploy_setup):
        result = await cardano_license.deploy_dues_contract(
            authority_wallet_label="dues_auth",
            license_ref=deploy_setup["license_id"],
            annual_dues_lovelace=50_000_000,
        )

        assert result["contract_id"] > 0
        assert result["annual_dues_lovelace"] == 50_000_000
        assert result["license_ref"] == deploy_setup["license_id"]
        assert len(result["script_hash"]) == 56
        assert result["contract_address"].startswith("addr_test1")
        assert result["authority_address"] == deploy_setup["wallet"]["base_address"]

    @pytest.mark.asyncio
    async def test_deploy_saves_to_disk(self, deploy_setup):
        result = await cardano_license.deploy_dues_contract(
            "dues_auth", deploy_setup["license_id"], 50_000_000,
        )
        tmp_path = deploy_setup["tmp_path"]
        label = f"lic_{deploy_setup['license_id']}"
        assert (tmp_path / f"dues_{label}.json").exists()
        assert (tmp_path / f"dues_{label}.cbor").exists()

    @pytest.mark.asyncio
    async def test_deploy_stores_db_record(self, deploy_setup):
        result = await cardano_license.deploy_dues_contract(
            "dues_auth", deploy_setup["license_id"], 50_000_000,
        )
        rec = await cardano_license.get_dues_contract(result["contract_id"])
        assert rec is not None
        assert rec["status"] == "active"
        assert rec["annual_dues_lovelace"] == 50_000_000

    @pytest.mark.asyncio
    async def test_deploy_license_not_found(self, deploy_setup):
        with pytest.raises(ValueError, match="License not found"):
            await cardano_license.deploy_dues_contract(
                "dues_auth", 99999, 50_000_000,
            )

    @pytest.mark.asyncio
    async def test_deploy_wallet_not_found(self, deploy_setup):
        with pytest.raises(FileNotFoundError):
            await cardano_license.deploy_dues_contract(
                "nonexistent_wallet", deploy_setup["license_id"], 50_000_000,
            )

    @pytest.mark.asyncio
    async def test_deploy_custom_grace_period(self, deploy_setup):
        result = await cardano_license.deploy_dues_contract(
            "dues_auth", deploy_setup["license_id"], 25_000_000,
            grace_period_slots=43200,
        )
        assert result["grace_period_slots"] == 43200


# ── Pay Dues Tests ────────────────────────────────────────────────

class TestPayDues:
    @pytest.fixture
    async def payment_setup(self):
        wallet = await cardano_license.generate_wallet(
            "authority", "pay_auth", save_keys=False
        )
        addr = wallet["base_address"]
        lic_id = await cardano_license_core._store_license_record(
            "LICPAY", "aa" * 28, addr, addr, SAMPLE_LICENSE_METADATA, "tx_lic",
        )
        cid = await cardano_license_core._store_dues_contract(
            authority_address=addr,
            authority_pkh=wallet["payment_key_hash"],
            license_ref=lic_id,
            annual_dues_lovelace=50_000_000,
            grace_period_slots=86400,
            policy_id="cc" * 28,
            script_hash="cc" * 28,
            contract_address="addr_test1qzcontract",
            script_cbor_hex="ff" * 20,
        )
        return {
            "contract_id": cid,
            "license_id": lic_id,
            "authority_address": addr,
        }

    @pytest.mark.asyncio
    async def test_pay_dues_success(self, payment_setup):
        result = await cardano_license.pay_dues(
            contract_id=payment_setup["contract_id"],
            payer_address="addr_test1qzpayer",
            payment_lovelace=50_000_000,
            new_expiry="2027-01-01",
            payment_tx_hash="ab" * 32,
        )
        assert result["payment_id"] > 0
        assert result["status"] == "confirmed"
        assert result["amount_lovelace"] == 50_000_000
        assert result["new_expiry"] == "2027-01-01"
        assert result["payment_tx_hash"] == "ab" * 32

    @pytest.mark.asyncio
    async def test_pay_dues_pending_no_tx_hash(self, payment_setup):
        result = await cardano_license.pay_dues(
            contract_id=payment_setup["contract_id"],
            payer_address="addr_test1qzpayer",
            payment_lovelace=50_000_000,
            new_expiry="2027-01-01",
        )
        assert result["status"] == "pending"

    @pytest.mark.asyncio
    async def test_pay_dues_insufficient_amount(self, payment_setup):
        with pytest.raises(ValueError, match="Payment validation failed"):
            await cardano_license.pay_dues(
                contract_id=payment_setup["contract_id"],
                payer_address="addr_test1qzpayer",
                payment_lovelace=1_000_000,  # way less than 50M
                new_expiry="2027-01-01",
            )

    @pytest.mark.asyncio
    async def test_pay_dues_contract_not_found(self):
        with pytest.raises(ValueError, match="Dues contract not found"):
            await cardano_license.pay_dues(
                contract_id=99999,
                payer_address="addr_test1qzpayer",
                payment_lovelace=50_000_000,
                new_expiry="2027-01-01",
            )

    @pytest.mark.asyncio
    async def test_pay_dues_suspended_contract(self, payment_setup):
        # Suspend the contract
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE dues_contracts SET status = 'suspended' WHERE id = ?",
                (payment_setup["contract_id"],),
            )
            await db.commit()

        with pytest.raises(ValueError, match="not active"):
            await cardano_license.pay_dues(
                contract_id=payment_setup["contract_id"],
                payer_address="addr_test1qzpayer",
                payment_lovelace=50_000_000,
                new_expiry="2027-01-01",
            )

    @pytest.mark.asyncio
    async def test_pay_dues_records_payment(self, payment_setup):
        result = await cardano_license.pay_dues(
            contract_id=payment_setup["contract_id"],
            payer_address="addr_test1qzpayer",
            payment_lovelace=75_000_000,
            new_expiry="2027-06-01",
            payment_tx_hash="cd" * 32,
        )

        payments = await cardano_license.list_dues_payments(
            contract_id=payment_setup["contract_id"]
        )
        assert len(payments) == 1
        assert payments[0]["amount_lovelace"] == 75_000_000
        assert payments[0]["status"] == "confirmed"
        assert payments[0]["new_expiry"] == "2027-06-01"


# ── List Dues Payments Tests ──────────────────────────────────────

class TestListDuesPayments:
    @pytest.mark.asyncio
    async def test_list_all_payments(self):
        await cardano_license_core._store_dues_payment(1, "addr1", 50_000_000, "tx1", "2027-01-01", "confirmed")
        await cardano_license_core._store_dues_payment(1, "addr2", 50_000_000, "tx2", "2027-06-01", "pending")

        payments = await cardano_license.list_dues_payments()
        assert len(payments) == 2

    @pytest.mark.asyncio
    async def test_list_payments_by_contract(self):
        await cardano_license_core._store_dues_payment(1, "addr1", 50_000_000, "tx1", "2027-01-01", "confirmed")
        await cardano_license_core._store_dues_payment(2, "addr2", 50_000_000, "tx2", "2027-06-01", "confirmed")

        payments = await cardano_license.list_dues_payments(contract_id=1)
        assert len(payments) == 1
        assert payments[0]["contract_id"] == 1

    @pytest.mark.asyncio
    async def test_list_payments_by_payer(self):
        await cardano_license_core._store_dues_payment(1, "addr_target", 50_000_000, "tx1", "2027-01-01", "confirmed")
        await cardano_license_core._store_dues_payment(1, "addr_other", 50_000_000, "tx2", "2027-06-01", "confirmed")

        payments = await cardano_license.list_dues_payments(payer_address="addr_target")
        assert len(payments) == 1

    @pytest.mark.asyncio
    async def test_list_payments_by_status(self):
        await cardano_license_core._store_dues_payment(1, "addr1", 50_000_000, "tx1", "2027-01-01", "confirmed")
        await cardano_license_core._store_dues_payment(1, "addr2", 50_000_000, None, "2027-06-01", "pending")

        confirmed = await cardano_license.list_dues_payments(status="confirmed")
        assert len(confirmed) == 1
        assert confirmed[0]["status"] == "confirmed"


# ── Revoke Dues Validity Tests ────────────────────────────────────

class TestRevokeDuesValidity:
    @pytest.fixture
    async def revoke_setup(self):
        wallet = await cardano_license.generate_wallet(
            "authority", "revoke_auth", save_keys=False
        )
        addr = wallet["base_address"]
        lic_id = await cardano_license_core._store_license_record(
            "LICREV", "aa" * 28, addr, addr, SAMPLE_LICENSE_METADATA, "tx_lic",
        )
        # Create an active validity token
        await cardano_license_core._store_validity_token_record(
            policy_id="bb" * 28,
            token_name="VAL1_0",
            licensee_address=addr,
            license_ref=lic_id,
            valid_until="2028-01-01",
            mint_tx_hash="cc" * 32,
        )
        cid = await cardano_license_core._store_dues_contract(
            authority_address=addr,
            authority_pkh=wallet["payment_key_hash"],
            license_ref=lic_id,
            annual_dues_lovelace=50_000_000,
            grace_period_slots=86400,
            policy_id="dd" * 28,
            script_hash="dd" * 28,
            contract_address="addr_test1qzcontract",
            script_cbor_hex="ff" * 20,
        )
        return {
            "contract_id": cid,
            "license_id": lic_id,
            "licensee_address": addr,
        }

    @pytest.mark.asyncio
    async def test_revoke_success(self, revoke_setup):
        result = await cardano_license.revoke_dues_validity(
            revoke_setup["contract_id"],
            reason="non_payment",
        )
        assert result["status"] == "suspended"
        assert result["reason"] == "non_payment"
        assert result["license_ref"] == revoke_setup["license_id"]

    @pytest.mark.asyncio
    async def test_revoke_suspends_contract(self, revoke_setup):
        await cardano_license.revoke_dues_validity(revoke_setup["contract_id"])
        rec = await cardano_license.get_dues_contract(revoke_setup["contract_id"])
        assert rec["status"] == "suspended"

    @pytest.mark.asyncio
    async def test_revoke_expires_validity_tokens(self, revoke_setup):
        await cardano_license.revoke_dues_validity(revoke_setup["contract_id"])

        tokens = await cardano_license.list_validity_tokens(
            licensee_address=revoke_setup["licensee_address"],
            license_ref=revoke_setup["license_id"],
        )
        for t in tokens:
            assert t["status"] == "expired"

    @pytest.mark.asyncio
    async def test_revoke_default_reason(self, revoke_setup):
        result = await cardano_license.revoke_dues_validity(
            revoke_setup["contract_id"]
        )
        assert result["reason"] == "authority_revocation"

    @pytest.mark.asyncio
    async def test_revoke_contract_not_found(self):
        with pytest.raises(ValueError, match="Dues contract not found"):
            await cardano_license.revoke_dues_validity(99999)


# ── Get Dues Status Tests ─────────────────────────────────────────

class TestGetDuesStatus:
    @pytest.mark.asyncio
    async def test_status_no_contract(self):
        status = await cardano_license.get_dues_status(99999)
        assert status["has_dues_contract"] is False
        assert status["contract"] is None
        assert status["payments"] == []
        assert status["total_paid"] == 0

    @pytest.mark.asyncio
    async def test_status_with_contract(self):
        cid = await cardano_license_core._store_dues_contract(
            "addr_auth", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_contract", "ff" * 20,
        )
        status = await cardano_license.get_dues_status(1)
        assert status["has_dues_contract"] is True
        assert status["contract_id"] == cid
        assert status["annual_dues_lovelace"] == 50_000_000
        assert status["annual_dues_ada"] == 50.0
        assert status["total_payments"] == 0
        assert status["total_paid_lovelace"] == 0

    @pytest.mark.asyncio
    async def test_status_with_payments(self):
        cid = await cardano_license_core._store_dues_contract(
            "addr_auth", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_contract", "ff" * 20,
        )
        await cardano_license_core._store_dues_payment(
            cid, "addr_payer", 50_000_000, "tx1", "2027-01-01", "confirmed",
        )
        await cardano_license_core._store_dues_payment(
            cid, "addr_payer", 50_000_000, "tx2", "2028-01-01", "confirmed",
        )

        status = await cardano_license.get_dues_status(1)
        assert status["total_payments"] == 2
        assert status["total_paid_lovelace"] == 100_000_000
        assert status["total_paid_ada"] == 100.0
        assert status["latest_expiry"] == "2028-01-01"

    @pytest.mark.asyncio
    async def test_status_excludes_pending_from_total(self):
        cid = await cardano_license_core._store_dues_contract(
            "addr_auth", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_contract", "ff" * 20,
        )
        await cardano_license_core._store_dues_payment(
            cid, "addr_payer", 50_000_000, "tx1", "2027-01-01", "confirmed",
        )
        await cardano_license_core._store_dues_payment(
            cid, "addr_payer", 50_000_000, None, "2028-01-01", "pending",
        )

        status = await cardano_license.get_dues_status(1)
        assert status["total_payments"] == 1  # only confirmed
        assert status["total_paid_lovelace"] == 50_000_000


# ── Status Tests with Dues ────────────────────────────────────────

class TestStatusWithDues:
    @pytest.mark.asyncio
    async def test_status_includes_dues_count(self):
        status = await cardano_license.get_cardano_status()
        assert "dues_contract_count" in status
        assert status["dues_contract_count"] == 0

    @pytest.mark.asyncio
    async def test_status_counts_dues_contracts(self):
        await cardano_license_core._store_dues_contract(
            "addr1", _make_dues_pkh(1), 1, 50_000_000, 86400,
            "aa" * 28, "aa" * 28, "addr_c1", "ff" * 20,
        )
        await cardano_license_core._store_dues_contract(
            "addr2", _make_dues_pkh(2), 2, 100_000_000, 86400,
            "bb" * 28, "bb" * 28, "addr_c2", "ee" * 20,
        )

        status = await cardano_license.get_cardano_status()
        assert status["dues_contract_count"] == 2


# ── Dues End-to-End Workflow Test ─────────────────────────────────

class TestDuesEndToEnd:
    @pytest.mark.asyncio
    async def test_full_dues_lifecycle(self, monkeypatch, tmp_path):
        monkeypatch.setattr("cardano_license.core.POLICY_DIR", tmp_path)

        # Step 1: Create authority wallet
        wallet = await cardano_license.generate_wallet("authority", "e2e_dues_auth")
        addr = wallet["base_address"]

        # Step 2: Create license
        lic_id = await cardano_license_core._store_license_record(
            "LICE2E", "aa" * 28, addr, addr, SAMPLE_LICENSE_METADATA, "tx_lic",
        )

        # Step 3: Deploy dues contract
        deploy_result = await cardano_license.deploy_dues_contract(
            authority_wallet_label="e2e_dues_auth",
            license_ref=lic_id,
            annual_dues_lovelace=50_000_000,
            grace_period_slots=43200,
        )
        contract_id = deploy_result["contract_id"]
        assert contract_id > 0

        # Step 4: Check status before payment
        status_before = await cardano_license.get_dues_status(lic_id)
        assert status_before["has_dues_contract"] is True
        assert status_before["total_payments"] == 0

        # Step 5: Pay dues
        pay_result = await cardano_license.pay_dues(
            contract_id=contract_id,
            payer_address=addr,
            payment_lovelace=50_000_000,
            new_expiry="2027-06-01",
            payment_tx_hash="ab" * 32,
        )
        assert pay_result["status"] == "confirmed"

        # Step 6: Verify payment recorded
        status_after = await cardano_license.get_dues_status(lic_id)
        assert status_after["total_payments"] == 1
        assert status_after["total_paid_lovelace"] == 50_000_000
        assert status_after["latest_expiry"] == "2027-06-01"

        # Step 7: Make second payment (renewal)
        await cardano_license.pay_dues(
            contract_id=contract_id,
            payer_address=addr,
            payment_lovelace=50_000_000,
            new_expiry="2028-06-01",
            payment_tx_hash="cd" * 32,
        )
        status_renewed = await cardano_license.get_dues_status(lic_id)
        assert status_renewed["total_payments"] == 2
        assert status_renewed["latest_expiry"] == "2028-06-01"

        # Step 8: Revoke dues validity
        revoke_result = await cardano_license.revoke_dues_validity(
            contract_id, reason="non_compliance",
        )
        assert revoke_result["status"] == "suspended"

        # Step 9: Contract should be suspended
        rec = await cardano_license.get_dues_contract(contract_id)
        assert rec["status"] == "suspended"

        # Step 10: Cannot pay on suspended contract
        with pytest.raises(ValueError, match="not active"):
            await cardano_license.pay_dues(
                contract_id=contract_id,
                payer_address=addr,
                payment_lovelace=50_000_000,
                new_expiry="2029-01-01",
            )
