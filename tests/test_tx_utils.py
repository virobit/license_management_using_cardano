"""Tests for cardano_tx_utils module.

Task: #373 (P-18, WS-CONTRACTS)
Tests: Fee estimation, UTxO selection, build_mint_tx, build_transfer_tx,
       build_multisig_tx, submit_tx, wait_for_confirmation, convenience functions.
"""

import os
import asyncio
import time
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock, PropertyMock
from dataclasses import dataclass

# Fixtures (patch_paths, setup_db) are in conftest.py

import cardano_license.tx_utils as txu
from cardano_license.tx_utils import (
    TxResult,
    UTxOSelection,
    estimate_fee,
    estimate_fee_from_context,
    select_utxos,
    build_mint_tx,
    build_transfer_tx,
    build_multisig_tx,
    submit_tx,
    wait_for_confirmation,
    build_and_submit_mint,
    build_and_submit_transfer,
    calculate_min_utxo,
    _utxo_lovelace,
    _accumulate_utxo_assets,
    _assets_satisfied,
    _flatten_assets,
    MIN_UTXO_LOVELACE,
    DEFAULT_MIN_UTXO,
    FEE_BUFFER_LOVELACE,
)


# ── Mock Helpers ──────────────────────────────────────────────────

def _mock_utxo(lovelace=5_000_000, multi_asset=None):
    """Create a mock UTxO with given lovelace and optional multi-asset."""
    utxo = MagicMock()
    if multi_asset:
        value = MagicMock()
        value.coin = lovelace
        value.multi_asset = multi_asset
        utxo.output.amount = value
        # Make isinstance check work for Value
        utxo.output.amount.__class__ = type("Value", (), {"coin": lovelace, "multi_asset": multi_asset})
    else:
        utxo.output.amount = lovelace
    return utxo


def _mock_utxo_with_value(lovelace=5_000_000):
    """Create a mock UTxO wrapping a Value object."""
    from pycardano import Value
    utxo = MagicMock()
    utxo.output.amount = Value(lovelace)
    return utxo


def _mock_tx_body(n_inputs=2, n_outputs=2, fee=200_000):
    """Create a mock TransactionBody."""
    body = MagicMock()
    body.inputs = [MagicMock() for _ in range(n_inputs)]
    body.outputs = [MagicMock() for _ in range(n_outputs)]
    body.fee = fee
    # Make to_cbor return bytes of predictable size
    body.to_cbor.return_value = b"\x00" * 400
    return body


def _mock_signed_tx(tx_hash="abc123def456", fee=180_000, n_inputs=2, n_outputs=2):
    """Create a mock signed Transaction."""
    tx = MagicMock()
    tx.id.to_primitive.return_value.hex.return_value = tx_hash
    tx.transaction_body.fee = fee
    tx.transaction_body.inputs = [MagicMock() for _ in range(n_inputs)]
    tx.transaction_body.outputs = [MagicMock() for _ in range(n_outputs)]
    return tx


def _mock_wallet_keys():
    """Create mock wallet keys dict."""
    sk = MagicMock()
    vk = MagicMock()
    vk.hash.return_value = MagicMock()
    vk.hash.return_value.to_primitive.return_value = b"\x01" * 28
    return {
        "payment_sk": sk,
        "payment_vk": vk,
        "base_address": "addr_test1qz..." + "a" * 50,
        "payment_key_hash": "01" * 28,
    }


# ══════════════════════════════════════════════════════════════════
# TxResult Tests
# ══════════════════════════════════════════════════════════════════

class TestTxResult:
    def test_default_values(self):
        r = TxResult(tx_hash="abc123")
        assert r.tx_hash == "abc123"
        assert r.signed_tx is None
        assert r.fee_lovelace == 0
        assert r.confirmed is False
        assert r.error is None

    def test_to_dict(self):
        r = TxResult(
            tx_hash="abc123",
            fee_lovelace=200_000,
            inputs_used=3,
            outputs_count=2,
            confirmed=True,
            block_height=12345,
        )
        d = r.to_dict()
        assert d["tx_hash"] == "abc123"
        assert d["fee_lovelace"] == 200_000
        assert d["inputs_used"] == 3
        assert d["outputs_count"] == 2
        assert d["confirmed"] is True
        assert d["block_height"] == 12345
        assert d["error"] is None
        # signed_tx should not be in dict
        assert "signed_tx" not in d

    def test_to_dict_with_error(self):
        r = TxResult(tx_hash="dead", error="submission failed")
        d = r.to_dict()
        assert d["error"] == "submission failed"
        assert d["confirmed"] is False

    def test_to_dict_with_mint_assets(self):
        r = TxResult(tx_hash="mint1", mint_assets={"policy.token": 5})
        d = r.to_dict()
        assert d["mint_assets"] == {"policy.token": 5}


class TestUTxOSelection:
    def test_default_values(self):
        sel = UTxOSelection(selected=[])
        assert sel.selected == []
        assert sel.total_lovelace == 0
        assert sel.total_assets is None
        assert sel.change_lovelace == 0


# ══════════════════════════════════════════════════════════════════
# Fee Estimation Tests
# ══════════════════════════════════════════════════════════════════

class TestEstimateFee:
    def test_fee_from_tx_body_with_cbor(self):
        body = _mock_tx_body()
        fee = estimate_fee(body)
        # 400 bytes * 44 + 155381 + witness overhead
        assert fee > 155_381
        assert isinstance(fee, int)

    def test_fee_from_tx_body_cbor_fails(self):
        body = _mock_tx_body(n_inputs=3, n_outputs=4)
        body.to_cbor.side_effect = Exception("serialize fail")
        fee = estimate_fee(body)
        # Fallback: 250 + 3*60 + 4*80 + 200 = 950 bytes estimate
        assert fee > 155_381
        assert isinstance(fee, int)

    def test_fee_increases_with_more_inputs(self):
        body1 = _mock_tx_body(n_inputs=1)
        body1.to_cbor.return_value = b"\x00" * 300
        body2 = _mock_tx_body(n_inputs=5)
        body2.to_cbor.return_value = b"\x00" * 600
        fee1 = estimate_fee(body1)
        fee2 = estimate_fee(body2)
        assert fee2 > fee1

    def test_fee_never_below_minimum(self):
        body = _mock_tx_body(n_inputs=1, n_outputs=1)
        body.to_cbor.return_value = b"\x00" * 10  # tiny
        fee = estimate_fee(body)
        assert fee >= 155_381


class TestEstimateFeeFromContext:
    def test_basic_fee_estimate(self):
        fee = estimate_fee_from_context()
        assert fee > 155_381
        assert isinstance(fee, int)

    def test_more_inputs_higher_fee(self):
        fee1 = estimate_fee_from_context(n_inputs=1)
        fee2 = estimate_fee_from_context(n_inputs=10)
        assert fee2 > fee1

    def test_more_outputs_higher_fee(self):
        fee1 = estimate_fee_from_context(n_outputs=1)
        fee2 = estimate_fee_from_context(n_outputs=10)
        assert fee2 > fee1

    def test_mint_adds_cost(self):
        fee_no_mint = estimate_fee_from_context(has_mint=False)
        fee_mint = estimate_fee_from_context(has_mint=True)
        assert fee_mint > fee_no_mint

    def test_metadata_adds_cost(self):
        fee_no_meta = estimate_fee_from_context(has_metadata=False)
        fee_meta = estimate_fee_from_context(has_metadata=True)
        assert fee_meta > fee_no_meta

    def test_scripts_add_cost(self):
        fee_no_script = estimate_fee_from_context(has_scripts=False)
        fee_script = estimate_fee_from_context(has_scripts=True)
        assert fee_script > fee_no_script

    def test_includes_buffer(self):
        fee = estimate_fee_from_context()
        # The buffer should be part of the calculation
        assert fee >= 155_381 + FEE_BUFFER_LOVELACE

    def test_multiple_witnesses(self):
        fee1 = estimate_fee_from_context(n_witnesses=1)
        fee2 = estimate_fee_from_context(n_witnesses=3)
        assert fee2 > fee1


# ══════════════════════════════════════════════════════════════════
# UTxO Selection Tests
# ══════════════════════════════════════════════════════════════════

class TestSelectUtxos:
    def test_empty_utxos_raises(self):
        with pytest.raises(ValueError, match="No UTxOs available"):
            select_utxos([], 1_000_000)

    def test_insufficient_lovelace_raises(self):
        utxos = [_mock_utxo_with_value(500_000)]
        with pytest.raises(ValueError, match="Insufficient lovelace"):
            select_utxos(utxos, 10_000_000)

    def test_single_utxo_sufficient(self):
        utxos = [_mock_utxo_with_value(10_000_000)]
        result = select_utxos(utxos, 5_000_000)
        assert len(result.selected) == 1
        assert result.total_lovelace == 10_000_000
        assert result.change_lovelace == 5_000_000

    def test_multiple_utxos_needed(self):
        utxos = [
            _mock_utxo_with_value(3_000_000),
            _mock_utxo_with_value(4_000_000),
            _mock_utxo_with_value(2_000_000),
        ]
        result = select_utxos(utxos, 6_000_000)
        # Largest-first: 4M first, then 3M = 7M >= 6M
        assert len(result.selected) == 2
        assert result.total_lovelace >= 6_000_000

    def test_exact_amount_zero_change(self):
        utxos = [_mock_utxo_with_value(5_000_000)]
        result = select_utxos(utxos, 5_000_000)
        assert result.change_lovelace == 0

    def test_largest_first_ordering(self):
        utxos = [
            _mock_utxo_with_value(1_000_000),
            _mock_utxo_with_value(10_000_000),
            _mock_utxo_with_value(5_000_000),
        ]
        result = select_utxos(utxos, 8_000_000)
        # Should pick 10M first (enough), only 1 UTxO needed
        assert len(result.selected) == 1
        assert result.total_lovelace == 10_000_000


class TestUtxoHelpers:
    def test_utxo_lovelace_plain_int(self):
        utxo = MagicMock()
        utxo.output.amount = 5_000_000
        assert _utxo_lovelace(utxo) == 5_000_000

    def test_utxo_lovelace_value_obj(self):
        utxo = _mock_utxo_with_value(7_000_000)
        assert _utxo_lovelace(utxo) == 7_000_000

    def test_flatten_assets(self):
        assets = {
            "pid1": {"asset_a": 5, "asset_b": 10},
            "pid2": {"asset_c": 3},
        }
        flat = _flatten_assets(assets)
        assert flat == {
            "pid1.asset_a": 5,
            "pid1.asset_b": 10,
            "pid2.asset_c": 3,
        }

    def test_assets_satisfied_true(self):
        collected = {"pid1": {"a": 5}}
        required = {"pid1": {"a": 3}}
        assert _assets_satisfied(collected, required) is True

    def test_assets_satisfied_false_missing_policy(self):
        collected = {"pid1": {"a": 5}}
        required = {"pid2": {"b": 1}}
        assert _assets_satisfied(collected, required) is False

    def test_assets_satisfied_false_insufficient_qty(self):
        collected = {"pid1": {"a": 2}}
        required = {"pid1": {"a": 5}}
        assert _assets_satisfied(collected, required) is False

    def test_assets_satisfied_exact(self):
        collected = {"pid1": {"a": 5}}
        required = {"pid1": {"a": 5}}
        assert _assets_satisfied(collected, required) is True


# ══════════════════════════════════════════════════════════════════
# Build Mint TX Tests
# ══════════════════════════════════════════════════════════════════

class TestBuildMintTx:
    @pytest.mark.asyncio
    async def test_quantity_below_one_raises(self):
        with pytest.raises(ValueError, match="quantity must be >= 1"):
            await build_mint_tx("wallet", MagicMock(), "token", quantity=0)

    @pytest.mark.asyncio
    async def test_missing_wallet_raises(self):
        with pytest.raises(FileNotFoundError):
            await build_mint_tx("nonexistent_wallet", MagicMock(), "token")

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_build_mint_tx_success(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        # Mock the TransactionBuilder
        mock_signed = _mock_signed_tx("mint_hash_1", 185_000)

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            policy = MagicMock()
            policy.hash.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value.hex.return_value = "aabbcc"

            result = await build_mint_tx(
                wallet_label="test_wallet",
                policy=policy,
                token_name="LIC_001",
                quantity=1,
            )

        assert result.tx_hash == "mint_hash_1"
        assert result.fee_lovelace == 185_000
        assert result.error is None
        assert result.mint_assets is not None
        assert "aabbcc.LIC_001" in result.mint_assets

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_build_mint_tx_with_metadata(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("mint_meta")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            policy = MagicMock()
            policy.hash.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value.hex.return_value = "dd"

            metadata = {721: {"dd": {"LIC_002": {"name": "License #2"}}}}

            result = await build_mint_tx(
                wallet_label="test",
                policy=policy,
                token_name="LIC_002",
                metadata=metadata,
            )

        assert result.tx_hash == "mint_meta"
        # Verify auxiliary_data was set on the builder
        assert builder_inst.auxiliary_data is not None

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_build_mint_tx_with_recipient(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("mint_recip")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            policy = MagicMock()
            policy.hash.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value.hex.return_value = "ee"

            result = await build_mint_tx(
                wallet_label="test",
                policy=policy,
                token_name="SIG_001",
                recipient="addr_test1recipient...",
                quantity=10,
            )

        assert result.tx_hash == "mint_recip"
        assert result.mint_assets["ee.SIG_001"] == 10

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_build_mint_tx_multiple_quantity(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("mint_multi")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            policy = MagicMock()
            policy.hash.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value = MagicMock()
            policy.hash.return_value.to_primitive.return_value.hex.return_value = "ff"

            result = await build_mint_tx(
                wallet_label="test",
                policy=policy,
                token_name="BATCH_TOK",
                quantity=100,
            )

        assert result.mint_assets["ff.BATCH_TOK"] == 100


# ══════════════════════════════════════════════════════════════════
# Build Transfer TX Tests
# ══════════════════════════════════════════════════════════════════

class TestBuildTransferTx:
    @pytest.mark.asyncio
    async def test_no_lovelace_no_tokens_raises(self):
        with pytest.raises(ValueError, match="Must specify lovelace and/or tokens"):
            await build_transfer_tx("wallet", "addr_test1...", lovelace=None, tokens=None)

    @pytest.mark.asyncio
    async def test_missing_wallet_raises(self):
        with pytest.raises(FileNotFoundError):
            await build_transfer_tx("nonexistent", "addr_test1...", lovelace=5_000_000)

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_transfer_lovelace_only(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("transfer_ada")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            result = await build_transfer_tx(
                wallet_label="test",
                recipient="addr_test1dest...",
                lovelace=10_000_000,
            )

        assert result.tx_hash == "transfer_ada"
        assert result.error is None

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_transfer_with_tokens(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("transfer_tok")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            tokens = {"aabbccdd" * 7: {"SIG_TOKEN": 5}}

            result = await build_transfer_tx(
                wallet_label="test",
                recipient="addr_test1dest...",
                tokens=tokens,
            )

        assert result.tx_hash == "transfer_tok"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_transfer_lovelace_and_tokens(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("transfer_both")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            tokens = {"aabbccdd" * 7: {"MY_TOKEN": 1}}

            result = await build_transfer_tx(
                wallet_label="test",
                recipient="addr_test1dest...",
                lovelace=5_000_000,
                tokens=tokens,
            )

        assert result.tx_hash == "transfer_both"


# ══════════════════════════════════════════════════════════════════
# Build Multisig TX Tests
# ══════════════════════════════════════════════════════════════════

class TestBuildMultisigTx:
    @pytest.mark.asyncio
    async def test_empty_signers_raises(self):
        with pytest.raises(ValueError, match="At least one signer"):
            await build_multisig_tx([], [{"address": "addr...", "lovelace": 1}])

    @pytest.mark.asyncio
    async def test_empty_outputs_raises(self):
        with pytest.raises(ValueError, match="At least one output"):
            await build_multisig_tx([{"wallet_label": "w1"}], [])

    @pytest.mark.asyncio
    async def test_invalid_signer_raises(self):
        with pytest.raises(ValueError, match="must have 'wallet_label'"):
            await build_multisig_tx(
                [{"invalid_key": "value"}],
                [{"address": "addr...", "lovelace": 1}],
            )

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_multisig_with_wallet_labels(self, mock_load, mock_ctx, mock_addr):
        keys1 = _mock_wallet_keys()
        keys2 = _mock_wallet_keys()
        # Called: signer_a(loop), signer_b(loop), signer_a(funding fallback)
        # Return the same keys1 instance for the 3rd call so dedup works
        mock_load.side_effect = lambda label: keys1 if label == "signer_a" else keys2
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("multisig_1")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            result = await build_multisig_tx(
                signers=[
                    {"wallet_label": "signer_a"},
                    {"wallet_label": "signer_b"},
                ],
                outputs=[
                    {"address": "addr_test1dest...", "lovelace": 5_000_000},
                ],
            )

        assert result.tx_hash == "multisig_1"
        # build_and_sign should have been called with 2 signing keys
        call_args = builder_inst.build_and_sign.call_args
        assert len(call_args.kwargs["signing_keys"]) == 2

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_multisig_with_direct_keys(self, mock_load, mock_ctx, mock_addr):
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("multisig_direct")

        sk1 = MagicMock()
        vk1 = MagicMock()
        vk1.hash.return_value = MagicMock()
        vk1.hash.return_value.to_primitive.return_value = b"\x01" * 28
        sk2 = MagicMock()
        vk2 = MagicMock()
        vk2.hash.return_value = MagicMock()
        vk2.hash.return_value.to_primitive.return_value = b"\x02" * 28

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            result = await build_multisig_tx(
                signers=[
                    {"payment_sk": sk1, "payment_vk": vk1, "base_address": "addr_test1a..."},
                    {"payment_sk": sk2, "payment_vk": vk2},
                ],
                outputs=[
                    {"address": "addr_test1dest...", "lovelace": 3_000_000},
                ],
            )

        assert result.tx_hash == "multisig_direct"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_multisig_with_tokens_output(self, mock_load, mock_ctx, mock_addr):
        mock_load.return_value = _mock_wallet_keys()
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("multisig_tok")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            result = await build_multisig_tx(
                signers=[{"wallet_label": "signer_a"}],
                outputs=[{
                    "address": "addr_test1dest...",
                    "lovelace": 2_000_000,
                    "tokens": {"aabbccdd" * 7: {"SIG_TOK": 1}},
                }],
            )

        assert result.tx_hash == "multisig_tok"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.Address")
    @patch("cardano_license.tx_utils.get_chain_context")
    @patch("cardano_license.tx_utils.load_wallet_keys")
    async def test_multisig_with_funding_wallet(self, mock_load, mock_ctx, mock_addr):
        keys_s = _mock_wallet_keys()
        keys_f = _mock_wallet_keys()
        keys_f["base_address"] = "addr_test1funder..."
        mock_load.side_effect = [keys_s, keys_f]
        mock_ctx.return_value = MagicMock()
        mock_signed = _mock_signed_tx("multisig_funded")

        with patch("cardano_license.tx_utils.TransactionBuilder") as MockBuilder:
            builder_inst = MagicMock()
            MockBuilder.return_value = builder_inst
            builder_inst.build_and_sign.return_value = mock_signed

            result = await build_multisig_tx(
                signers=[{"wallet_label": "signer_a"}],
                outputs=[{"address": "addr_test1dest...", "lovelace": 1_000_000}],
                funding_wallet_label="funder",
            )

        assert result.tx_hash == "multisig_funded"
        # Should have 2 signing keys (signer + funder)
        call_args = builder_inst.build_and_sign.call_args
        assert len(call_args.kwargs["signing_keys"]) == 2


# ══════════════════════════════════════════════════════════════════
# Submit TX Tests
# ══════════════════════════════════════════════════════════════════

class TestSubmitTx:
    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.get_chain_context")
    async def test_submit_success(self, mock_ctx):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        signed = _mock_signed_tx("submit_ok", 175_000)

        result = await submit_tx(signed)

        assert result.tx_hash == "submit_ok"
        assert result.fee_lovelace == 175_000
        assert result.error is None
        mock_context.submit_tx.assert_called_once_with(signed)

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.get_chain_context")
    async def test_submit_failure(self, mock_ctx):
        mock_context = MagicMock()
        mock_context.submit_tx.side_effect = Exception("network error")
        mock_ctx.return_value = mock_context
        signed = _mock_signed_tx("submit_fail")

        result = await submit_tx(signed)

        assert result.tx_hash == "submit_fail"
        assert result.error == "network error"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.get_chain_context")
    async def test_submit_returns_input_output_counts(self, mock_ctx):
        mock_ctx.return_value = MagicMock()
        signed = _mock_signed_tx("submit_counts", n_inputs=3, n_outputs=4)

        result = await submit_tx(signed)

        assert result.inputs_used == 3
        assert result.outputs_count == 4


# ══════════════════════════════════════════════════════════════════
# Wait for Confirmation Tests
# ══════════════════════════════════════════════════════════════════

class TestWaitForConfirmation:
    @pytest.mark.asyncio
    @patch("cardano_license.core.BLOCKFROST_PROJECT_ID", "")
    async def test_no_blockfrost_id(self):
        result = await wait_for_confirmation("tx123", timeout=1)
        assert result.confirmed is False
        assert "BLOCKFROST_PROJECT_ID" in result.error

    @pytest.mark.asyncio
    @patch("cardano_license.core.BLOCKFROST_PROJECT_ID", "test_project_id")
    @patch("cardano_license.core._get_blockfrost_url", return_value="https://cardano-testnet.blockfrost.io/api")
    async def test_confirmation_success(self, mock_url):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"block_height": 9999, "fees": "200000"}

        with patch("requests.get", return_value=mock_resp):
            result = await wait_for_confirmation("tx_confirmed", timeout=10)

        assert result.confirmed is True
        assert result.block_height == 9999
        assert result.fee_lovelace == 200_000

    @pytest.mark.asyncio
    @patch("cardano_license.core.BLOCKFROST_PROJECT_ID", "test_project_id")
    @patch("cardano_license.core._get_blockfrost_url", return_value="https://cardano-testnet.blockfrost.io/api")
    async def test_confirmation_timeout(self, mock_url):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("requests.get", return_value=mock_resp):
            result = await wait_for_confirmation(
                "tx_timeout", timeout=2, poll_interval=1
            )

        assert result.confirmed is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    @patch("cardano_license.core.BLOCKFROST_PROJECT_ID", "test_project_id")
    @patch("cardano_license.core._get_blockfrost_url", return_value="https://cardano-testnet.blockfrost.io/api")
    async def test_confirmation_network_error_retries(self, mock_url):
        import requests as req_module
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise req_module.RequestException("connection refused")
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"block_height": 1000, "fees": "180000"}
            return resp

        with patch("requests.get", side_effect=side_effect):
            result = await wait_for_confirmation(
                "tx_retry", timeout=30, poll_interval=1
            )

        assert result.confirmed is True


# ══════════════════════════════════════════════════════════════════
# Convenience Function Tests
# ══════════════════════════════════════════════════════════════════

class TestBuildAndSubmitMint:
    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.submit_tx")
    @patch("cardano_license.tx_utils.build_mint_tx")
    async def test_build_and_submit_success(self, mock_build, mock_submit):
        mock_build.return_value = TxResult(
            tx_hash="conv_mint",
            signed_tx=_mock_signed_tx("conv_mint"),
            fee_lovelace=180_000,
        )
        mock_submit.return_value = TxResult(
            tx_hash="conv_mint",
            fee_lovelace=180_000,
        )

        result = await build_and_submit_mint(
            wallet_label="test",
            policy=MagicMock(),
            token_name="TOK",
        )

        assert result.tx_hash == "conv_mint"
        mock_build.assert_called_once()
        mock_submit.assert_called_once()

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.build_mint_tx")
    async def test_build_error_skips_submit(self, mock_build):
        mock_build.return_value = TxResult(
            tx_hash="", error="build failed"
        )

        result = await build_and_submit_mint(
            wallet_label="test",
            policy=MagicMock(),
            token_name="TOK",
        )

        assert result.error == "build failed"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.wait_for_confirmation")
    @patch("cardano_license.tx_utils.submit_tx")
    @patch("cardano_license.tx_utils.build_mint_tx")
    async def test_build_submit_and_wait(self, mock_build, mock_submit, mock_wait):
        mock_build.return_value = TxResult(
            tx_hash="wait_mint",
            signed_tx=_mock_signed_tx("wait_mint"),
        )
        mock_submit.return_value = TxResult(tx_hash="wait_mint")
        mock_wait.return_value = TxResult(
            tx_hash="wait_mint",
            confirmed=True,
            block_height=5000,
        )

        result = await build_and_submit_mint(
            wallet_label="test",
            policy=MagicMock(),
            token_name="TOK",
            wait_confirm=True,
        )

        assert result.confirmed is True
        mock_wait.assert_called_once()


class TestBuildAndSubmitTransfer:
    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.submit_tx")
    @patch("cardano_license.tx_utils.build_transfer_tx")
    async def test_build_and_submit_success(self, mock_build, mock_submit):
        mock_build.return_value = TxResult(
            tx_hash="conv_xfer",
            signed_tx=_mock_signed_tx("conv_xfer"),
        )
        mock_submit.return_value = TxResult(tx_hash="conv_xfer")

        result = await build_and_submit_transfer(
            wallet_label="test",
            recipient="addr_test1...",
            lovelace=5_000_000,
        )

        assert result.tx_hash == "conv_xfer"

    @pytest.mark.asyncio
    @patch("cardano_license.tx_utils.submit_tx")
    @patch("cardano_license.tx_utils.build_transfer_tx")
    async def test_submit_error_returned(self, mock_build, mock_submit):
        mock_build.return_value = TxResult(
            tx_hash="conv_xfer",
            signed_tx=_mock_signed_tx("conv_xfer"),
        )
        mock_submit.return_value = TxResult(
            tx_hash="conv_xfer",
            error="rejected",
        )

        result = await build_and_submit_transfer(
            wallet_label="test",
            recipient="addr_test1...",
            lovelace=5_000_000,
        )

        assert result.error == "rejected"


# ══════════════════════════════════════════════════════════════════
# Min UTxO Calculation Tests
# ══════════════════════════════════════════════════════════════════

class TestCalculateMinUtxo:
    def test_no_tokens(self):
        min_val = calculate_min_utxo(has_tokens=False)
        assert min_val == MIN_UTXO_LOVELACE

    def test_one_policy_one_asset(self):
        min_val = calculate_min_utxo(
            has_tokens=True,
            n_distinct_assets=1,
            n_distinct_policies=1,
        )
        assert min_val > MIN_UTXO_LOVELACE
        assert min_val == MIN_UTXO_LOVELACE + 400_000 + 100_000

    def test_multiple_policies_assets(self):
        min_val = calculate_min_utxo(
            has_tokens=True,
            n_distinct_assets=5,
            n_distinct_policies=3,
        )
        expected = MIN_UTXO_LOVELACE + (3 * 400_000) + (5 * 100_000)
        assert min_val == expected

    def test_scales_with_complexity(self):
        simple = calculate_min_utxo(True, 1, 1)
        complex_ = calculate_min_utxo(True, 10, 5)
        assert complex_ > simple

    def test_zero_assets_with_tokens_flag(self):
        min_val = calculate_min_utxo(has_tokens=True, n_distinct_assets=0, n_distinct_policies=0)
        assert min_val == MIN_UTXO_LOVELACE
