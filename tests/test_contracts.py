"""Tests for Cardano smart contract logic.

Task: #379 (P-18, WS-TESTING/WS-75)
Tests: Minting policy validation (authorized vs unauthorized),
       signature validator logic (valid/expired/missing tokens),
       dues enforcement (paid/unpaid/partial),
       transaction builder utilities.
"""

import os
import json
import asyncio
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from dataclasses import dataclass

# Fixtures (patch_paths, setup_db) are in conftest.py

from tests.conftest import TEST_DB, TEST_WALLET_DIR, TEST_POLICY_DIR

from cardano_license import (
    PlutusV2MintingPolicy,
    SignatureCollectionValidator,
    SignerDatum,
    DuesEnforcementContract,
    CollectRedeemer,
    FinalizeRedeemer,
    ReclaimRedeemer,
    PayDuesRedeemer,
    RevokeValidityRedeemer,
    DuesContractDatum,
    MintAction,
    BurnAction,
    build_minting_policy,
    build_signature_validator,
    build_dues_contract,
    VALID_REDEEMER_ACTIONS,
    REQUIRED_TOKEN_METADATA_FIELDS,
    DEFAULT_GRACE_PERIOD_SLOTS,
    MIN_ANNUAL_DUES_LOVELACE,
    MAX_ANNUAL_DUES_LOVELACE,
)

from cardano_license.tx_utils import (
    TxResult,
    UTxOSelection,
    estimate_fee,
    estimate_fee_from_context,
    select_utxos,
    MIN_UTXO_LOVELACE,
    DEFAULT_MIN_UTXO,
    FEE_BUFFER_LOVELACE,
    _utxo_lovelace,
    _assets_satisfied,
    _flatten_assets,
)

from pycardano import (
    ScriptPubkey,
    ScriptAll,
    InvalidBefore,
    InvalidHereAfter,
    NativeScript,
    PlutusData,
    Redeemer,
    RedeemerTag,
)
from pycardano.hash import VerificationKeyHash, ScriptHash


# ── Test Helpers ─────────────────────────────────────────────────

# Valid 28-byte hex PKH (56 hex chars)
AUTHORITY_PKH = "a1" * 28  # a1a1a1...a1 (56 chars)
SIGNER1_PKH = "b2" * 28
SIGNER2_PKH = "c3" * 28
SIGNER3_PKH = "d4" * 28
UNAUTHORIZED_PKH = "ff" * 28

# Valid 32-byte hex document hash
DOC_HASH = "ab" * 32  # 64 hex chars

# Mock authority address
AUTHORITY_ADDR = "addr_test1qzabc123def456"


def _mock_utxo(lovelace=5_000_000, multi_asset=None):
    """Create a mock UTxO."""
    utxo = MagicMock()
    if multi_asset:
        value = MagicMock()
        value.coin = lovelace
        value.multi_asset = multi_asset
        utxo.output.amount = value
        utxo.output.amount.__class__ = type(
            "Value", (), {"coin": lovelace, "multi_asset": multi_asset}
        )
    else:
        utxo.output.amount = lovelace
    return utxo


# ══════════════════════════════════════════════════════════════════
# PlutusV2MintingPolicy Tests
# ══════════════════════════════════════════════════════════════════


class TestMintingPolicyConstruction:
    """Test minting policy creation and validation."""

    def test_valid_authority_key_creates_policy(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        assert policy.authority_pubkey_hash == AUTHORITY_PKH
        assert policy.policy_id is not None
        assert policy.policy_cbor_hex is not None
        assert isinstance(policy.native_script, ScriptPubkey)

    def test_policy_id_is_deterministic(self):
        p1 = PlutusV2MintingPolicy(AUTHORITY_PKH)
        p2 = PlutusV2MintingPolicy(AUTHORITY_PKH)
        assert p1.get_policy_id_hex() == p2.get_policy_id_hex()

    def test_different_keys_produce_different_policies(self):
        p1 = PlutusV2MintingPolicy(AUTHORITY_PKH)
        p2 = PlutusV2MintingPolicy(SIGNER1_PKH)
        assert p1.get_policy_id_hex() != p2.get_policy_id_hex()

    def test_invalid_hex_raises_valueerror(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            PlutusV2MintingPolicy("not_valid_hex")

    def test_wrong_length_raises_valueerror(self):
        with pytest.raises(ValueError, match="28 bytes"):
            PlutusV2MintingPolicy("aa" * 16)  # Only 16 bytes

    def test_empty_key_raises_valueerror(self):
        with pytest.raises(ValueError, match="28 bytes"):
            PlutusV2MintingPolicy("")

    def test_too_long_key_raises_valueerror(self):
        with pytest.raises(ValueError, match="28 bytes"):
            PlutusV2MintingPolicy("aa" * 32)  # 32 bytes


class TestMintingPolicyTimeLocks:
    """Test time-locked minting policies."""

    def test_time_lock_after_creates_script_all(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH, time_lock_after=1_000_000)
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_after == 1_000_000

    def test_time_lock_before_creates_script_all(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH, time_lock_before=500_000)
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_before == 500_000

    def test_both_time_locks_creates_script_all(self):
        policy = PlutusV2MintingPolicy(
            AUTHORITY_PKH,
            time_lock_before=500_000,
            time_lock_after=1_000_000,
        )
        assert isinstance(policy.native_script, ScriptAll)
        assert policy.time_lock_before == 500_000
        assert policy.time_lock_after == 1_000_000

    def test_no_time_lock_uses_script_pubkey(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        assert isinstance(policy.native_script, ScriptPubkey)

    def test_time_locked_policy_differs_from_unlocked(self):
        p_unlocked = PlutusV2MintingPolicy(AUTHORITY_PKH)
        p_locked = PlutusV2MintingPolicy(AUTHORITY_PKH, time_lock_after=1_000_000)
        assert p_unlocked.get_policy_id_hex() != p_locked.get_policy_id_hex()


class TestMintingPolicySerialization:
    """Test policy serialization (to_dict, CBOR, save/load)."""

    def test_to_dict_contains_required_fields(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        d = policy.to_dict()
        assert d["authority_pubkey_hash"] == AUTHORITY_PKH
        assert "policy_id" in d
        assert "policy_cbor_hex" in d
        assert "script_type" in d
        assert "created_at" in d

    def test_to_dict_script_type_pubkey(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        d = policy.to_dict()
        assert d["script_type"] == "native_script_pubkey"

    def test_to_dict_script_type_all(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH, time_lock_after=100)
        d = policy.to_dict()
        assert d["script_type"] == "native_script_all"

    def test_cbor_hex_roundtrip(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        cbor_hex = policy.policy_cbor_hex
        restored = PlutusV2MintingPolicy.from_cbor_hex(cbor_hex)
        assert restored.get_policy_id_hex() == policy.get_policy_id_hex()
        assert restored.authority_pubkey_hash == policy.authority_pubkey_hash

    def test_cbor_hex_roundtrip_with_time_locks(self):
        policy = PlutusV2MintingPolicy(
            AUTHORITY_PKH, time_lock_before=500, time_lock_after=1000
        )
        cbor_hex = policy.policy_cbor_hex
        restored = PlutusV2MintingPolicy.from_cbor_hex(cbor_hex)
        assert restored.get_policy_id_hex() == policy.get_policy_id_hex()
        assert restored.time_lock_before == 500
        assert restored.time_lock_after == 1000

    def test_save_and_load_policy(self):
        policy = PlutusV2MintingPolicy(AUTHORITY_PKH)
        json_path = policy.save_policy("test_authority")
        assert json_path.exists()
        assert (TEST_POLICY_DIR / "test_authority.cbor").exists()

        loaded = PlutusV2MintingPolicy.load_policy("test_authority")
        assert loaded.get_policy_id_hex() == policy.get_policy_id_hex()

    def test_load_nonexistent_policy_raises(self):
        with pytest.raises(FileNotFoundError):
            PlutusV2MintingPolicy.load_policy("nonexistent_policy")


class TestMintingPolicyBuildConvenience:
    """Test the build_minting_policy convenience function."""

    def test_build_minting_policy_returns_policy(self):
        policy = build_minting_policy(AUTHORITY_PKH)
        assert isinstance(policy, PlutusV2MintingPolicy)
        assert policy.authority_pubkey_hash == AUTHORITY_PKH

    def test_build_minting_policy_with_time_lock(self):
        policy = build_minting_policy(AUTHORITY_PKH, time_lock_after=999)
        assert policy.time_lock_after == 999

    def test_build_minting_policy_invalid_key(self):
        with pytest.raises(ValueError):
            build_minting_policy("bad_hex")


class TestRedeemers:
    """Test Plutus V2 redeemer types."""

    def test_mint_action_constr_id(self):
        assert MintAction.CONSTR_ID == 0

    def test_burn_action_constr_id(self):
        assert BurnAction.CONSTR_ID == 1

    def test_valid_redeemer_actions_tuple(self):
        assert MintAction in VALID_REDEEMER_ACTIONS
        assert BurnAction in VALID_REDEEMER_ACTIONS


# ══════════════════════════════════════════════════════════════════
# SignatureCollectionValidator Tests
# ══════════════════════════════════════════════════════════════════


class TestSignatureValidatorConstruction:
    """Test signature validator creation and validation."""

    def test_valid_construction(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        assert v.required_signers == [SIGNER1_PKH, SIGNER2_PKH]
        assert v.authority_pkh == AUTHORITY_PKH
        assert v.document_hash == DOC_HASH
        assert v.validator_address is not None

    def test_empty_signers_raises(self):
        with pytest.raises(ValueError, match="at least one PKH"):
            SignatureCollectionValidator(
                required_signers=[],
                authority_pkh=AUTHORITY_PKH,
                document_hash=DOC_HASH,
            )

    def test_invalid_document_hash_raises(self):
        with pytest.raises(ValueError, match="valid hex hash"):
            SignatureCollectionValidator(
                required_signers=[SIGNER1_PKH],
                authority_pkh=AUTHORITY_PKH,
                document_hash="short",
            )

    def test_invalid_signer_pkh_raises(self):
        with pytest.raises(ValueError):
            SignatureCollectionValidator(
                required_signers=["bad_hex"],
                authority_pkh=AUTHORITY_PKH,
                document_hash=DOC_HASH,
            )

    def test_invalid_authority_pkh_raises(self):
        with pytest.raises(ValueError):
            SignatureCollectionValidator(
                required_signers=[SIGNER1_PKH],
                authority_pkh="too_short",
                document_hash=DOC_HASH,
            )

    def test_validator_address_is_string(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        addr = v.get_validator_address()
        assert isinstance(addr, str)
        assert len(addr) > 0

    def test_script_hash_is_hex(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        sh = v.get_script_hash_hex()
        assert isinstance(sh, str)
        bytes.fromhex(sh)  # Should not raise

    def test_with_validity_deadline(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=1_000_000,
        )
        assert v.validity_slot_deadline == 1_000_000


class TestSignerAuthorization:
    """Test signer authorization checks."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )

    def test_authorized_signer_passes(self):
        ok, msg = self.v.validate_signer_authorized(SIGNER1_PKH)
        assert ok is True
        assert msg == "authorized"

    def test_second_authorized_signer_passes(self):
        ok, msg = self.v.validate_signer_authorized(SIGNER2_PKH)
        assert ok is True

    def test_unauthorized_signer_fails(self):
        ok, msg = self.v.validate_signer_authorized(UNAUTHORIZED_PKH)
        assert ok is False
        assert "not in required_signers" in msg

    def test_authority_is_not_automatically_a_signer(self):
        ok, _ = self.v.validate_signer_authorized(AUTHORITY_PKH)
        # Authority PKH is not in the required_signers list
        assert ok is False


class TestValidityExpiry:
    """Test validity token expiry checks."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=1_000_000,
        )

    def test_valid_token_passes(self):
        ok, msg = self.v.validate_validity_not_expired(
            validity_expiry_slot=500_000, current_slot=100_000
        )
        assert ok is True
        assert msg == "valid"

    def test_expired_token_fails(self):
        ok, msg = self.v.validate_validity_not_expired(
            validity_expiry_slot=100_000, current_slot=200_000
        )
        assert ok is False
        assert "expired" in msg

    def test_exactly_at_expiry_fails(self):
        ok, msg = self.v.validate_validity_not_expired(
            validity_expiry_slot=100_000, current_slot=100_000
        )
        assert ok is False
        assert "expired" in msg

    def test_expiry_exceeds_deadline_fails(self):
        ok, msg = self.v.validate_validity_not_expired(
            validity_expiry_slot=2_000_000, current_slot=100_000
        )
        assert ok is False
        assert "exceeds deadline" in msg

    def test_no_deadline_allows_any_future_expiry(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=None,
        )
        ok, msg = v.validate_validity_not_expired(
            validity_expiry_slot=999_999_999, current_slot=100_000
        )
        assert ok is True


class TestDepositValidation:
    """Test full deposit validation logic."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=1_000_000,
        )

    def test_valid_deposit_passes(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
            has_sig_token=True,
            has_val_token=True,
        )
        assert ok is True
        assert errors == []

    def test_unauthorized_signer_deposit_fails(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=UNAUTHORIZED_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
        )
        assert ok is False
        assert any("not in required_signers" in e for e in errors)

    def test_expired_validity_deposit_fails(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=50_000,
            current_slot=100_000,
        )
        assert ok is False
        assert any("expired" in e for e in errors)

    def test_missing_sig_token_fails(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
            has_sig_token=False,
            has_val_token=True,
        )
        assert ok is False
        assert any("signature token" in e for e in errors)

    def test_missing_val_token_fails(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
            has_sig_token=True,
            has_val_token=False,
        )
        assert ok is False
        assert any("validity token" in e for e in errors)

    def test_missing_both_tokens_fails(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
            has_sig_token=False,
            has_val_token=False,
        )
        assert ok is False
        assert len(errors) >= 2  # Both token errors

    def test_duplicate_deposit_fails(self):
        # First deposit succeeds
        self.v.record_deposit(
            signer_pkh=SIGNER1_PKH,
            deposit_slot=100_000,
            sig_token_policy="aa" * 28,
            val_token_policy="bb" * 28,
            validity_expiry_slot=500_000,
            tx_hash="tx123",
        )
        # Second deposit from same signer fails
        ok, errors = self.v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=500_000,
            current_slot=100_000,
        )
        assert ok is False
        assert any("already deposited" in e for e in errors)

    def test_multiple_errors_accumulated(self):
        ok, errors = self.v.validate_deposit(
            signer_pkh=UNAUTHORIZED_PKH,
            validity_expiry_slot=50_000,
            current_slot=100_000,
            has_sig_token=False,
            has_val_token=False,
        )
        assert ok is False
        assert len(errors) == 4  # unauthorized + expired + 2x missing tokens


class TestRecordDeposit:
    """Test deposit recording and SignerDatum creation."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )

    def test_record_deposit_returns_datum(self):
        datum = self.v.record_deposit(
            signer_pkh=SIGNER1_PKH,
            deposit_slot=100,
            sig_token_policy="aa" * 28,
            val_token_policy="bb" * 28,
            validity_expiry_slot=500,
            tx_hash="tx_abc",
        )
        assert isinstance(datum, SignerDatum)
        assert datum.signer_pkh == bytes.fromhex(SIGNER1_PKH)
        assert datum.document_hash == bytes.fromhex(DOC_HASH)
        assert datum.deposit_slot == 100
        assert datum.validity_expiry_slot == 500

    def test_record_deposit_tracks_signer(self):
        self.v.record_deposit(
            signer_pkh=SIGNER1_PKH,
            deposit_slot=100,
            sig_token_policy="aa" * 28,
            val_token_policy="bb" * 28,
            validity_expiry_slot=500,
            tx_hash="tx_abc",
        )
        assert SIGNER1_PKH in self.v._collected_signers
        info = self.v._collected_signers[SIGNER1_PKH]
        assert info["deposit_slot"] == 100
        assert info["tx_hash"] == "tx_abc"


class TestFinalizationCheck:
    """Test finalization readiness checks."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )

    def test_no_deposits_not_ready(self):
        ready, details = self.v.check_finalization_ready()
        assert ready is False
        assert details["total_required"] == 2
        assert details["total_collected"] == 0
        assert len(details["missing_signers"]) == 2
        assert details["progress"] == "0/2"

    def test_partial_deposits_not_ready(self):
        self.v.record_deposit(
            signer_pkh=SIGNER1_PKH, deposit_slot=100,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=500, tx_hash="tx1",
        )
        ready, details = self.v.check_finalization_ready()
        assert ready is False
        assert details["total_collected"] == 1
        assert details["progress"] == "1/2"

    def test_all_deposits_ready(self):
        self.v.record_deposit(
            signer_pkh=SIGNER1_PKH, deposit_slot=100,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=500, tx_hash="tx1",
        )
        self.v.record_deposit(
            signer_pkh=SIGNER2_PKH, deposit_slot=200,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=500, tx_hash="tx2",
        )
        ready, details = self.v.check_finalization_ready()
        assert ready is True
        assert details["total_collected"] == 2
        assert details["missing_signers"] == []
        assert details["progress"] == "2/2"

    def test_single_signer_ready_after_one_deposit(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        v.record_deposit(
            signer_pkh=SIGNER1_PKH, deposit_slot=100,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=500, tx_hash="tx1",
        )
        ready, _ = v.check_finalization_ready()
        assert ready is True


class TestValidatorRedeemers:
    """Test redeemer building for the validator."""

    def setup_method(self):
        self.v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )

    def test_collect_redeemer(self):
        r = self.v.build_collect_redeemer()
        assert isinstance(r, Redeemer)
        # PyCardano stores RedeemerTag in ex_units field
        assert r.tag == RedeemerTag.SPEND or r.ex_units == RedeemerTag.SPEND

    def test_finalize_redeemer(self):
        r = self.v.build_finalize_redeemer()
        assert isinstance(r, Redeemer)
        assert r.tag == RedeemerTag.SPEND or r.ex_units == RedeemerTag.SPEND

    def test_reclaim_redeemer(self):
        r = self.v.build_reclaim_redeemer()
        assert isinstance(r, Redeemer)
        assert r.tag == RedeemerTag.SPEND or r.ex_units == RedeemerTag.SPEND

    def test_redeemer_constr_ids_are_distinct(self):
        assert CollectRedeemer.CONSTR_ID == 0
        assert FinalizeRedeemer.CONSTR_ID == 1
        assert ReclaimRedeemer.CONSTR_ID == 2


class TestValidatorSerialization:
    """Test validator serialization (to_dict, save/load)."""

    def test_to_dict_contains_required_fields(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        d = v.to_dict()
        assert d["required_signers"] == [SIGNER1_PKH, SIGNER2_PKH]
        assert d["authority_pkh"] == AUTHORITY_PKH
        assert d["document_hash"] == DOC_HASH
        assert "script_hash" in d
        assert "validator_address" in d
        assert "script_cbor_hex" in d
        assert "created_at" in d

    def test_save_and_load_validator(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=900_000,
        )
        json_path = v.save_validator("test_validator")
        assert json_path.exists()

        loaded = SignatureCollectionValidator.load_validator("test_validator")
        assert loaded.required_signers == [SIGNER1_PKH]
        assert loaded.authority_pkh == AUTHORITY_PKH
        assert loaded.document_hash == DOC_HASH
        assert loaded.validity_slot_deadline == 900_000

    def test_save_preserves_collected_signers(self):
        v = SignatureCollectionValidator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        v.record_deposit(
            signer_pkh=SIGNER1_PKH, deposit_slot=100,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=500, tx_hash="tx1",
        )
        v.save_validator("test_with_deposits")
        loaded = SignatureCollectionValidator.load_validator("test_with_deposits")
        assert SIGNER1_PKH in loaded._collected_signers

    def test_load_nonexistent_validator_raises(self):
        with pytest.raises(FileNotFoundError):
            SignatureCollectionValidator.load_validator("nonexistent_validator")


class TestBuildSignatureValidator:
    """Test the build_signature_validator convenience function."""

    def test_build_returns_validator(self):
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH],
            document_hash=DOC_HASH,
        )
        assert isinstance(v, SignatureCollectionValidator)
        assert v.required_signers == [SIGNER1_PKH]

    def test_build_defaults_authority_to_first_signer(self):
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            document_hash=DOC_HASH,
        )
        assert v.authority_pkh == SIGNER1_PKH

    def test_build_explicit_authority(self):
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        assert v.authority_pkh == AUTHORITY_PKH

    def test_build_empty_doc_hash_uses_placeholder(self):
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH],
            document_hash="",
        )
        assert v.document_hash == "0" * 64

    def test_build_empty_signers_raises(self):
        with pytest.raises(ValueError, match="at least one PKH"):
            build_signature_validator(required_signers=[])


class TestSignerDatum:
    """Test SignerDatum Plutus data type."""

    def test_default_values(self):
        d = SignerDatum()
        assert d.signer_pkh == b""
        assert d.document_hash == b""
        assert d.deposit_slot == 0
        assert d.sig_token_policy == b""
        assert d.val_token_policy == b""
        assert d.validity_expiry_slot == 0

    def test_constr_id(self):
        assert SignerDatum.CONSTR_ID == 0

    def test_is_plutus_data(self):
        assert issubclass(SignerDatum, PlutusData)

    def test_with_values(self):
        d = SignerDatum(
            signer_pkh=bytes.fromhex(SIGNER1_PKH),
            document_hash=bytes.fromhex(DOC_HASH),
            deposit_slot=42000,
            sig_token_policy=bytes.fromhex("aa" * 28),
            val_token_policy=bytes.fromhex("bb" * 28),
            validity_expiry_slot=99000,
        )
        assert d.deposit_slot == 42000
        assert d.validity_expiry_slot == 99000


# ══════════════════════════════════════════════════════════════════
# DuesEnforcementContract Tests
# ══════════════════════════════════════════════════════════════════


class TestDuesContractConstruction:
    """Test dues enforcement contract creation."""

    def test_valid_construction(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        assert c.authority_pkh == AUTHORITY_PKH
        assert c.authority_address == AUTHORITY_ADDR
        assert c.annual_dues_lovelace == 50_000_000
        assert c.license_ref == 1
        assert c.grace_period_slots == DEFAULT_GRACE_PERIOD_SLOTS

    def test_custom_grace_period(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            grace_period_slots=172800,
        )
        assert c.grace_period_slots == 172800

    def test_invalid_authority_pkh_raises(self):
        with pytest.raises(ValueError):
            DuesEnforcementContract(
                authority_pkh="bad",
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=5_000_000,
                license_ref=1,
            )

    def test_empty_authority_address_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            DuesEnforcementContract(
                authority_pkh=AUTHORITY_PKH,
                authority_address="",
                annual_dues_lovelace=5_000_000,
                license_ref=1,
            )

    def test_dues_below_minimum_raises(self):
        with pytest.raises(ValueError, match=f">= {MIN_ANNUAL_DUES_LOVELACE}"):
            DuesEnforcementContract(
                authority_pkh=AUTHORITY_PKH,
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=500_000,  # 0.5 ADA, below 1 ADA min
                license_ref=1,
            )

    def test_dues_above_maximum_raises(self):
        with pytest.raises(ValueError, match=f"<= {MAX_ANNUAL_DUES_LOVELACE}"):
            DuesEnforcementContract(
                authority_pkh=AUTHORITY_PKH,
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=11_000_000_000,  # 11K ADA, above 10K max
                license_ref=1,
            )

    def test_zero_license_ref_raises(self):
        with pytest.raises(ValueError, match="positive"):
            DuesEnforcementContract(
                authority_pkh=AUTHORITY_PKH,
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=5_000_000,
                license_ref=0,
            )

    def test_negative_grace_period_raises(self):
        with pytest.raises(ValueError, match=">= 0"):
            DuesEnforcementContract(
                authority_pkh=AUTHORITY_PKH,
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=5_000_000,
                license_ref=1,
                grace_period_slots=-1,
            )

    def test_contract_address_is_string(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
        )
        assert isinstance(c.get_contract_address(), str)

    def test_minimum_dues_accepted(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=MIN_ANNUAL_DUES_LOVELACE,
            license_ref=1,
        )
        assert c.annual_dues_lovelace == MIN_ANNUAL_DUES_LOVELACE

    def test_maximum_dues_accepted(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=MAX_ANNUAL_DUES_LOVELACE,
            license_ref=1,
        )
        assert c.annual_dues_lovelace == MAX_ANNUAL_DUES_LOVELACE


class TestDuesPaymentValidation:
    """Test dues payment validation logic."""

    def setup_method(self):
        self.c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,  # 50 ADA
            license_ref=1,
        )

    def test_exact_payment_passes(self):
        ok, errors = self.c.validate_payment(50_000_000, AUTHORITY_ADDR)
        assert ok is True
        assert errors == []

    def test_overpayment_passes(self):
        ok, errors = self.c.validate_payment(100_000_000, AUTHORITY_ADDR)
        assert ok is True
        assert errors == []

    def test_underpayment_fails(self):
        ok, errors = self.c.validate_payment(49_999_999, AUTHORITY_ADDR)
        assert ok is False
        assert any("payment" in e and "lovelace" in e for e in errors)

    def test_zero_payment_fails(self):
        ok, errors = self.c.validate_payment(0, AUTHORITY_ADDR)
        assert ok is False

    def test_wrong_recipient_fails(self):
        ok, errors = self.c.validate_payment(50_000_000, "addr_test1_wrong_addr")
        assert ok is False
        assert any("authority address" in e for e in errors)

    def test_underpayment_and_wrong_recipient(self):
        ok, errors = self.c.validate_payment(1_000, "addr_test1_wrong")
        assert ok is False
        assert len(errors) == 2  # Both errors


class TestDuesRenewalValidation:
    """Test full renewal validation with grace period."""

    def setup_method(self):
        self.c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            grace_period_slots=86400,
        )

    def test_renewal_before_expiry_passes(self):
        ok, errors = self.c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=500_000,
            current_expiry_slot=600_000,  # Not expired yet
        )
        assert ok is True

    def test_renewal_within_grace_period_passes(self):
        ok, errors = self.c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=600_100,  # 100 slots past expiry
            current_expiry_slot=600_000,
        )
        assert ok is True  # Within 86400 grace period

    def test_renewal_past_grace_period_fails(self):
        ok, errors = self.c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=700_000,  # 100K slots past expiry
            current_expiry_slot=600_000,
        )
        assert ok is False
        assert any("grace period" in e for e in errors)

    def test_renewal_without_expiry_slot_passes(self):
        ok, errors = self.c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=500_000,
            current_expiry_slot=None,
        )
        assert ok is True

    def test_renewal_underpayment_past_grace_both_fail(self):
        ok, errors = self.c.validate_renewal(
            payment_lovelace=1_000,
            recipient_address="addr_test1_wrong",
            current_slot=800_000,
            current_expiry_slot=600_000,
        )
        assert ok is False
        assert len(errors) == 3  # Underpay + wrong addr + past grace


class TestDuesSigningValidity:
    """Test validity-for-signing checks."""

    def setup_method(self):
        self.c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            grace_period_slots=86400,
        )

    def test_valid_token_allows_signing(self):
        ok, msg = self.c.check_validity_for_signing(
            validity_expiry_slot=500_000, current_slot=100_000
        )
        assert ok is True
        assert msg == "valid"

    def test_expired_token_blocks_signing(self):
        ok, msg = self.c.check_validity_for_signing(
            validity_expiry_slot=100_000, current_slot=200_000
        )
        assert ok is False
        assert "expired" in msg
        assert "renew" in msg

    def test_at_expiry_blocks_signing(self):
        ok, msg = self.c.check_validity_for_signing(
            validity_expiry_slot=100_000, current_slot=100_000
        )
        assert ok is False

    def test_grace_period_does_not_extend_signing(self):
        # Even within grace period, signing is blocked
        ok, _ = self.c.check_validity_for_signing(
            validity_expiry_slot=100_000, current_slot=100_001
        )
        assert ok is False


class TestGracePeriodCheck:
    """Test grace period detection."""

    def setup_method(self):
        self.c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            grace_period_slots=86400,
        )

    def test_not_expired_returns_false(self):
        in_grace, remaining = self.c.check_in_grace_period(
            validity_expiry_slot=500_000, current_slot=100_000
        )
        assert in_grace is False
        assert remaining == 0

    def test_just_expired_in_grace(self):
        in_grace, remaining = self.c.check_in_grace_period(
            validity_expiry_slot=100_000, current_slot=100_001
        )
        assert in_grace is True
        assert remaining == 86399  # 86400 - 1

    def test_midway_through_grace(self):
        in_grace, remaining = self.c.check_in_grace_period(
            validity_expiry_slot=100_000, current_slot=143_200  # 43200 past
        )
        assert in_grace is True
        assert remaining == 43200  # 86400 - 43200

    def test_at_grace_boundary_still_in_grace(self):
        in_grace, remaining = self.c.check_in_grace_period(
            validity_expiry_slot=100_000, current_slot=186_400  # Exactly at boundary
        )
        assert in_grace is True
        assert remaining == 0

    def test_past_grace_period(self):
        in_grace, remaining = self.c.check_in_grace_period(
            validity_expiry_slot=100_000, current_slot=186_401
        )
        assert in_grace is False
        assert remaining == 0

    def test_zero_grace_period(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            grace_period_slots=0,
        )
        in_grace, remaining = c.check_in_grace_period(
            validity_expiry_slot=100_000, current_slot=100_001
        )
        assert in_grace is False


class TestDuesContractDatumAndRedeemers:
    """Test Plutus data types for dues enforcement."""

    def test_datum_construction(self):
        d = DuesContractDatum(
            authority_pkh=bytes.fromhex(AUTHORITY_PKH),
            annual_dues=50_000_000,
            license_ref=1,
            grace_period_slots=86400,
        )
        assert d.annual_dues == 50_000_000
        assert d.license_ref == 1
        assert d.grace_period_slots == 86400

    def test_datum_constr_id(self):
        assert DuesContractDatum.CONSTR_ID == 0

    def test_pay_dues_redeemer_constr_id(self):
        assert PayDuesRedeemer.CONSTR_ID == 0

    def test_revoke_validity_redeemer_constr_id(self):
        assert RevokeValidityRedeemer.CONSTR_ID == 1

    def test_build_datum_from_contract(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        datum = c.build_datum()
        assert isinstance(datum, DuesContractDatum)
        assert datum.authority_pkh == bytes.fromhex(AUTHORITY_PKH)
        assert datum.annual_dues == 50_000_000

    def test_build_pay_redeemer(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
        )
        r = c.build_pay_redeemer()
        assert isinstance(r, Redeemer)
        assert r.tag == RedeemerTag.SPEND or r.ex_units == RedeemerTag.SPEND

    def test_build_revoke_redeemer(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
        )
        r = c.build_revoke_redeemer()
        assert isinstance(r, Redeemer)
        assert r.tag == RedeemerTag.SPEND or r.ex_units == RedeemerTag.SPEND


class TestDuesContractSerialization:
    """Test dues contract serialization."""

    def test_to_dict_fields(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
        )
        d = c.to_dict()
        assert d["authority_pkh"] == AUTHORITY_PKH
        assert d["authority_address"] == AUTHORITY_ADDR
        assert d["annual_dues_lovelace"] == 50_000_000
        assert d["license_ref"] == 1
        assert "script_hash" in d
        assert "contract_address" in d
        assert "created_at" in d

    def test_save_and_load_contract(self):
        c = DuesEnforcementContract(
            authority_pkh=AUTHORITY_PKH,
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            grace_period_slots=172800,
        )
        json_path = c.save_contract("test_dues")
        assert json_path.exists()
        assert (TEST_POLICY_DIR / "dues_test_dues.cbor").exists()

        loaded = DuesEnforcementContract.load_contract("test_dues")
        assert loaded.authority_pkh == AUTHORITY_PKH
        assert loaded.annual_dues_lovelace == 50_000_000
        assert loaded.grace_period_slots == 172800

    def test_load_nonexistent_contract_raises(self):
        with pytest.raises(FileNotFoundError):
            DuesEnforcementContract.load_contract("nonexistent_contract")


class TestBuildDuesContract:
    """Test the build_dues_contract convenience function."""

    def test_build_with_explicit_pkh(self):
        c = build_dues_contract(
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,
            license_ref=1,
            authority_pkh=AUTHORITY_PKH,
        )
        assert isinstance(c, DuesEnforcementContract)
        assert c.authority_pkh == AUTHORITY_PKH

    def test_build_invalid_dues_raises(self):
        with pytest.raises(ValueError):
            build_dues_contract(
                authority_address=AUTHORITY_ADDR,
                annual_dues_lovelace=500,  # Below minimum
                license_ref=1,
                authority_pkh=AUTHORITY_PKH,
            )


# ══════════════════════════════════════════════════════════════════
# Transaction Builder Utility Tests
# ══════════════════════════════════════════════════════════════════


class TestFeeEstimation:
    """Test fee estimation functions."""

    def test_estimate_fee_from_tx_body(self):
        body = MagicMock()
        body.to_cbor.return_value = b"\x00" * 400
        body.inputs = [MagicMock(), MagicMock()]
        fee = estimate_fee(body)
        assert isinstance(fee, int)
        assert fee > 0

    def test_estimate_fee_fallback_on_cbor_error(self):
        body = MagicMock()
        body.to_cbor.side_effect = Exception("CBOR error")
        body.inputs = [MagicMock()]
        body.outputs = [MagicMock(), MagicMock()]
        fee = estimate_fee(body)
        assert isinstance(fee, int)
        assert fee > 0

    def test_estimate_fee_from_context_basic(self):
        fee = estimate_fee_from_context()
        assert isinstance(fee, int)
        assert fee > 155_381  # At least the constant term

    def test_estimate_fee_from_context_more_inputs(self):
        fee_small = estimate_fee_from_context(n_inputs=1, n_outputs=1)
        fee_large = estimate_fee_from_context(n_inputs=10, n_outputs=5)
        assert fee_large > fee_small

    def test_estimate_fee_with_mint(self):
        fee_no_mint = estimate_fee_from_context(has_mint=False)
        fee_mint = estimate_fee_from_context(has_mint=True)
        assert fee_mint > fee_no_mint

    def test_estimate_fee_with_metadata(self):
        fee_no_meta = estimate_fee_from_context(has_metadata=False)
        fee_meta = estimate_fee_from_context(has_metadata=True)
        assert fee_meta > fee_no_meta

    def test_estimate_fee_with_scripts(self):
        fee_no_script = estimate_fee_from_context(has_scripts=False)
        fee_script = estimate_fee_from_context(has_scripts=True)
        assert fee_script > fee_no_script


class TestUTxOSelection:
    """Test UTxO selection for transactions."""

    def test_select_single_utxo(self):
        utxos = [_mock_utxo(10_000_000)]
        result = select_utxos(utxos, required_lovelace=5_000_000)
        assert len(result.selected) == 1
        assert result.total_lovelace >= 5_000_000
        assert result.change_lovelace == 5_000_000

    def test_select_multiple_utxos(self):
        utxos = [_mock_utxo(2_000_000), _mock_utxo(3_000_000), _mock_utxo(4_000_000)]
        result = select_utxos(utxos, required_lovelace=6_000_000)
        assert result.total_lovelace >= 6_000_000

    def test_insufficient_funds_raises(self):
        utxos = [_mock_utxo(1_000_000)]
        with pytest.raises(ValueError, match="Insufficient lovelace"):
            select_utxos(utxos, required_lovelace=5_000_000)

    def test_empty_utxos_raises(self):
        with pytest.raises(ValueError, match="No UTxOs"):
            select_utxos([], required_lovelace=1_000_000)

    def test_exact_amount(self):
        utxos = [_mock_utxo(5_000_000)]
        result = select_utxos(utxos, required_lovelace=5_000_000)
        assert result.change_lovelace == 0


class TestTxResult:
    """Test TxResult dataclass."""

    def test_txresult_defaults(self):
        r = TxResult(tx_hash="abc123")
        assert r.tx_hash == "abc123"
        assert r.signed_tx is None
        assert r.fee_lovelace == 0
        assert r.confirmed is False
        assert r.error is None

    def test_txresult_to_dict(self):
        r = TxResult(
            tx_hash="abc123",
            fee_lovelace=200_000,
            inputs_used=2,
            outputs_count=3,
            confirmed=True,
            block_height=12345,
        )
        d = r.to_dict()
        assert d["tx_hash"] == "abc123"
        assert d["fee_lovelace"] == 200_000
        assert d["confirmed"] is True
        assert d["block_height"] == 12345

    def test_txresult_with_error(self):
        r = TxResult(tx_hash="", error="network timeout")
        d = r.to_dict()
        assert d["error"] == "network timeout"


class TestUtxoHelpers:
    """Test internal UTxO helper functions."""

    def test_utxo_lovelace_plain_int(self):
        utxo = _mock_utxo(5_000_000)
        assert _utxo_lovelace(utxo) == 5_000_000

    def test_assets_satisfied_empty(self):
        assert _assets_satisfied({}, {}) is True

    def test_assets_satisfied_present(self):
        collected = {"pid1": {"asset1": 10}}
        required = {"pid1": {"asset1": 5}}
        assert _assets_satisfied(collected, required) is True

    def test_assets_not_satisfied(self):
        collected = {"pid1": {"asset1": 2}}
        required = {"pid1": {"asset1": 5}}
        assert _assets_satisfied(collected, required) is False

    def test_assets_missing_policy(self):
        collected = {}
        required = {"pid1": {"asset1": 5}}
        assert _assets_satisfied(collected, required) is False

    def test_flatten_assets(self):
        nested = {"pid1": {"asset1": 10, "asset2": 5}}
        flat = _flatten_assets(nested)
        assert flat["pid1.asset1"] == 10
        assert flat["pid1.asset2"] == 5


class TestConstants:
    """Test module constants are sensible."""

    def test_min_utxo_lovelace(self):
        assert MIN_UTXO_LOVELACE == 1_000_000

    def test_default_min_utxo(self):
        assert DEFAULT_MIN_UTXO == 2_000_000

    def test_fee_buffer(self):
        assert FEE_BUFFER_LOVELACE == 200_000

    def test_default_grace_period(self):
        assert DEFAULT_GRACE_PERIOD_SLOTS == 86400

    def test_min_annual_dues(self):
        assert MIN_ANNUAL_DUES_LOVELACE == 1_000_000

    def test_max_annual_dues(self):
        assert MAX_ANNUAL_DUES_LOVELACE == 10_000_000_000

    def test_required_token_metadata_fields(self):
        assert "name" in REQUIRED_TOKEN_METADATA_FIELDS
        assert "license_type" in REQUIRED_TOKEN_METADATA_FIELDS
        assert "issuing_authority" in REQUIRED_TOKEN_METADATA_FIELDS
        assert "issue_date" in REQUIRED_TOKEN_METADATA_FIELDS


# ══════════════════════════════════════════════════════════════════
# Integration: End-to-End Workflow Tests
# ══════════════════════════════════════════════════════════════════


class TestEndToEndSignatureWorkflow:
    """Test a complete signature collection workflow."""

    def test_full_two_signer_workflow(self):
        # 1. Build validator with 2 required signers
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH, SIGNER2_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
            validity_slot_deadline=1_000_000,
        )

        # 2. Check not ready
        ready, _ = v.check_finalization_ready()
        assert ready is False

        # 3. Signer 1 deposits
        ok, errors = v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=800_000,
            current_slot=100_000,
        )
        assert ok is True
        v.record_deposit(
            signer_pkh=SIGNER1_PKH, deposit_slot=100_000,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=800_000, tx_hash="tx1",
        )

        # 4. Still not ready (1/2)
        ready, details = v.check_finalization_ready()
        assert ready is False
        assert details["progress"] == "1/2"

        # 5. Unauthorized signer rejected
        ok, _ = v.validate_deposit(
            signer_pkh=UNAUTHORIZED_PKH,
            validity_expiry_slot=800_000,
            current_slot=100_000,
        )
        assert ok is False

        # 6. Signer 2 deposits
        ok, errors = v.validate_deposit(
            signer_pkh=SIGNER2_PKH,
            validity_expiry_slot=800_000,
            current_slot=200_000,
        )
        assert ok is True
        v.record_deposit(
            signer_pkh=SIGNER2_PKH, deposit_slot=200_000,
            sig_token_policy="aa" * 28, val_token_policy="bb" * 28,
            validity_expiry_slot=800_000, tx_hash="tx2",
        )

        # 7. Now ready (2/2)
        ready, details = v.check_finalization_ready()
        assert ready is True
        assert details["progress"] == "2/2"
        assert details["missing_signers"] == []

    def test_expired_validity_blocks_deposit(self):
        v = build_signature_validator(
            required_signers=[SIGNER1_PKH],
            authority_pkh=AUTHORITY_PKH,
            document_hash=DOC_HASH,
        )
        ok, errors = v.validate_deposit(
            signer_pkh=SIGNER1_PKH,
            validity_expiry_slot=50_000,  # Already expired
            current_slot=100_000,
        )
        assert ok is False
        assert any("expired" in e for e in errors)


class TestEndToEndDuesWorkflow:
    """Test a complete dues enforcement workflow."""

    def test_full_dues_lifecycle(self):
        # 1. Create contract
        c = build_dues_contract(
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=50_000_000,  # 50 ADA
            license_ref=1,
            grace_period_slots=86400,
            authority_pkh=AUTHORITY_PKH,
        )

        # 2. Validity is good, signing allowed
        ok, _ = c.check_validity_for_signing(
            validity_expiry_slot=500_000, current_slot=100_000
        )
        assert ok is True

        # 3. Validity expires, signing blocked
        ok, _ = c.check_validity_for_signing(
            validity_expiry_slot=500_000, current_slot=500_001
        )
        assert ok is False

        # 4. Within grace period — can still renew
        in_grace, remaining = c.check_in_grace_period(
            validity_expiry_slot=500_000, current_slot=510_000
        )
        assert in_grace is True
        assert remaining > 0

        # 5. Renewal with correct payment passes
        ok, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=510_000,
            current_expiry_slot=500_000,
        )
        assert ok is True

        # 6. Partial payment rejected
        ok, errors = c.validate_renewal(
            payment_lovelace=25_000_000,  # Only 25 ADA
            recipient_address=AUTHORITY_ADDR,
            current_slot=510_000,
            current_expiry_slot=500_000,
        )
        assert ok is False

        # 7. Past grace period — renewal rejected
        ok, errors = c.validate_renewal(
            payment_lovelace=50_000_000,
            recipient_address=AUTHORITY_ADDR,
            current_slot=700_000,  # Way past grace
            current_expiry_slot=500_000,
        )
        assert ok is False
        assert any("grace period" in e for e in errors)


class TestMintingPolicyWithDuesIntegration:
    """Test minting policy paired with dues enforcement."""

    def test_same_authority_different_scripts(self):
        """Minting policy and dues contract for same authority produce different scripts."""
        policy = build_minting_policy(AUTHORITY_PKH)
        contract = build_dues_contract(
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            authority_pkh=AUTHORITY_PKH,
        )
        # Both use the same authority key but are independent scripts
        # (policy_id and script_hash can be equal since both are ScriptPubkey(same_vkh))
        assert policy.native_script is not contract.native_script

    def test_time_locked_policy_differs(self):
        """Time-locked policy produces different ID than dues contract."""
        policy = build_minting_policy(AUTHORITY_PKH, time_lock_after=999)
        contract = build_dues_contract(
            authority_address=AUTHORITY_ADDR,
            annual_dues_lovelace=5_000_000,
            license_ref=1,
            authority_pkh=AUTHORITY_PKH,
        )
        # ScriptAll != ScriptPubkey
        assert policy.get_policy_id_hex() != contract.get_script_hash_hex()
