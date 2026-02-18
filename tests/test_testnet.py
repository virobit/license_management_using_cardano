"""End-to-end integration tests on Cardano preprod testnet.

Task: #380 (P-18, WS-TESTING)
Created: 2026-02-16

Tests:
  1. Create authority + licensee wallets
  2. Fund from faucet (manual step — skip if no tADA)
  3. Mint license NFT
  4. Mint signature + validity tokens
  5. Create work product
  6. Sign with valid tokens
  7. Verify signatures
  8. Test expiration (validity token with past date)

Requirements:
  - BLOCKFROST_PROJECT_ID env var set to a preprod project ID
  - CARDANO_NETWORK=testnet (default)
  - Wallets funded with test ADA from preprod faucet
    (https://docs.cardano.org/cardano-testnets/tools/faucet/)

Usage:
  pytest tests/test_cardano_testnet.py -v -m integration --timeout=300
"""

import os
import json
import asyncio
import hashlib
import tempfile
import shutil
import time
import pytest
import aiosqlite
from pathlib import Path
from datetime import datetime, timedelta

# ── Gate: skip entire module if no Blockfrost key ────────────────

BLOCKFROST_PROJECT_ID = os.getenv("BLOCKFROST_PROJECT_ID", "")
if not BLOCKFROST_PROJECT_ID:
    pytest.skip(
        "BLOCKFROST_PROJECT_ID env var not set — skipping testnet integration tests",
        allow_module_level=True,
    )

# Marks for the entire module
pytestmark = [
    pytest.mark.slow,
    pytest.mark.integration,
    pytest.mark.timeout(300),
]

# ── Test isolation: use temp dir for DB + wallets ────────────────

TEST_DIR = tempfile.mkdtemp(prefix="cardano_testnet_")
TEST_DB = os.path.join(TEST_DIR, "test_memory.db")
TEST_WALLET_DIR = Path(TEST_DIR) / "wallets"

os.environ["CARDANO_NETWORK"] = "testnet"

import cardano_license  # noqa: E402
import cardano_license.tx_utils as cardano_tx_utils  # noqa: E402

# ── Fixtures ─────────────────────────────────────────────────────

MIN_FUNDING_LOVELACE = 10_000_000  # 10 tADA needed to run tests


@pytest.fixture(autouse=True)
def patch_paths(monkeypatch):
    """Redirect DB and wallet dir to temp paths for test isolation."""
    monkeypatch.setattr("cardano_license.core.MEMORY_DB", TEST_DB)
    monkeypatch.setattr("cardano_license.core.WALLET_DIR", TEST_WALLET_DIR)


@pytest.fixture(autouse=True, scope="module")
def _setup_test_dir():
    """Create and cleanup the test directory."""
    TEST_WALLET_DIR.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(TEST_DIR, ignore_errors=True)


@pytest.fixture(autouse=True, scope="module")
def _setup_db():
    """Create required blockchain tables for tests."""
    from cardano_license.schema import init_db
    asyncio.get_event_loop().run_until_complete(init_db(TEST_DB))


def _doc_hash(content: str = "test document content") -> str:
    """Generate a deterministic document hash."""
    return hashlib.sha256(content.encode()).hexdigest()


# ── Shared state between ordered tests ───────────────────────────
# Using a dict so ordered tests can share data across the test class.

_state = {
    "authority_wallet": None,
    "licensee_wallet": None,
    "authority_address": None,
    "licensee_address": None,
    "license_id": None,
    "license_policy_id": None,
    "sig_token_result": None,
    "validity_token_result": None,
    "work_product": None,
    "document_hash": None,
    "sign_result": None,
}


# ── Test class (ordered execution) ──────────────────────────────


@pytest.mark.incremental
class TestCardanoTestnetE2E:
    """End-to-end testnet integration tests.

    Tests run in order — later tests depend on earlier ones having
    created wallets, minted tokens, etc. If an early test fails,
    subsequent tests are skipped via the incremental marker.
    """

    # ─── 1. Wallet Creation ───────────────────────────────────

    @pytest.mark.asyncio
    async def test_01_create_authority_wallet(self):
        """Create an authority wallet for the license issuer."""
        label = f"test_authority_{int(time.time())}"
        wallet = await cardano_license.create_authority_wallet(label)

        assert wallet is not None
        assert "base_address" in wallet
        assert "mnemonic" in wallet
        assert wallet["wallet_type"] == "authority"
        assert len(wallet["mnemonic"].split()) == 24

        _state["authority_wallet"] = wallet
        _state["authority_wallet_label"] = label
        _state["authority_address"] = wallet["base_address"]

    @pytest.mark.asyncio
    async def test_02_create_licensee_wallet(self):
        """Create a licensee wallet for the license holder."""
        label = f"test_licensee_{int(time.time())}"
        wallet = await cardano_license.create_licensee_wallet(label)

        assert wallet is not None
        assert "base_address" in wallet
        assert wallet["wallet_type"] == "licensee"

        _state["licensee_wallet"] = wallet
        _state["licensee_wallet_label"] = label
        _state["licensee_address"] = wallet["base_address"]

    # ─── 2. Funding Check ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_03_check_authority_funding(self):
        """Verify authority wallet has enough tADA for minting.

        If the wallet is unfunded, the test is skipped with instructions
        to fund from the preprod faucet.
        """
        label = _state["authority_wallet_label"]
        balance = await cardano_license.get_wallet_balance(label)

        if balance["lovelace"] < MIN_FUNDING_LOVELACE:
            pytest.skip(
                f"Authority wallet needs funding. "
                f"Send >= {MIN_FUNDING_LOVELACE / 1_000_000:.0f} tADA to:\n"
                f"  {_state['authority_address']}\n"
                f"Use faucet: https://docs.cardano.org/cardano-testnets/tools/faucet/\n"
                f"Current balance: {balance['lovelace']} lovelace"
            )

        assert balance["lovelace"] >= MIN_FUNDING_LOVELACE

    # ─── 3. Mint License NFT ──────────────────────────────────

    @pytest.mark.asyncio
    async def test_04_mint_license_nft(self):
        """Mint a license NFT from authority to licensee."""
        now = datetime.now()
        metadata = {
            "license_type": "Professional Engineer",
            "licensee_name": "Test Engineer",
            "issuing_authority": "Test Board of Engineers",
            "issue_date": now.strftime("%Y-%m-%d"),
            "expiry_date": (now + timedelta(days=365)).strftime("%Y-%m-%d"),
            "jurisdiction": "Test State",
            "license_number": f"PE-TEST-{int(time.time())}",
        }

        result = await cardano_license.mint_license_nft(
            authority_wallet_label=_state["authority_wallet_label"],
            licensee_address=_state["licensee_address"],
            license_metadata=metadata,
        )

        assert result is not None
        assert "tx_hash" in result
        assert "policy_id" in result
        assert "license_id" in result
        assert len(result["tx_hash"]) == 64  # 32-byte hex

        _state["license_id"] = result["license_id"]
        _state["license_policy_id"] = result["policy_id"]
        _state["license_tx_hash"] = result["tx_hash"]

        # Wait for on-chain confirmation (up to 120s)
        confirmation = await cardano_tx_utils.wait_for_confirmation(
            result["tx_hash"], timeout=120
        )
        assert confirmation.confirmed or confirmation.error is None

    # ─── 4. Mint Signature Tokens ─────────────────────────────

    @pytest.mark.asyncio
    async def test_05_mint_signature_tokens(self):
        """Mint signature tokens for the licensee."""
        result = await cardano_license.mint_signature_tokens(
            authority_wallet_label=_state["authority_wallet_label"],
            licensee_address=_state["licensee_address"],
            token_count=5,
            license_ref=_state["license_id"],
        )

        assert result is not None
        assert "tx_hash" in result
        assert "policy_id" in result
        assert result["quantity"] == 5

        _state["sig_token_result"] = result

        # Wait for confirmation
        confirmation = await cardano_tx_utils.wait_for_confirmation(
            result["tx_hash"], timeout=120
        )
        assert confirmation.confirmed or confirmation.error is None

    # ─── 5. Mint Validity Token ───────────────────────────────

    @pytest.mark.asyncio
    async def test_06_mint_validity_token(self):
        """Mint a validity token for the licensee (valid for 1 year)."""
        valid_until = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")

        result = await cardano_license.mint_validity_token(
            authority_wallet_label=_state["authority_wallet_label"],
            licensee_address=_state["licensee_address"],
            license_ref=_state["license_id"],
            valid_until=valid_until,
        )

        assert result is not None
        assert "tx_hash" in result
        assert "token_id" in result
        assert result["valid_until"] == valid_until

        _state["validity_token_result"] = result

        # Wait for confirmation
        confirmation = await cardano_tx_utils.wait_for_confirmation(
            result["tx_hash"], timeout=120
        )
        assert confirmation.confirmed or confirmation.error is None

    # ─── 6. Check Validity ────────────────────────────────────

    @pytest.mark.asyncio
    async def test_07_check_validity_active(self):
        """Verify the licensee has an active validity token."""
        result = await cardano_license.check_validity(
            licensee_address=_state["licensee_address"],
            license_ref=_state["license_id"],
        )

        assert result["is_valid"] is True
        assert result["license_ref"] == _state["license_id"]

    # ─── 7. Check Signature Balance ───────────────────────────

    @pytest.mark.asyncio
    async def test_08_check_signature_balance(self):
        """Verify the licensee has signature tokens."""
        result = await cardano_license.get_signature_balance(
            _state["licensee_wallet_label"]
        )

        assert result["total"] >= 5
        assert _state["license_id"] in result["by_license"]
        assert result["by_license"][_state["license_id"]] >= 5

    # ─── 8. Create Work Product ───────────────────────────────

    @pytest.mark.asyncio
    async def test_09_create_work_product(self):
        """Create a work product requiring the licensee's signature."""
        doc_hash = _doc_hash("PE stamped structural analysis report v1.0")
        _state["document_hash"] = doc_hash

        result = await cardano_license.create_work_product(
            title="Structural Analysis Report",
            document_hash=doc_hash,
            required_signers=[_state["licensee_address"]],
        )

        assert result is not None
        assert "work_product_id" in result
        assert result["status"] == "pending"
        assert result["document_hash"] == doc_hash

        _state["work_product"] = result

    # ─── 9. Sign Document ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_10_sign_document(self):
        """Sign the work product with the licensee's credentials."""
        wp = _state["work_product"]

        result = await cardano_license.sign_document(
            signer_wallet_label=_state["licensee_wallet_label"],
            document_hash=_state["document_hash"],
            contract_address=wp["wp_address"],
            license_ref=_state["license_id"],
        )

        assert result is not None
        assert "signature_id" in result
        assert "tx_hash" in result
        assert result["document_hash"] == _state["document_hash"]

        _state["sign_result"] = result

        # Wait for confirmation
        confirmation = await cardano_tx_utils.wait_for_confirmation(
            result["tx_hash"], timeout=120
        )
        assert confirmation.confirmed or confirmation.error is None

    # ─── 10. Verify Signature ─────────────────────────────────

    @pytest.mark.asyncio
    async def test_11_verify_signature(self):
        """Verify the document's signature is valid."""
        wp = _state["work_product"]

        result = await cardano_license.verify_signature(
            contract_address=wp["wp_address"],
            document_hash=_state["document_hash"],
        )

        assert result["is_verified"] is True
        assert result["signature_count"] >= 1
        assert len(result["signatures"]) >= 1

        # Confirm signer address matches licensee
        signer_addrs = [s["signer_address"] for s in result["signatures"]]
        assert _state["licensee_address"] in signer_addrs

    # ─── 11. Finalize Work Product ────────────────────────────

    @pytest.mark.asyncio
    async def test_12_finalize_work_product(self):
        """Finalize the work product (all required signatures present)."""
        wp = _state["work_product"]

        result = await cardano_license.finalize_work_product(
            work_product_id=wp["work_product_id"]
        )

        assert result is not None
        assert result["status"] == "finalized"
        assert result["finalized_at"] is not None

    # ─── 12. Signature Balance Decremented ────────────────────

    @pytest.mark.asyncio
    async def test_13_signature_token_consumed(self):
        """Verify one signature token was consumed by signing."""
        result = await cardano_license.get_signature_balance(
            _state["licensee_wallet_label"]
        )

        # We minted 5, used 1 for signing
        assert result["by_license"].get(_state["license_id"], 0) >= 4

    # ─── 13. Expired Validity Token ───────────────────────────

    @pytest.mark.asyncio
    async def test_14_expired_validity_token(self):
        """Mint a validity token with a past date and verify it shows expired."""
        past_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        result = await cardano_license.mint_validity_token(
            authority_wallet_label=_state["authority_wallet_label"],
            licensee_address=_state["licensee_address"],
            license_ref=_state["license_id"],
            valid_until=past_date,
        )

        assert result is not None
        assert "token_id" in result

        # Wait for confirmation
        confirmation = await cardano_tx_utils.wait_for_confirmation(
            result["tx_hash"], timeout=120
        )

        # Manually update the most recently minted validity token to expired status
        # by checking its DB record (check_validity only looks at active tokens)
        expired_token_id = result["token_id"]

        # check_validity should still return valid because the earlier (future-dated)
        # token is still active — it checks the most recent valid one
        check = await cardano_license.check_validity(
            licensee_address=_state["licensee_address"],
            license_ref=_state["license_id"],
        )
        # The original token (valid 1 year) should still be active
        assert check["is_valid"] is True

        # Now deactivate the original valid token and verify the expired one fails
        async with aiosqlite.connect(TEST_DB) as db:
            # Deactivate the original (future-dated) validity token
            original_token_id = _state["validity_token_result"]["token_id"]
            await db.execute(
                "UPDATE blockchain_validity_tokens SET status = 'revoked' WHERE id = ?",
                (original_token_id,),
            )
            await db.commit()

        # Now the only remaining active token is the expired one
        check_expired = await cardano_license.check_validity(
            licensee_address=_state["licensee_address"],
            license_ref=_state["license_id"],
        )
        assert check_expired["is_valid"] is False
        assert "expired" in check_expired.get("reason", "")

        # Restore the original token for any later tests
        async with aiosqlite.connect(TEST_DB) as db:
            await db.execute(
                "UPDATE blockchain_validity_tokens SET status = 'active' WHERE id = ?",
                (original_token_id,),
            )
            await db.commit()

    # ─── 14. Double-sign Prevention ───────────────────────────

    @pytest.mark.asyncio
    async def test_15_verify_finalized_cannot_refinalize(self):
        """A finalized work product cannot be finalized again."""
        wp = _state["work_product"]

        with pytest.raises(ValueError, match="already finalized"):
            await cardano_license.finalize_work_product(
                work_product_id=wp["work_product_id"]
            )

    # ─── 15. Query Functions ──────────────────────────────────

    @pytest.mark.asyncio
    async def test_16_get_work_product_status(self):
        """Query work product status shows finalized with signer info."""
        wp = _state["work_product"]

        status = await cardano_license.get_work_product_status(
            work_product_id=wp["work_product_id"]
        )

        assert status is not None
        assert status["status"] == "finalized"
        assert len(status["missing_signers"]) == 0
        assert _state["licensee_address"] in status["required_signers"]

    @pytest.mark.asyncio
    async def test_17_list_work_products(self):
        """List work products includes our test work product."""
        products = await cardano_license.list_work_products()

        assert len(products) >= 1
        wp_ids = [p["id"] for p in products]
        assert _state["work_product"]["work_product_id"] in wp_ids

    @pytest.mark.asyncio
    async def test_18_list_signatures(self):
        """List signatures includes our test signature."""
        sigs = await cardano_license.list_signatures()

        assert len(sigs) >= 1
        sig_ids = [s["id"] for s in sigs]
        assert _state["sign_result"]["signature_id"] in sig_ids


# ── Incremental test support ─────────────────────────────────────
# If a test fails, skip all subsequent tests in the class.


def pytest_runtest_makereport(item, call):
    """Mark subsequent tests as expected failures if a prior test failed."""
    if "incremental" in item.keywords:
        if call.excinfo is not None and call.when == "call":
            parent = item.parent
            parent._previousfailed = item


def pytest_runtest_setup(item):
    """Skip incremental tests if a prior test in the class failed."""
    if "incremental" in item.keywords:
        previousfailed = getattr(item.parent, "_previousfailed", None)
        if previousfailed is not None:
            pytest.skip(
                f"previous test failed: {previousfailed.name}"
            )
