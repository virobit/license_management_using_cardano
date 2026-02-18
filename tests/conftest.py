"""Shared test fixtures for cardano-license tests."""

import os
import sys
import tempfile
import shutil
import pytest
import aiosqlite
from pathlib import Path

# ── Test isolation ───────────────────────────────────────────────
# Guard against double-import: pytest loads this as "conftest" and
# test files may also import it as "tests.conftest".  If the pytest-
# loaded instance already created TEST_DIR, reuse it.

_pytest_conftest = sys.modules.get("conftest")
if _pytest_conftest and hasattr(_pytest_conftest, "TEST_DIR"):
    # Reuse the already-created test directory
    TEST_DIR = _pytest_conftest.TEST_DIR
    TEST_DB = _pytest_conftest.TEST_DB
    TEST_WALLET_DIR = _pytest_conftest.TEST_WALLET_DIR
    TEST_POLICY_DIR = _pytest_conftest.TEST_POLICY_DIR
else:
    TEST_DIR = tempfile.mkdtemp(prefix="cardano_test_")
    TEST_DB = os.path.join(TEST_DIR, "test_license.db")
    TEST_WALLET_DIR = Path(TEST_DIR) / "wallets"
    TEST_POLICY_DIR = Path(TEST_DIR) / "policies"

    # Set env vars BEFORE anything imports the package
    os.environ["CARDANO_LICENSE_DB"] = TEST_DB
    os.environ["CARDANO_LICENSE_DIR"] = TEST_DIR
    os.environ["CARDANO_LICENSE_PASSWORD"] = "test-password-not-for-production"
    os.environ.setdefault("BLOCKFROST_PROJECT_ID", "")
    os.environ.setdefault("CARDANO_NETWORK", "testnet")

# Now import core — config.py will use our env vars (or may already
# have been imported by pytest collection; either way we reconcile below).
import cardano_license.core as _core  # noqa: E402

# Reconcile: force the module attributes to match our TEST_DIR.
_core.LICENSE_DB = TEST_DB
_core.WALLET_DIR = TEST_WALLET_DIR
_core.POLICY_DIR = TEST_POLICY_DIR

# Ensure the directories exist
TEST_WALLET_DIR.mkdir(parents=True, exist_ok=True)
TEST_POLICY_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture(autouse=True)
def patch_paths():
    """Keep core module vars pointing at test paths for each test."""
    _core.LICENSE_DB = TEST_DB
    _core.WALLET_DIR = TEST_WALLET_DIR
    _core.POLICY_DIR = TEST_POLICY_DIR
    yield


@pytest.fixture(autouse=True)
async def setup_db():
    """Create all blockchain tables for testing."""
    from cardano_license.schema import init_db
    await init_db(TEST_DB)
    yield
    # Clean up between tests — defensive try/except per table
    async with aiosqlite.connect(TEST_DB) as db:
        for table in (
            "dues_payments", "dues_contracts",
            "blockchain_work_products", "blockchain_signatures",
            "blockchain_validity_tokens", "blockchain_signature_tokens",
            "blockchain_minting_policies",
            "blockchain_wallets", "blockchain_licenses",
        ):
            try:
                await db.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        await db.commit()
    # Clean wallet/policy files
    if TEST_WALLET_DIR.exists():
        shutil.rmtree(TEST_WALLET_DIR, ignore_errors=True)
    if TEST_POLICY_DIR.exists():
        shutil.rmtree(TEST_POLICY_DIR, ignore_errors=True)
