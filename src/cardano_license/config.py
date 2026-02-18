"""Environment-based configuration for cardano-license.

All settings are loaded from environment variables with sane defaults.
"""

import os
from pathlib import Path

# ── Base directory ────────────────────────────────────────────────

CARDANO_LICENSE_DIR = Path(
    os.getenv("CARDANO_LICENSE_DIR", "~/.cardano-license")
).expanduser()

# ── SQLite database ───────────────────────────────────────────────

CARDANO_LICENSE_DB = os.getenv(
    "CARDANO_LICENSE_DB",
    str(CARDANO_LICENSE_DIR / "license.db"),
)

# ── Wallet key files ─────────────────────────────────────────────

WALLET_DIR = CARDANO_LICENSE_DIR / "wallets"

# ── Policy storage ───────────────────────────────────────────────

POLICY_DIR = CARDANO_LICENSE_DIR / "policies"

# ── Cardano network ──────────────────────────────────────────────

BLOCKFROST_PROJECT_ID = os.getenv("BLOCKFROST_PROJECT_ID", "")
CARDANO_NETWORK = os.getenv("CARDANO_NETWORK", "testnet").lower()

# ── Encryption password ──────────────────────────────────────────
# Read from env; if empty, crypto.py will prompt interactively.

CARDANO_LICENSE_PASSWORD = os.getenv("CARDANO_LICENSE_PASSWORD", "")

# ── Ensure directories exist on import ───────────────────────────

CARDANO_LICENSE_DIR.mkdir(parents=True, exist_ok=True)
WALLET_DIR.mkdir(parents=True, exist_ok=True)
POLICY_DIR.mkdir(parents=True, exist_ok=True)
