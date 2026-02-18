"""Database schema initialization for cardano-license.

Contains all 10 CREATE TABLE statements. Call init_db() once on first use
to ensure all tables exist.
"""

import aiosqlite

from cardano_license.config import CARDANO_LICENSE_DB

_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS blockchain_wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_type TEXT NOT NULL CHECK(wallet_type IN (
        'authority', 'licensee', 'signer', 'observer'
    )),
    address TEXT NOT NULL UNIQUE,
    public_key_hash TEXT NOT NULL,
    network TEXT NOT NULL DEFAULT 'testnet' CHECK(network IN ('mainnet', 'testnet')),
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blockchain_licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_name TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    licensee_address TEXT NOT NULL,
    authority_address TEXT NOT NULL,
    metadata_json JSON,
    mint_tx_hash TEXT,
    burn_tx_hash TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
        'pending', 'active', 'revoked', 'expired', 'burned'
    )),
    license_type TEXT DEFAULT 'professional',
    valid_from TEXT,
    valid_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blockchain_signature_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    token_name TEXT NOT NULL,
    licensee_address TEXT NOT NULL,
    license_ref INTEGER,
    quantity INTEGER NOT NULL DEFAULT 1,
    mint_tx_hash TEXT,
    burn_tx_hash TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
        'pending', 'minted', 'burned', 'transferred'
    )),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blockchain_validity_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    token_name TEXT NOT NULL,
    licensee_address TEXT NOT NULL,
    license_ref INTEGER,
    valid_until TEXT NOT NULL,
    mint_tx_hash TEXT,
    burn_tx_hash TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
        'pending', 'active', 'expired', 'revoked', 'burned'
    )),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blockchain_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_hash TEXT NOT NULL,
    signer_address TEXT NOT NULL,
    license_ref INTEGER,
    signature_tx_hash TEXT,
    signature_datum JSON,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS blockchain_work_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    wp_address TEXT,
    document_hash TEXT NOT NULL,
    required_signers_json JSON NOT NULL DEFAULT '[]',
    collected_signatures_json JSON NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN (
        'draft', 'pending_signatures', 'partially_signed',
        'fully_signed', 'finalized', 'rejected'
    )),
    finalize_tx_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    finalized_at TEXT,
    validator_address TEXT,
    validator_script_hash TEXT
);

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
);

CREATE TABLE IF NOT EXISTS dues_contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authority_address TEXT NOT NULL,
    authority_pkh TEXT NOT NULL,
    license_ref INTEGER NOT NULL,
    annual_dues_lovelace INTEGER NOT NULL,
    grace_period_slots INTEGER NOT NULL DEFAULT 86400,
    policy_id TEXT,
    script_hash TEXT,
    contract_address TEXT,
    script_cbor_hex TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'suspended', 'terminated')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata_json JSON
);

CREATE TABLE IF NOT EXISTS dues_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    payer_address TEXT NOT NULL,
    amount_lovelace INTEGER NOT NULL,
    payment_tx_hash TEXT,
    new_expiry TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'confirmed', 'failed')),
    confirmed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


async def init_db(db_path: str | None = None) -> None:
    """Create all tables if they don't exist.

    Args:
        db_path: SQLite database path. Defaults to CARDANO_LICENSE_DB.
    """
    path = db_path or CARDANO_LICENSE_DB
    async with aiosqlite.connect(path) as db:
        await db.executescript(_TABLES_SQL)
        await db.commit()
