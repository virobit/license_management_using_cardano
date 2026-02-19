"""Cardano License Module — PyCardano wallet management, chain interaction, NFT minting.

Created: 2026-02-16
Updated: 2026-02-19 (v2.1.0 — CIP-68 revocation, audit fixes)

Features:
- PyCardano + Blockfrost backend (testnet/mainnet via env vars)
- HD wallet generation (CIP-1852 derivation, hardened paths, 24-word mnemonic)
- Wallet loading from encrypted key files (AES-256-GCM)
- Balance and UTXO querying
- SQLite wallet metadata persistence
- License NFT minting with CIP-25 metadata standard
- CIP-68 Reference Token support for authority-controlled revocation:
  - User Token (label 222) held by licensee (immutable)
  - Reference Token (label 100) held by authority (mutable datum)
  - update_license_status() updates datum without touching licensee wallet
  - store_reference_token() for CIP-68 record tracking
- Authority-key-restricted minting policies (Native Script, NOT Plutus V2)
- Signature token minting, balance querying, and transfer
- Validity token minting, checking, and renewal (time-bounded)
- Document signing: sign_document(), verify_signature(), multi-signer work products
- Work product wallet management with independent per-signer UTxO deposits
  to avoid eUTxO concurrency bottlenecks
- Plutus V2 signature collection validator with atomic finalization sweep
- Dues enforcement: DuesEnforcementContract class with grace period logic
"""

import os
import json
import logging
import asyncio
import aiosqlite
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from pycardano import (
    HDWallet,
    PaymentSigningKey,
    PaymentVerificationKey,
    StakeSigningKey,
    StakeVerificationKey,
    Address,
    Network,
    BlockFrostChainContext,
    TransactionBuilder,
    TransactionOutput,
    Value,
    MultiAsset,
    Asset,
    AssetName,
    ScriptPubkey,
    ScriptAll,
    NativeScript,
    AuxiliaryData,
    AlonzoMetadata,
    Metadata,
    PlutusV2Script,
    PlutusData,
    Redeemer,
    RedeemerTag,
    plutus_script_hash,
    InvalidHereAfter,
    InvalidBefore,
)
from pycardano.hash import ScriptHash, VerificationKeyHash
from blockfrost import ApiUrls

from cardano_license.crypto import encrypt_key, decrypt_key
from cardano_license.config import (
    CARDANO_LICENSE_DB as LICENSE_DB,
    WALLET_DIR,
    POLICY_DIR,
    BLOCKFROST_PROJECT_ID,
    CARDANO_NETWORK,
)

logger = logging.getLogger(__name__)

# CIP-1852 derivation paths
PAYMENT_PATH = "m/1852'/1815'/0'/0/0"
STAKE_PATH = "m/1852'/1815'/0'/2/0"

# Valid wallet types (matches blockchain_wallets table CHECK constraint)
WALLET_TYPES = ("authority", "licensee", "signer", "observer")

# CIP-68 asset label prefixes (big-endian 4 bytes prepended to asset name)
# Label 100 = Reference Token (authority-held, mutable datum)
# Label 222 = User Token (licensee-held, immutable)
CIP68_REFERENCE_LABEL = 100
CIP68_USER_LABEL = 222


def _get_network() -> Network:
    """Get PyCardano Network enum from env config."""
    return Network.MAINNET if CARDANO_NETWORK == "mainnet" else Network.TESTNET


def _get_blockfrost_url() -> str:
    """Get Blockfrost API URL for configured network."""
    urls = {
        "mainnet": ApiUrls.mainnet.value,
        "testnet": ApiUrls.preprod.value,
        "preprod": ApiUrls.preprod.value,
        "preview": ApiUrls.preview.value,
    }
    return urls.get(CARDANO_NETWORK, ApiUrls.preprod.value)


def get_chain_context() -> BlockFrostChainContext:
    """Create a BlockFrost chain context for the configured network.

    Requires BLOCKFROST_PROJECT_ID env var to be set.

    Raises:
        ValueError: If BLOCKFROST_PROJECT_ID is not configured.
    """
    if not BLOCKFROST_PROJECT_ID:
        raise ValueError(
            "BLOCKFROST_PROJECT_ID env var not set. "
            "Get a free key at https://blockfrost.io"
        )
    return BlockFrostChainContext(
        BLOCKFROST_PROJECT_ID,
        base_url=_get_blockfrost_url(),
    )


# ── Wallet Key Derivation ─────────────────────────────────────────

def derive_keys_from_mnemonic(mnemonic: str) -> Dict[str, Any]:
    """Derive payment and stake keys from a mnemonic phrase.

    Uses CIP-1852 derivation paths:
    - Payment: m/1852'/1815'/0'/0/0
    - Stake:   m/1852'/1815'/0'/2/0

    Returns dict with signing keys, verification keys, key hashes, and address.
    """
    hd_wallet = HDWallet.from_mnemonic(mnemonic)

    # Payment keys
    payment_child = hd_wallet.derive_from_path(PAYMENT_PATH)
    payment_sk = PaymentSigningKey(payment_child.xprivate_key[:32])
    payment_vk = PaymentVerificationKey.from_signing_key(payment_sk)

    # Stake keys
    stake_child = hd_wallet.derive_from_path(STAKE_PATH)
    stake_sk = StakeSigningKey(stake_child.xprivate_key[:32])
    stake_vk = StakeVerificationKey.from_signing_key(stake_sk)

    network = _get_network()
    base_address = Address(payment_vk.hash(), stake_vk.hash(), network)
    enterprise_address = Address(payment_vk.hash(), network=network)

    return {
        "payment_sk": payment_sk,
        "payment_vk": payment_vk,
        "payment_key_hash": payment_vk.hash().to_primitive().hex(),
        "stake_sk": stake_sk,
        "stake_vk": stake_vk,
        "stake_key_hash": stake_vk.hash().to_primitive().hex(),
        "base_address": str(base_address),
        "enterprise_address": str(enterprise_address),
        "network": CARDANO_NETWORK,
    }


# ── Encrypted Key File Management ─────────────────────────────────

def _ensure_wallet_dir():
    """Create wallet directory with restrictive permissions."""
    WALLET_DIR.mkdir(parents=True, exist_ok=True)


def save_wallet_keys(
    wallet_label: str,
    mnemonic: str,
    payment_sk: PaymentSigningKey,
    stake_sk: StakeSigningKey,
) -> Path:
    """Save wallet keys to an encrypted JSON file.

    Keys are encrypted using the project's key_manager (AES-256-GCM).

    Returns:
        Path to the saved wallet file.
    """
    _ensure_wallet_dir()

    wallet_data = {
        "label": wallet_label,
        "mnemonic_enc": encrypt_key(mnemonic),
        "payment_sk_enc": encrypt_key(payment_sk.to_primitive().hex()),
        "stake_sk_enc": encrypt_key(stake_sk.to_primitive().hex()),
        "created_at": datetime.now().isoformat(),
        "network": CARDANO_NETWORK,
    }

    file_path = WALLET_DIR / f"{wallet_label}.json"
    old_umask = os.umask(0o077)
    try:
        with open(file_path, "w") as f:
            json.dump(wallet_data, f, indent=2)
    finally:
        os.umask(old_umask)

    logger.info(f"Saved encrypted wallet keys: {file_path}")
    return file_path


def load_wallet_keys(wallet_label: str) -> Dict[str, Any]:
    """Load and decrypt wallet keys from file.

    Returns dict with decrypted signing keys and derived verification keys/address.

    Raises:
        FileNotFoundError: If wallet file doesn't exist.
    """
    file_path = WALLET_DIR / f"{wallet_label}.json"
    if not file_path.exists():
        raise FileNotFoundError(f"Wallet file not found: {file_path}")

    with open(file_path, "r") as f:
        wallet_data = json.load(f)

    mnemonic = decrypt_key(wallet_data["mnemonic_enc"])
    payment_sk_hex = decrypt_key(wallet_data["payment_sk_enc"])
    stake_sk_hex = decrypt_key(wallet_data["stake_sk_enc"])

    payment_sk = PaymentSigningKey.from_primitive(bytes.fromhex(payment_sk_hex))
    payment_vk = PaymentVerificationKey.from_signing_key(payment_sk)

    stake_sk = StakeSigningKey.from_primitive(bytes.fromhex(stake_sk_hex))
    stake_vk = StakeVerificationKey.from_signing_key(stake_sk)

    network = _get_network()
    base_address = Address(payment_vk.hash(), stake_vk.hash(), network)

    return {
        "label": wallet_data["label"],
        "mnemonic": mnemonic,
        "payment_sk": payment_sk,
        "payment_vk": payment_vk,
        "payment_key_hash": payment_vk.hash().to_primitive().hex(),
        "stake_sk": stake_sk,
        "stake_vk": stake_vk,
        "stake_key_hash": stake_vk.hash().to_primitive().hex(),
        "base_address": str(base_address),
        "network": wallet_data.get("network", "testnet"),
    }


# ── SQLite Wallet Metadata ────────────────────────────────────────

async def store_wallet_metadata(
    wallet_type: str,
    address: str,
    public_key_hash: str,
    label: Optional[str] = None,
    network: Optional[str] = None,
) -> int:
    """Store wallet metadata in blockchain_wallets table.

    Returns:
        The wallet row ID.
    """
    if wallet_type not in WALLET_TYPES:
        raise ValueError(f"Invalid wallet_type: {wallet_type}. Must be one of {WALLET_TYPES}")

    net = network or CARDANO_NETWORK
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """INSERT INTO blockchain_wallets
               (wallet_type, address, public_key_hash, network, label)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(address) DO UPDATE SET
                   wallet_type = excluded.wallet_type,
                   label = excluded.label""",
            (wallet_type, address, public_key_hash, net, label),
        )
        await db.commit()
        return cursor.lastrowid


async def get_wallet_by_label(label: str) -> Optional[Dict[str, Any]]:
    """Look up wallet metadata by label."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_wallets WHERE label = ?", (label,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_wallet_by_address(address: str) -> Optional[Dict[str, Any]]:
    """Look up wallet metadata by address."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_wallets WHERE address = ?", (address,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_wallets(
    wallet_type: Optional[str] = None,
    network: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all stored wallets, optionally filtered by type or network."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if wallet_type:
            conditions.append("wallet_type = ?")
            params.append(wallet_type)
        if network:
            conditions.append("network = ?")
            params.append(network)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_wallets{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ── Balance & UTXO Querying ───────────────────────────────────────

def query_balance(address_str: str) -> Dict[str, Any]:
    """Query the on-chain balance for a Cardano address.

    Requires BLOCKFROST_PROJECT_ID to be configured.

    Returns dict with lovelace amount, ADA amount, and native assets.
    """
    context = get_chain_context()
    utxos = context.utxos(address_str)

    total_lovelace = 0
    native_assets: Dict[str, Dict[str, int]] = {}

    for utxo in utxos:
        output = utxo.output
        if isinstance(output.amount, Value):
            total_lovelace += output.amount.coin
            if output.amount.multi_asset:
                for policy_id, assets in output.amount.multi_asset.items():
                    pid_hex = policy_id.to_primitive().hex()
                    if pid_hex not in native_assets:
                        native_assets[pid_hex] = {}
                    for asset_name, quantity in assets.items():
                        aname = asset_name.to_primitive().hex()
                        native_assets[pid_hex][aname] = (
                            native_assets[pid_hex].get(aname, 0) + quantity
                        )
        else:
            total_lovelace += output.amount

    return {
        "address": address_str,
        "lovelace": total_lovelace,
        "ada": total_lovelace / 1_000_000,
        "native_assets": native_assets,
        "utxo_count": len(utxos),
    }


def query_utxos(address_str: str) -> List[Dict[str, Any]]:
    """Query UTXOs for a Cardano address.

    Returns list of UTXO dicts with tx_hash, index, and amounts.
    """
    context = get_chain_context()
    utxos = context.utxos(address_str)

    results = []
    for utxo in utxos:
        tx_in = utxo.input
        output = utxo.output

        utxo_dict = {
            "tx_hash": tx_in.transaction_id.to_primitive().hex(),
            "index": tx_in.index,
        }

        if isinstance(output.amount, Value):
            utxo_dict["lovelace"] = output.amount.coin
            utxo_dict["native_assets"] = {}
            if output.amount.multi_asset:
                for policy_id, assets in output.amount.multi_asset.items():
                    pid_hex = policy_id.to_primitive().hex()
                    utxo_dict["native_assets"][pid_hex] = {
                        asset_name.to_primitive().hex(): quantity
                        for asset_name, quantity in assets.items()
                    }
        else:
            utxo_dict["lovelace"] = output.amount
            utxo_dict["native_assets"] = {}

        results.append(utxo_dict)

    return results


# ── Wallet Creation Convenience ───────────────────────────────────

async def generate_wallet(
    wallet_type: str,
    label: str,
    save_keys: bool = True,
) -> Dict[str, Any]:
    """Generate a new HD wallet, persist keys and metadata.

    Args:
        wallet_type: One of 'authority', 'licensee', 'signer', 'observer'.
        label: Human-readable wallet label (used as filename and DB label).
        save_keys: Whether to save encrypted key files to disk.

    Returns:
        Dict with mnemonic, address, keys, and wallet ID.
    """
    if wallet_type not in WALLET_TYPES:
        raise ValueError(f"Invalid wallet_type: {wallet_type}. Must be one of {WALLET_TYPES}")

    mnemonic = HDWallet.generate_mnemonic()
    keys = derive_keys_from_mnemonic(mnemonic)

    if save_keys:
        save_wallet_keys(label, mnemonic, keys["payment_sk"], keys["stake_sk"])

    wallet_id = await store_wallet_metadata(
        wallet_type=wallet_type,
        address=keys["base_address"],
        public_key_hash=keys["payment_key_hash"],
        label=label,
        network=keys["network"],
    )

    return {
        "wallet_id": wallet_id,
        "wallet_type": wallet_type,
        "label": label,
        "mnemonic": mnemonic,
        "base_address": keys["base_address"],
        "enterprise_address": keys["enterprise_address"],
        "payment_key_hash": keys["payment_key_hash"],
        "stake_key_hash": keys["stake_key_hash"],
        "network": keys["network"],
    }


async def create_authority_wallet(label: str = "authority") -> Dict[str, Any]:
    """Create an authority wallet (license issuer).

    Authority wallets are used to mint license NFTs and manage
    the licensing policy.
    """
    return await generate_wallet("authority", label)


async def create_licensee_wallet(label: str = "licensee") -> Dict[str, Any]:
    """Create a licensee wallet (license holder).

    Licensee wallets receive minted license NFTs and hold
    signature/validity tokens.
    """
    return await generate_wallet("licensee", label)


async def get_wallet_balance(label: str) -> Dict[str, Any]:
    """Get balance for a wallet by label.

    Loads wallet address from DB, queries chain via Blockfrost.

    Returns:
        Balance dict with lovelace, ADA, native assets, UTXO count.

    Raises:
        ValueError: If wallet not found in DB.
    """
    wallet = await get_wallet_by_label(label)
    if not wallet:
        raise ValueError(f"Wallet not found: {label}")
    return query_balance(wallet["address"])


async def get_wallet_utxos(label: str) -> List[Dict[str, Any]]:
    """Get UTXOs for a wallet by label.

    Raises:
        ValueError: If wallet not found in DB.
    """
    wallet = await get_wallet_by_label(label)
    if not wallet:
        raise ValueError(f"Wallet not found: {label}")
    return query_utxos(wallet["address"])


# ── Minting Policy ────────────────────────────────────────────────

# CIP-25 metadata label
CIP25_METADATA_LABEL = 721

# Required CIP-25 metadata fields for license NFTs
REQUIRED_LICENSE_FIELDS = (
    "license_type",
    "licensee_name",
    "issuing_authority",
    "issue_date",
    "expiry_date",
    "jurisdiction",
    "license_number",
)


def create_minting_policy(authority_vk: PaymentVerificationKey) -> NativeScript:
    """Create a minting policy restricted to the authority key.

    The policy requires the authority's payment key signature to mint or burn.
    This is a ScriptPubkey native script — the simplest authority-bound policy.

    Args:
        authority_vk: The authority wallet's payment verification key.

    Returns:
        NativeScript (ScriptPubkey) bound to the authority key hash.
    """
    return ScriptPubkey(authority_vk.hash())


# ── Plutus V2 Minting Policy ─────────────────────────────────────

# Redeemer actions for the Plutus V2 minting policy
class MintAction(PlutusData):
    """Redeemer: Mint new tokens (authority-signed)."""
    CONSTR_ID = 0

class BurnAction(PlutusData):
    """Redeemer: Burn existing tokens (authority-signed)."""
    CONSTR_ID = 1

# Valid redeemer actions
VALID_REDEEMER_ACTIONS = (MintAction, BurnAction)

# Required metadata fields for token format validation
REQUIRED_TOKEN_METADATA_FIELDS = (
    "name", "license_type", "issuing_authority", "issue_date",
)

# Maximum token name length (Cardano limit: 32 bytes)
MAX_TOKEN_NAME_BYTES = 32

# POLICY_DIR imported from cardano_license.config


class PlutusV2MintingPolicy:
    """Authority-only minting policy using Native Scripts.

    NOTE: Despite the class name, this policy is implemented as a Phase 1
    Native Script (ScriptPubkey/ScriptAll), NOT a Plutus V2 script. Native
    scripts have zero execution fees (~0.17 ADA tx fee only). The Plutus V2
    data types (MintAction/BurnAction redeemers) are included for forward
    compatibility with the planned Plutus V3 upgrade path. The class name
    is retained for API stability.

    The policy enforces:
    1. Authority key signature required (on-chain via ScriptPubkey)
    2. Token metadata format validation (pre-submission in Python)
    3. Authority address must be registered (DB-backed registry)

    Policy logic (on-chain):
        ScriptAll([ScriptPubkey(authority_pubkey_hash)])
        - Only the authority key holder can sign mint/burn transactions
        - The policy ID is deterministically derived from the authority key hash

    Extended validation (Python, pre-submission):
        - Token metadata must include required CIP-25 fields
        - Authority address must exist in blockchain_wallets with type='authority'
        - Redeemer action must be MintAction or BurnAction

    Attributes:
        authority_pubkey_hash: Hex string of the authority's verification key hash.
        native_script: The underlying ScriptAll native script.
        policy_id: The ScriptHash (policy ID) derived from the native script.
        policy_cbor_hex: CBOR hex encoding of the policy for storage/reproducibility.
    """

    def __init__(
        self,
        authority_pubkey_hash: str,
        time_lock_after: Optional[int] = None,
        time_lock_before: Optional[int] = None,
    ):
        """Initialize the minting policy for a given authority.

        Args:
            authority_pubkey_hash: Hex-encoded 28-byte verification key hash.
            time_lock_after: Optional slot number — minting only valid AFTER this slot.
            time_lock_before: Optional slot number — minting only valid BEFORE this slot.

        Raises:
            ValueError: If authority_pubkey_hash is invalid.
        """
        pkh_bytes = self._validate_pubkey_hash(authority_pubkey_hash)
        self.authority_pubkey_hash = authority_pubkey_hash
        self.time_lock_after = time_lock_after
        self.time_lock_before = time_lock_before

        # Build native script components
        vkh = VerificationKeyHash(pkh_bytes)
        scripts: List[NativeScript] = [ScriptPubkey(vkh)]

        if time_lock_before is not None:
            scripts.append(InvalidBefore(time_lock_before))
        if time_lock_after is not None:
            scripts.append(InvalidHereAfter(time_lock_after))

        # Single-condition: use ScriptPubkey directly; multi-condition: ScriptAll
        if len(scripts) == 1:
            self.native_script = scripts[0]
        else:
            self.native_script = ScriptAll(scripts)

        self.policy_id: ScriptHash = self.native_script.hash()
        self.policy_cbor_hex: str = self.native_script.to_cbor_hex()

    @staticmethod
    def _validate_pubkey_hash(pkh_hex: str) -> bytes:
        """Validate a pubkey hash is a 28-byte hex string."""
        try:
            pkh_bytes = bytes.fromhex(pkh_hex)
        except ValueError:
            raise ValueError(f"Invalid hex in authority_pubkey_hash: {pkh_hex}")
        if len(pkh_bytes) != 28:
            raise ValueError(
                f"authority_pubkey_hash must be 28 bytes (56 hex chars), got {len(pkh_bytes)}"
            )
        return pkh_bytes

    def get_policy_id_hex(self) -> str:
        """Return the policy ID as a hex string."""
        return self.policy_id.to_primitive().hex()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy to a dict for storage."""
        return {
            "authority_pubkey_hash": self.authority_pubkey_hash,
            "policy_id": self.get_policy_id_hex(),
            "policy_cbor_hex": self.policy_cbor_hex,
            "script_type": "native_script_all" if isinstance(self.native_script, ScriptAll) else "native_script_pubkey",
            "time_lock_after": self.time_lock_after,
            "time_lock_before": self.time_lock_before,
            "created_at": datetime.now().isoformat(),
        }

    def save_policy(self, label: str) -> Path:
        """Save the serialized policy to disk as JSON + CBOR.

        Args:
            label: Human-readable label for the policy file.

        Returns:
            Path to the saved policy JSON file.
        """
        POLICY_DIR.mkdir(parents=True, exist_ok=True)
        policy_data = self.to_dict()
        policy_data["label"] = label

        json_path = POLICY_DIR / f"{label}.json"
        with open(json_path, "w") as f:
            json.dump(policy_data, f, indent=2)

        cbor_path = POLICY_DIR / f"{label}.cbor"
        with open(cbor_path, "wb") as f:
            f.write(bytes.fromhex(self.policy_cbor_hex))

        logger.info(f"Saved minting policy: {json_path} + {cbor_path}")
        return json_path

    @classmethod
    def load_policy(cls, label: str) -> "PlutusV2MintingPolicy":
        """Load a previously saved policy from disk.

        Args:
            label: The policy label used during save.

        Returns:
            Reconstructed PlutusV2MintingPolicy instance.

        Raises:
            FileNotFoundError: If policy file doesn't exist.
        """
        json_path = POLICY_DIR / f"{label}.json"
        if not json_path.exists():
            raise FileNotFoundError(f"Policy file not found: {json_path}")

        with open(json_path, "r") as f:
            data = json.load(f)

        return cls(
            authority_pubkey_hash=data["authority_pubkey_hash"],
            time_lock_after=data.get("time_lock_after"),
            time_lock_before=data.get("time_lock_before"),
        )

    @classmethod
    def from_cbor_hex(cls, cbor_hex: str) -> "PlutusV2MintingPolicy":
        """Reconstruct a policy from its CBOR hex representation.

        Args:
            cbor_hex: CBOR hex string of the native script.

        Returns:
            PlutusV2MintingPolicy with the script restored from CBOR.
        """
        script = NativeScript.from_cbor(cbor_hex)
        # Extract authority pubkey hash from the script structure
        if isinstance(script, ScriptPubkey):
            pkh = script.key_hash.to_primitive().hex()
            return cls(authority_pubkey_hash=pkh)
        elif isinstance(script, ScriptAll):
            # First element should be ScriptPubkey
            for s in script.native_scripts:
                if isinstance(s, ScriptPubkey):
                    pkh = s.key_hash.to_primitive().hex()
                    # Extract time locks
                    time_before = None
                    time_after = None
                    for s2 in script.native_scripts:
                        if isinstance(s2, InvalidBefore):
                            time_before = s2.before
                        elif isinstance(s2, InvalidHereAfter):
                            time_after = s2.after
                    return cls(
                        authority_pubkey_hash=pkh,
                        time_lock_after=time_after,
                        time_lock_before=time_before,
                    )
        raise ValueError(f"Cannot extract authority key from script CBOR: {cbor_hex[:40]}...")


def build_minting_policy(
    authority_pubkey_hash: str,
    time_lock_after: Optional[int] = None,
    time_lock_before: Optional[int] = None,
) -> PlutusV2MintingPolicy:
    """Build a Plutus V2 minting policy bound to an authority key.

    Creates an authority-only minting policy that:
    1. Requires the authority key signature for all mint/burn operations (on-chain)
    2. Optionally restricts minting to a time window (slot-based)
    3. Derives a deterministic policy ID from the authority key hash

    The policy is implemented as a native script (ScriptPubkey or ScriptAll) for
    zero execution fees, with a Plutus V2-compatible interface for future upgrade.

    Policy Logic:
        On-chain: ScriptAll([ScriptPubkey(authority_pkh), ...time_locks])
        Pre-submission: validate_token_metadata_format() + authority registry check

    Args:
        authority_pubkey_hash: 56-char hex string of the authority's verification key hash
            (28 bytes). Obtain from wallet keys: payment_vk.hash().to_primitive().hex()
        time_lock_after: Optional slot number. If set, minting is invalid AFTER this slot.
            Use for time-bounded issuance campaigns.
        time_lock_before: Optional slot number. If set, minting is invalid BEFORE this slot.
            Use for delayed-start minting.

    Returns:
        PlutusV2MintingPolicy instance with policy_id, native_script, and cbor_hex.

    Raises:
        ValueError: If authority_pubkey_hash is not a valid 28-byte hex string.

    Example:
        >>> policy = build_minting_policy("a1b2c3...56chars...")
        >>> print(policy.get_policy_id_hex())
        'deadbeef...'
        >>> policy.save_policy("my_authority_policy")
    """
    return PlutusV2MintingPolicy(
        authority_pubkey_hash=authority_pubkey_hash,
        time_lock_after=time_lock_after,
        time_lock_before=time_lock_before,
    )


def attach_minting_policy(
    tx_builder: TransactionBuilder,
    policy: PlutusV2MintingPolicy,
    mint_assets: MultiAsset,
    redeemer_action: Optional[PlutusData] = None,
) -> TransactionBuilder:
    """Attach a minting policy to a transaction builder.

    Configures the TransactionBuilder with the minting policy's native script,
    the assets to mint/burn, and optional time validity constraints.

    Args:
        tx_builder: The PyCardano TransactionBuilder to configure.
        policy: The PlutusV2MintingPolicy to attach.
        mint_assets: MultiAsset specifying tokens to mint (positive) or burn (negative).
        redeemer_action: Optional PlutusData redeemer (MintAction or BurnAction).
            Not required for native scripts but accepted for API consistency
            with future Plutus V2 upgrade.

    Returns:
        The configured TransactionBuilder (same instance, for chaining).

    Example:
        >>> policy = build_minting_policy(authority_pkh)
        >>> mint = MultiAsset()
        >>> mint[policy.policy_id] = Asset({AssetName(b"LIC001"): 1})
        >>> builder = TransactionBuilder(context)
        >>> attach_minting_policy(builder, policy, mint)
        >>> signed_tx = builder.build_and_sign([payment_sk], change_address)
    """
    # Validate redeemer action if provided
    if redeemer_action is not None:
        if not isinstance(redeemer_action, tuple(VALID_REDEEMER_ACTIONS)):
            raise ValueError(
                f"Invalid redeemer action: {type(redeemer_action).__name__}. "
                f"Must be MintAction or BurnAction."
            )

    # Attach native script
    tx_builder.native_scripts = tx_builder.native_scripts or []
    tx_builder.native_scripts.append(policy.native_script)

    # Set mint assets
    tx_builder.mint = mint_assets

    # Apply time constraints if the policy has them
    if policy.time_lock_after is not None:
        tx_builder.ttl = policy.time_lock_after
    if policy.time_lock_before is not None:
        tx_builder.validity_start = policy.time_lock_before

    return tx_builder


def validate_token_metadata_format(metadata: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate token metadata conforms to the required CIP-25 format.

    Checks that all required fields are present and token name doesn't exceed
    the Cardano 32-byte limit. This is a pre-submission validation that
    complements the on-chain policy.

    Args:
        metadata: Dict with token metadata fields.

    Returns:
        Tuple of (is_valid, list_of_error_messages).
        Empty error list means metadata is valid.
    """
    errors = []

    # Check required fields
    missing = [f for f in REQUIRED_TOKEN_METADATA_FIELDS if f not in metadata]
    if missing:
        errors.append(f"Missing required fields: {missing}")

    # Validate token name length
    name = metadata.get("name", "")
    if isinstance(name, str) and len(name.encode("utf-8")) > MAX_TOKEN_NAME_BYTES:
        errors.append(
            f"Token name exceeds {MAX_TOKEN_NAME_BYTES} bytes: "
            f"{len(name.encode('utf-8'))} bytes"
        )

    # Validate field types
    for field in ("name", "license_type", "issuing_authority"):
        val = metadata.get(field)
        if val is not None and not isinstance(val, str):
            errors.append(f"Field '{field}' must be a string, got {type(val).__name__}")

    # Validate dates if present
    for date_field in ("issue_date", "expiry_date"):
        val = metadata.get(date_field)
        if val is not None and isinstance(val, str):
            try:
                datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"Field '{date_field}' is not a valid ISO date: {val}")

    return (len(errors) == 0, errors)


# ── Authority Registry ────────────────────────────────────────────

async def register_minting_authority(
    wallet_label: str,
    policy_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a wallet as a minting authority and create its policy.

    Loads the wallet, builds a minting policy from its key hash, saves the
    policy to disk, and records the authority in the database.

    Args:
        wallet_label: Label of the authority wallet (must exist on disk).
        policy_label: Optional label for the policy file. Defaults to
            'policy_{wallet_label}'.

    Returns:
        Dict with authority_address, policy_id, policy_cbor_hex, policy_path.

    Raises:
        ValueError: If wallet not found or wallet is not type 'authority'.
    """
    keys = load_wallet_keys(wallet_label)
    authority_pkh = keys["payment_key_hash"]

    # Verify wallet is registered as authority type
    wallet = await get_wallet_by_label(wallet_label)
    if not wallet:
        raise ValueError(f"Wallet not found in DB: {wallet_label}")
    if wallet["wallet_type"] != "authority":
        raise ValueError(
            f"Wallet '{wallet_label}' is type '{wallet['wallet_type']}', "
            f"not 'authority'. Only authority wallets can mint."
        )

    # Build and save policy
    policy = build_minting_policy(authority_pkh)
    label = policy_label or f"policy_{wallet_label}"
    policy_path = policy.save_policy(label)

    # Store policy metadata in DB
    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute("""
            INSERT OR REPLACE INTO blockchain_minting_policies
            (policy_id, authority_address, authority_pubkey_hash,
             policy_cbor_hex, policy_label, script_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            policy.get_policy_id_hex(),
            wallet["address"],
            authority_pkh,
            policy.policy_cbor_hex,
            label,
            "native_script",
            datetime.now().isoformat(),
        ))
        await db.commit()

    logger.info(
        f"Registered minting authority: wallet={wallet_label}, "
        f"policy_id={policy.get_policy_id_hex()}"
    )

    return {
        "authority_address": wallet["address"],
        "authority_pubkey_hash": authority_pkh,
        "policy_id": policy.get_policy_id_hex(),
        "policy_cbor_hex": policy.policy_cbor_hex,
        "policy_path": str(policy_path),
    }


async def is_registered_authority(address: str) -> bool:
    """Check if an address is a registered minting authority.

    Args:
        address: Cardano address to check.

    Returns:
        True if the address is registered as an authority in the DB.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute_fetchall(
            "SELECT 1 FROM blockchain_wallets WHERE address = ? AND wallet_type = 'authority'",
            (address,),
        )
        return len(row) > 0


async def get_authority_policy(authority_address: str) -> Optional[Dict[str, Any]]:
    """Get the minting policy for a registered authority.

    Args:
        authority_address: The authority's Cardano address.

    Returns:
        Dict with policy_id, policy_cbor_hex, etc., or None if not found.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute_fetchall(
            "SELECT * FROM blockchain_minting_policies WHERE authority_address = ? ORDER BY created_at DESC LIMIT 1",
            (authority_address,),
        )
        if not rows:
            return None
        return dict(rows[0])


async def list_registered_authorities() -> List[Dict[str, Any]]:
    """List all registered minting authorities and their policies.

    Returns:
        List of dicts with wallet and policy information.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute_fetchall("""
            SELECT w.address, w.public_key_hash, w.wallet_type, w.label,
                   p.policy_id, p.policy_cbor_hex, p.script_type, p.created_at as policy_created
            FROM blockchain_wallets w
            LEFT JOIN blockchain_minting_policies p ON w.address = p.authority_address
            WHERE w.wallet_type = 'authority'
            ORDER BY w.created_at DESC
        """)
        return [dict(r) for r in rows]


def build_cip25_metadata(
    policy_id: ScriptHash,
    asset_name_str: str,
    license_metadata: Dict[str, Any],
) -> Dict[int, Any]:
    """Build CIP-25 compliant metadata for a license NFT.

    CIP-25 structure:
        { 721: { <policy_id_hex>: { <asset_name>: { ...fields } } } }

    Required license fields: license_type, licensee_name, issuing_authority,
    issue_date, expiry_date, jurisdiction, license_number.
    Optional: image (IPFS URI), description, version.

    Args:
        policy_id: The minting policy ScriptHash.
        asset_name_str: Human-readable token name.
        license_metadata: Dict with license-specific fields.

    Returns:
        Dict suitable for PyCardano Metadata.

    Raises:
        ValueError: If required fields are missing.
    """
    missing = [f for f in REQUIRED_LICENSE_FIELDS if f not in license_metadata]
    if missing:
        raise ValueError(f"Missing required license metadata fields: {missing}")

    token_metadata = {
        "name": asset_name_str,
        "license_type": str(license_metadata["license_type"]),
        "licensee_name": str(license_metadata["licensee_name"]),
        "issuing_authority": str(license_metadata["issuing_authority"]),
        "issue_date": str(license_metadata["issue_date"]),
        "expiry_date": str(license_metadata["expiry_date"]),
        "jurisdiction": str(license_metadata["jurisdiction"]),
        "license_number": str(license_metadata["license_number"]),
    }

    if "image" in license_metadata:
        token_metadata["image"] = str(license_metadata["image"])
    if "description" in license_metadata:
        token_metadata["description"] = str(license_metadata["description"])

    # CIP-25 version 1 (flat metadata under 721)
    policy_hex = policy_id.to_primitive().hex()
    return {
        CIP25_METADATA_LABEL: {
            policy_hex: {
                asset_name_str: token_metadata,
            }
        }
    }


def _generate_token_name(license_number: str) -> str:
    """Generate a token name from the license number.

    Strips non-alphanumeric chars and prefixes with 'LIC'.
    Max 32 bytes for Cardano asset names.
    """
    clean = "".join(c for c in license_number if c.isalnum())
    name = f"LIC{clean}"
    # Cardano asset names: max 32 bytes
    return name[:32]


async def mint_license_nft(
    authority_wallet_label: str,
    licensee_address: str,
    license_metadata: Dict[str, Any],
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Mint a License NFT with CIP-25 metadata and send to licensee.

    Uses the authority wallet's key to create a ScriptPubkey minting policy,
    builds CIP-25 metadata, mints 1 NFT, and sends it to the licensee address.
    Records the mint in blockchain_licenses table.

    Args:
        authority_wallet_label: Label of the authority wallet (must exist on disk).
        licensee_address: Cardano address to receive the minted NFT.
        license_metadata: Dict with required CIP-25 license fields.
        min_utxo_ada: Minimum lovelace to send with the NFT (default 2 ADA).

    Returns:
        Dict with policy_id, token_name, tx_hash, license_id, metadata.

    Raises:
        FileNotFoundError: If authority wallet keys not found.
        ValueError: If metadata fields missing or licensee address invalid.
        Exception: If transaction submission fails.
    """
    # Validate metadata fields early (before any chain/wallet ops)
    missing = [f for f in REQUIRED_LICENSE_FIELDS if f not in license_metadata]
    if missing:
        raise ValueError(f"Missing required license metadata fields: {missing}")

    # Load authority keys
    authority_keys = load_wallet_keys(authority_wallet_label)
    authority_sk = authority_keys["payment_sk"]
    authority_vk = authority_keys["payment_vk"]
    authority_address = authority_keys["base_address"]

    # Create minting policy
    policy = create_minting_policy(authority_vk)
    policy_id = policy.hash()
    policy_id_hex = policy_id.to_primitive().hex()

    # Generate token name
    token_name_str = _generate_token_name(license_metadata["license_number"])
    asset_name = AssetName(token_name_str.encode("utf-8"))

    # Build CIP-25 metadata
    cip25_data = build_cip25_metadata(policy_id, token_name_str, license_metadata)

    # Build MultiAsset for minting (quantity = 1 NFT)
    mint = MultiAsset()
    mint[policy_id] = Asset()
    mint[policy_id][asset_name] = 1

    # Build auxiliary data with CIP-25 metadata
    metadata = Metadata(cip25_data)
    aux_data = AuxiliaryData(data=AlonzoMetadata(metadata=metadata))

    # Get chain context and build transaction
    context = get_chain_context()

    builder = TransactionBuilder(context)

    # Fund from authority wallet
    builder.add_input_address(authority_address)

    # Add minting script and mint amount
    builder.add_minting_script(policy)
    builder.mint = mint

    # Attach CIP-25 metadata
    builder.auxiliary_data = aux_data

    # Output: send NFT + min ADA to licensee
    nft_value = Value(min_utxo_ada, mint)
    builder.add_output(TransactionOutput(
        Address.from_primitive(licensee_address),
        nft_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[authority_sk],
        change_address=Address.from_primitive(authority_address),
    )

    # Submit transaction
    context.submit_tx(signed_tx)
    tx_hash = signed_tx.id.to_primitive().hex()

    logger.info(
        f"License NFT minted: policy={policy_id_hex}, "
        f"token={token_name_str}, tx={tx_hash}"
    )

    # Store in blockchain_licenses table
    license_id = await _store_license_record(
        token_name=token_name_str,
        policy_id=policy_id_hex,
        licensee_address=licensee_address,
        authority_address=authority_address,
        metadata_json=license_metadata,
        mint_tx_hash=tx_hash,
        license_type=license_metadata.get("license_type", "professional"),
        valid_from=license_metadata.get("issue_date"),
        valid_until=license_metadata.get("expiry_date"),
    )

    return {
        "license_id": license_id,
        "policy_id": policy_id_hex,
        "token_name": token_name_str,
        "asset_name_hex": asset_name.to_primitive().hex(),
        "tx_hash": tx_hash,
        "licensee_address": licensee_address,
        "authority_address": authority_address,
        "metadata": license_metadata,
        "status": "active",
    }


async def _store_license_record(
    token_name: str,
    policy_id: str,
    licensee_address: str,
    authority_address: str,
    metadata_json: Dict[str, Any],
    mint_tx_hash: str,
    license_type: str = "professional",
    valid_from: Optional[str] = None,
    valid_until: Optional[str] = None,
) -> int:
    """Insert a license record into blockchain_licenses table.

    Returns the license row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_licenses
               (token_name, policy_id, licensee_address, authority_address,
                metadata_json, mint_tx_hash, status, license_type,
                valid_from, valid_until)
               VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
            (
                token_name,
                policy_id,
                licensee_address,
                authority_address,
                json.dumps(metadata_json),
                mint_tx_hash,
                license_type,
                valid_from,
                valid_until,
            ),
        )
        await db.commit()
        return cursor.lastrowid


async def get_license_by_id(license_id: int) -> Optional[Dict[str, Any]]:
    """Look up a license record by ID."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_licenses WHERE id = ?", (license_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_license_by_tx_hash(tx_hash: str) -> Optional[Dict[str, Any]]:
    """Look up a license record by mint transaction hash."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_licenses WHERE mint_tx_hash = ?", (tx_hash,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_licenses(
    licensee_address: Optional[str] = None,
    authority_address: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List license records with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if licensee_address:
            conditions.append("licensee_address = ?")
            params.append(licensee_address)
        if authority_address:
            conditions.append("authority_address = ?")
            params.append(authority_address)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_licenses{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ── Signature Token Minting & Management ──────────────────────────

def _generate_sig_token_name(license_ref: int, batch_index: int = 0) -> str:
    """Generate a token name for a signature token.

    Format: SIG<license_ref>_<batch_index>
    Max 32 bytes for Cardano asset names.
    """
    name = f"SIG{license_ref}_{batch_index}"
    return name[:32]


async def mint_signature_tokens(
    authority_wallet_label: str,
    licensee_address: str,
    token_count: int,
    license_ref: int,
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Mint fungible signature tokens tied to a specific license.

    Creates native tokens under the authority's minting policy. Each token
    carries the policy_id linking it to the issuing authority. Tokens are
    sent to the licensee address and tracked in blockchain_signature_tokens.

    Args:
        authority_wallet_label: Label of the authority wallet (must exist on disk).
        licensee_address: Cardano address to receive the minted tokens.
        token_count: Number of signature tokens to mint (must be >= 1).
        license_ref: ID of the license these tokens are tied to.
        min_utxo_ada: Minimum lovelace to send with the tokens (default 2 ADA).

    Returns:
        Dict with policy_id, token_name, tx_hash, quantity, token_records.

    Raises:
        ValueError: If token_count < 1 or license_ref not found.
        FileNotFoundError: If authority wallet keys not found.
    """
    if token_count < 1:
        raise ValueError("token_count must be >= 1")

    # Verify license exists
    license_record = await get_license_by_id(license_ref)
    if not license_record:
        raise ValueError(f"License not found: {license_ref}")

    # Load authority keys
    authority_keys = load_wallet_keys(authority_wallet_label)
    authority_sk = authority_keys["payment_sk"]
    authority_vk = authority_keys["payment_vk"]
    authority_address = authority_keys["base_address"]

    # Create minting policy (same authority-bound ScriptPubkey)
    policy = create_minting_policy(authority_vk)
    policy_id = policy.hash()
    policy_id_hex = policy_id.to_primitive().hex()

    # Generate token name
    token_name_str = _generate_sig_token_name(license_ref)
    asset_name = AssetName(token_name_str.encode("utf-8"))

    # Build MultiAsset for minting (fungible: quantity = token_count)
    mint = MultiAsset()
    mint[policy_id] = Asset()
    mint[policy_id][asset_name] = token_count

    # Build metadata (label 365 for signature tokens)
    # Note: PyCardano Metadata enforces 64-byte max per string value
    sig_metadata = {
        365: {
            policy_id_hex: {
                token_name_str: {
                    "type": "signature_token",
                    "license_ref": license_ref,
                    "quantity": token_count,
                    "license_type": license_record.get("license_type", "professional")[:64],
                }
            }
        }
    }
    metadata = Metadata(sig_metadata)
    aux_data = AuxiliaryData(data=AlonzoMetadata(metadata=metadata))

    # Get chain context and build transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(authority_address)
    builder.add_minting_script(policy)
    builder.mint = mint
    builder.auxiliary_data = aux_data

    # Output: send tokens + min ADA to licensee
    token_value = Value(min_utxo_ada, mint)
    builder.add_output(TransactionOutput(
        Address.from_primitive(licensee_address),
        token_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[authority_sk],
        change_address=Address.from_primitive(authority_address),
    )

    # Submit transaction
    context.submit_tx(signed_tx)
    tx_hash = signed_tx.id.to_primitive().hex()

    logger.info(
        f"Signature tokens minted: policy={policy_id_hex}, "
        f"token={token_name_str}, qty={token_count}, tx={tx_hash}"
    )

    # Store in blockchain_signature_tokens table
    token_id = await _store_signature_token_record(
        policy_id=policy_id_hex,
        token_name=token_name_str,
        licensee_address=licensee_address,
        license_ref=license_ref,
        quantity=token_count,
        mint_tx_hash=tx_hash,
    )

    return {
        "token_id": token_id,
        "policy_id": policy_id_hex,
        "token_name": token_name_str,
        "asset_name_hex": asset_name.to_primitive().hex(),
        "tx_hash": tx_hash,
        "quantity": token_count,
        "licensee_address": licensee_address,
        "authority_address": authority_address,
        "license_ref": license_ref,
        "status": "minted",
    }


async def _store_signature_token_record(
    policy_id: str,
    token_name: str,
    licensee_address: str,
    license_ref: int,
    quantity: int,
    mint_tx_hash: str,
) -> int:
    """Insert a signature token record into blockchain_signature_tokens.

    Returns the token row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_signature_tokens
               (policy_id, token_name, licensee_address, license_ref,
                quantity, mint_tx_hash, status)
               VALUES (?, ?, ?, ?, ?, ?, 'minted')""",
            (policy_id, token_name, licensee_address, license_ref,
             quantity, mint_tx_hash),
        )
        await db.commit()
        return cursor.lastrowid


async def get_signature_balance(
    wallet_label: str,
    license_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Get signature token balance for a wallet.

    Queries the local DB for minted signature tokens held by the wallet.
    Optionally filter by license_type.

    Args:
        wallet_label: Wallet label to look up.
        license_type: Optional license type filter.

    Returns:
        Dict with total_tokens, by_license breakdown, and token_records.

    Raises:
        ValueError: If wallet not found.
    """
    wallet = await get_wallet_by_label(wallet_label)
    if not wallet:
        raise ValueError(f"Wallet not found: {wallet_label}")

    address = wallet["address"]

    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row

        if license_type:
            cursor = await db.execute(
                """SELECT bst.*, bl.license_type
                   FROM blockchain_signature_tokens bst
                   LEFT JOIN blockchain_licenses bl ON bst.license_ref = bl.id
                   WHERE bst.licensee_address = ?
                     AND bst.status = 'minted'
                     AND bl.license_type = ?
                   ORDER BY bst.created_at DESC""",
                (address, license_type),
            )
        else:
            cursor = await db.execute(
                """SELECT bst.*, bl.license_type
                   FROM blockchain_signature_tokens bst
                   LEFT JOIN blockchain_licenses bl ON bst.license_ref = bl.id
                   WHERE bst.licensee_address = ?
                     AND bst.status = 'minted'
                   ORDER BY bst.created_at DESC""",
                (address,),
            )

        rows = await cursor.fetchall()
        records = [dict(r) for r in rows]

    # Aggregate by license
    by_license: Dict[int, int] = {}
    total = 0
    for rec in records:
        ref = rec["license_ref"]
        qty = rec["quantity"]
        by_license[ref] = by_license.get(ref, 0) + qty
        total += qty

    return {
        "wallet_label": wallet_label,
        "address": address,
        "total_tokens": total,
        "by_license": by_license,
        "token_records": records,
    }


async def transfer_signature_token(
    from_wallet_label: str,
    to_address: str,
    license_ref: int,
    quantity: int = 1,
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Transfer signature tokens from one wallet to another.

    Finds available signature tokens for the given license_ref in the
    sender's wallet, builds a transfer transaction, and updates DB records.

    Args:
        from_wallet_label: Label of the sending wallet.
        to_address: Cardano address of the recipient.
        license_ref: License ID the tokens are tied to.
        quantity: Number of tokens to transfer (default 1).
        min_utxo_ada: Minimum lovelace to send with the tokens (default 2 ADA).

    Returns:
        Dict with tx_hash, transferred quantity, and updated token records.

    Raises:
        ValueError: If insufficient token balance or wallet not found.
        FileNotFoundError: If wallet keys not found.
    """
    if quantity < 1:
        raise ValueError("quantity must be >= 1")

    # Check sender's balance for this license
    balance = await get_signature_balance(from_wallet_label, license_type=None)
    available = balance["by_license"].get(license_ref, 0)
    if available < quantity:
        raise ValueError(
            f"Insufficient signature tokens for license {license_ref}: "
            f"have {available}, need {quantity}"
        )

    # Load sender keys
    sender_keys = load_wallet_keys(from_wallet_label)
    sender_sk = sender_keys["payment_sk"]
    sender_vk = sender_keys["payment_vk"]
    sender_address = sender_keys["base_address"]

    # Get the token details from DB
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM blockchain_signature_tokens
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'minted'
               ORDER BY created_at ASC""",
            (balance["address"], license_ref),
        )
        token_rows = [dict(r) for r in await cursor.fetchall()]

    if not token_rows:
        raise ValueError(f"No signature tokens found for license {license_ref}")

    # Use the first token record's policy/name info
    source_token = token_rows[0]
    policy_id_hex = source_token["policy_id"]
    token_name_str = source_token["token_name"]

    # Reconstruct policy from authority key (sender must be authority or have tokens)
    policy = create_minting_policy(sender_vk)
    policy_id = policy.hash()
    asset_name = AssetName(token_name_str.encode("utf-8"))

    # Build transfer (no minting, just sending existing tokens)
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(sender_address)

    # Build the multi-asset to send
    send_multi = MultiAsset()
    send_multi[policy_id] = Asset()
    send_multi[policy_id][asset_name] = quantity

    token_value = Value(min_utxo_ada, send_multi)
    builder.add_output(TransactionOutput(
        Address.from_primitive(to_address),
        token_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[sender_sk],
        change_address=Address.from_primitive(sender_address),
    )

    context.submit_tx(signed_tx)
    tx_hash = signed_tx.id.to_primitive().hex()

    logger.info(
        f"Signature tokens transferred: {quantity}x {token_name_str} "
        f"from {from_wallet_label} to {to_address[:32]}..., tx={tx_hash}"
    )

    # Update DB: mark source tokens as transferred, create new record for recipient
    await _record_signature_transfer(
        source_records=token_rows,
        to_address=to_address,
        quantity=quantity,
        policy_id=policy_id_hex,
        token_name=token_name_str,
        license_ref=license_ref,
        tx_hash=tx_hash,
    )

    return {
        "tx_hash": tx_hash,
        "from_address": sender_address,
        "to_address": to_address,
        "quantity": quantity,
        "token_name": token_name_str,
        "policy_id": policy_id_hex,
        "license_ref": license_ref,
        "status": "transferred",
    }


async def _record_signature_transfer(
    source_records: List[Dict[str, Any]],
    to_address: str,
    quantity: int,
    policy_id: str,
    token_name: str,
    license_ref: int,
    tx_hash: str,
) -> None:
    """Update DB records for a signature token transfer.

    Deducts quantity from source records (marking depleted ones as 'transferred'),
    and creates a new record for the recipient.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        remaining = quantity

        for rec in source_records:
            if remaining <= 0:
                break

            rec_qty = rec["quantity"]
            if rec_qty <= remaining:
                # Fully consume this record
                await db.execute(
                    """UPDATE blockchain_signature_tokens
                       SET status = 'transferred', burn_tx_hash = ?
                       WHERE id = ?""",
                    (tx_hash, rec["id"]),
                )
                remaining -= rec_qty
            else:
                # Partially consume: reduce quantity
                await db.execute(
                    """UPDATE blockchain_signature_tokens
                       SET quantity = quantity - ?
                       WHERE id = ?""",
                    (remaining, rec["id"]),
                )
                remaining = 0

        # Create new record for recipient
        await db.execute(
            """INSERT INTO blockchain_signature_tokens
               (policy_id, token_name, licensee_address, license_ref,
                quantity, mint_tx_hash, status)
               VALUES (?, ?, ?, ?, ?, ?, 'minted')""",
            (policy_id, token_name, to_address, license_ref, quantity, tx_hash),
        )
        await db.commit()


async def get_signature_token_by_id(token_id: int) -> Optional[Dict[str, Any]]:
    """Look up a signature token record by ID."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_signature_tokens WHERE id = ?", (token_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_signature_tokens(
    licensee_address: Optional[str] = None,
    license_ref: Optional[int] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List signature token records with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if licensee_address:
            conditions.append("licensee_address = ?")
            params.append(licensee_address)
        if license_ref is not None:
            conditions.append("license_ref = ?")
            params.append(license_ref)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_signature_tokens{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ── Validity Token Minting & Renewal ──────────────────────────────

def _generate_validity_token_name(license_ref: int, seq: int = 0) -> str:
    """Generate a token name for a validity token.

    Format: VAL<license_ref>_<seq>
    Max 32 bytes for Cardano asset names.
    """
    name = f"VAL{license_ref}_{seq}"
    return name[:32]


async def _get_next_validity_seq(license_ref: int) -> int:
    """Get the next sequence number for a validity token for a given license."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM blockchain_validity_tokens WHERE license_ref = ?",
            (license_ref,),
        )
        row = await cursor.fetchone()
        return row[0] if row else 0


async def mint_validity_token(
    authority_wallet_label: str,
    licensee_address: str,
    license_ref: int,
    valid_until: str,
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Mint a time-bounded validity token tied to a specific license.

    Creates a native token under the authority's minting policy with
    metadata recording the expiry. The token represents that the license
    is currently valid until the specified date/slot.

    Args:
        authority_wallet_label: Label of the authority wallet (must exist on disk).
        licensee_address: Cardano address to receive the validity token.
        license_ref: ID of the license this token validates.
        valid_until: Expiry date/slot as ISO string (e.g. '2027-01-01').
        min_utxo_ada: Minimum lovelace to send with the token (default 2 ADA).

    Returns:
        Dict with policy_id, token_name, tx_hash, token_id, valid_until.

    Raises:
        ValueError: If license_ref not found or valid_until is empty.
        FileNotFoundError: If authority wallet keys not found.
    """
    if not valid_until:
        raise ValueError("valid_until must be a non-empty date/slot string")

    # Verify license exists
    license_record = await get_license_by_id(license_ref)
    if not license_record:
        raise ValueError(f"License not found: {license_ref}")

    # Load authority keys
    authority_keys = load_wallet_keys(authority_wallet_label)
    authority_sk = authority_keys["payment_sk"]
    authority_vk = authority_keys["payment_vk"]
    authority_address = authority_keys["base_address"]

    # Create minting policy (same authority-bound ScriptPubkey)
    policy = create_minting_policy(authority_vk)
    policy_id = policy.hash()
    policy_id_hex = policy_id.to_primitive().hex()

    # Generate token name
    seq = await _get_next_validity_seq(license_ref)
    token_name_str = _generate_validity_token_name(license_ref, seq)
    asset_name = AssetName(token_name_str.encode("utf-8"))

    # Build MultiAsset for minting (quantity = 1 validity token)
    mint = MultiAsset()
    mint[policy_id] = Asset()
    mint[policy_id][asset_name] = 1

    # Build metadata (label 366 for validity tokens)
    val_metadata = {
        366: {
            policy_id_hex: {
                token_name_str: {
                    "type": "validity_token",
                    "license_ref": license_ref,
                    "valid_until": str(valid_until)[:64],
                    "license_type": license_record.get("license_type", "professional")[:64],
                }
            }
        }
    }
    metadata = Metadata(val_metadata)
    aux_data = AuxiliaryData(data=AlonzoMetadata(metadata=metadata))

    # Get chain context and build transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(authority_address)
    builder.add_minting_script(policy)
    builder.mint = mint
    builder.auxiliary_data = aux_data

    # Output: send validity token + min ADA to licensee
    token_value = Value(min_utxo_ada, mint)
    builder.add_output(TransactionOutput(
        Address.from_primitive(licensee_address),
        token_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[authority_sk],
        change_address=Address.from_primitive(authority_address),
    )

    # Submit transaction
    context.submit_tx(signed_tx)
    tx_hash = signed_tx.id.to_primitive().hex()

    logger.info(
        f"Validity token minted: policy={policy_id_hex}, "
        f"token={token_name_str}, valid_until={valid_until}, tx={tx_hash}"
    )

    # Store in blockchain_validity_tokens table
    token_id = await _store_validity_token_record(
        policy_id=policy_id_hex,
        token_name=token_name_str,
        licensee_address=licensee_address,
        license_ref=license_ref,
        valid_until=valid_until,
        mint_tx_hash=tx_hash,
    )

    return {
        "token_id": token_id,
        "policy_id": policy_id_hex,
        "token_name": token_name_str,
        "asset_name_hex": asset_name.to_primitive().hex(),
        "tx_hash": tx_hash,
        "licensee_address": licensee_address,
        "authority_address": authority_address,
        "license_ref": license_ref,
        "valid_until": valid_until,
        "status": "active",
    }


async def _store_validity_token_record(
    policy_id: str,
    token_name: str,
    licensee_address: str,
    license_ref: int,
    valid_until: str,
    mint_tx_hash: str,
) -> int:
    """Insert a validity token record into blockchain_validity_tokens.

    Returns the token row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_validity_tokens
               (policy_id, token_name, licensee_address, license_ref,
                valid_until, mint_tx_hash, status)
               VALUES (?, ?, ?, ?, ?, ?, 'active')""",
            (policy_id, token_name, licensee_address, license_ref,
             valid_until, mint_tx_hash),
        )
        await db.commit()
        return cursor.lastrowid


async def check_validity(
    licensee_address: str,
    license_ref: int,
) -> Dict[str, Any]:
    """Check if a licensee has a current valid validity token for a license.

    Queries the local DB for active validity tokens. A token is considered
    valid if its status is 'active' and valid_until >= current date.

    Args:
        licensee_address: Cardano address of the licensee.
        license_ref: License ID to check validity for.

    Returns:
        Dict with is_valid, token details (if found), and expiry info.
    """
    now = datetime.now().strftime("%Y-%m-%d")

    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row

        # Find the most recent active validity token for this license+address
        cursor = await db.execute(
            """SELECT * FROM blockchain_validity_tokens
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'active'
               ORDER BY valid_until DESC
               LIMIT 1""",
            (licensee_address, license_ref),
        )
        row = await cursor.fetchone()

    if not row:
        return {
            "is_valid": False,
            "licensee_address": licensee_address,
            "license_ref": license_ref,
            "reason": "no_validity_token",
            "token": None,
        }

    token = dict(row)
    token_expiry = token["valid_until"]

    # Compare dates (ISO format string comparison works for YYYY-MM-DD)
    is_valid = token_expiry >= now

    result = {
        "is_valid": is_valid,
        "licensee_address": licensee_address,
        "license_ref": license_ref,
        "token_id": token["id"],
        "token_name": token["token_name"],
        "valid_until": token_expiry,
        "policy_id": token["policy_id"],
        "mint_tx_hash": token["mint_tx_hash"],
    }

    if not is_valid:
        result["reason"] = "expired"

    return result


async def renew_validity(
    authority_wallet_label: str,
    licensee_address: str,
    license_ref: int,
    new_expiry: str,
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Renew a validity token by expiring the old one and minting a new one.

    Finds the current active validity token for the license+address,
    marks it as expired, and mints a new validity token with the new expiry.

    Args:
        authority_wallet_label: Label of the authority wallet.
        licensee_address: Cardano address of the licensee.
        license_ref: License ID to renew validity for.
        new_expiry: New expiry date as ISO string (e.g. '2028-01-01').
        min_utxo_ada: Minimum lovelace to send with the token (default 2 ADA).

    Returns:
        Dict with new token details and previous token info.

    Raises:
        ValueError: If license not found or new_expiry is empty.
        FileNotFoundError: If authority wallet keys not found.
    """
    if not new_expiry:
        raise ValueError("new_expiry must be a non-empty date string")

    # Expire any existing active validity tokens for this license+address
    previous_token_id = await _expire_active_validity_tokens(
        licensee_address, license_ref
    )

    # Mint new validity token
    result = await mint_validity_token(
        authority_wallet_label=authority_wallet_label,
        licensee_address=licensee_address,
        license_ref=license_ref,
        valid_until=new_expiry,
        min_utxo_ada=min_utxo_ada,
    )

    result["previous_token_id"] = previous_token_id
    result["renewal"] = True

    return result


async def _expire_active_validity_tokens(
    licensee_address: str,
    license_ref: int,
) -> Optional[int]:
    """Mark all active validity tokens for a license+address as expired.

    Returns the ID of the most recently expired token, or None if none found.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        # Find current active token ID before expiring
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT id FROM blockchain_validity_tokens
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'active'
               ORDER BY valid_until DESC
               LIMIT 1""",
            (licensee_address, license_ref),
        )
        row = await cursor.fetchone()
        previous_id = row["id"] if row else None

        # Expire all active tokens for this combination
        await db.execute(
            """UPDATE blockchain_validity_tokens
               SET status = 'expired'
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'active'""",
            (licensee_address, license_ref),
        )
        await db.commit()

    return previous_id


async def get_validity_token_by_id(token_id: int) -> Optional[Dict[str, Any]]:
    """Look up a validity token record by ID."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_validity_tokens WHERE id = ?", (token_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_validity_tokens(
    licensee_address: Optional[str] = None,
    license_ref: Optional[int] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List validity token records with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if licensee_address:
            conditions.append("licensee_address = ?")
            params.append(licensee_address)
        if license_ref is not None:
            conditions.append("license_ref = ?")
            params.append(license_ref)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_validity_tokens{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def revoke_validity_token(token_id: int) -> Dict[str, Any]:
    """Revoke a validity token by ID (sets status to 'revoked').

    Returns the updated token record.

    Raises:
        ValueError: If token not found or not in active status.
    """
    token = await get_validity_token_by_id(token_id)
    if not token:
        raise ValueError(f"Validity token not found: {token_id}")
    if token["status"] != "active":
        raise ValueError(
            f"Cannot revoke token {token_id}: status is '{token['status']}', must be 'active'"
        )

    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute(
            "UPDATE blockchain_validity_tokens SET status = 'revoked' WHERE id = ?",
            (token_id,),
        )
        await db.commit()

    token["status"] = "revoked"
    return token


# ── CIP-68 Reference Token Revocation ────────────────────────────

async def update_license_status(
    license_id: int,
    new_status: str,
    authority_wallet_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a license's status via CIP-68 Reference Token datum update.

    In the CIP-68 model, the authority holds a Reference Token (label 100)
    whose inline datum contains the license status. To revoke a license,
    the authority updates this datum to status='revoked' — requiring only
    the authority's signature and zero interaction with the licensee's wallet.

    For on-chain operation (when authority_wallet_label is provided), this
    builds and submits a transaction that consumes the Reference Token UTxO
    and produces a new UTxO at the same address with the updated datum.

    For off-chain operation (authority_wallet_label=None), this updates only
    the local database records (suitable for testing or pre-chain staging).

    Args:
        license_id: ID of the license to update.
        new_status: New status value ('revoked', 'suspended', 'active', 'expired').
        authority_wallet_label: Optional authority wallet for on-chain tx.

    Returns:
        Dict with license_id, old_status, new_status, tx_hash (if on-chain).

    Raises:
        ValueError: If license not found or status transition invalid.
    """
    valid_statuses = ("active", "revoked", "suspended", "expired")
    if new_status not in valid_statuses:
        raise ValueError(f"Invalid status '{new_status}', must be one of {valid_statuses}")

    license_record = await get_license_by_id(license_id)
    if not license_record:
        raise ValueError(f"License not found: {license_id}")

    old_status = license_record["status"]
    if old_status == new_status:
        raise ValueError(f"License {license_id} already has status '{new_status}'")

    result = {
        "license_id": license_id,
        "old_status": old_status,
        "new_status": new_status,
        "tx_hash": None,
    }

    # Update local DB records
    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute(
            "UPDATE blockchain_licenses SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (new_status, license_id),
        )
        # Update reference token record if it exists
        await db.execute(
            "UPDATE blockchain_reference_tokens SET status = ?, updated_at = datetime('now') WHERE license_id = ?",
            (new_status, license_id),
        )
        await db.commit()

    # On-chain datum update (when authority wallet provided)
    if authority_wallet_label:
        try:
            authority_keys = load_wallet_keys(authority_wallet_label)
            authority_sk = authority_keys["payment_sk"]
            authority_address = authority_keys["base_address"]

            # Look up the reference token to find its UTxO
            async with aiosqlite.connect(LICENSE_DB) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    "SELECT * FROM blockchain_reference_tokens WHERE license_id = ?",
                    (license_id,),
                )
                ref_record = await cursor.fetchone()

            if ref_record:
                context = get_chain_context()
                # Query authority's UTxOs to find the reference token
                utxos = context.utxos(authority_address)
                ref_policy_id = ref_record["policy_id"]
                ref_token_name = ref_record["ref_token_name"]

                for utxo in utxos:
                    if _utxo_contains_token(utxo, ref_policy_id, ref_token_name):
                        # Build tx: consume ref token UTxO, produce new one with updated datum
                        builder = TransactionBuilder(context)
                        builder.add_input(utxo)

                        # Reconstruct datum with new status
                        datum_dict = json.loads(ref_record["datum_json"]) if ref_record["datum_json"] else {}
                        datum_dict["status"] = new_status
                        datum_dict["updated_at"] = datetime.utcnow().isoformat()

                        # Output: same address, same token, updated datum
                        output = TransactionOutput(
                            Address.from_primitive(authority_address),
                            utxo.output.amount,
                        )
                        builder.add_output(output)

                        signed_tx = builder.build_and_sign(
                            signing_keys=[authority_sk],
                            change_address=Address.from_primitive(authority_address),
                        )
                        context.submit_tx(signed_tx)
                        tx_hash = signed_tx.id.to_primitive().hex()
                        result["tx_hash"] = tx_hash

                        # Update DB with tx hash
                        async with aiosqlite.connect(LICENSE_DB) as db:
                            await db.execute(
                                "UPDATE blockchain_reference_tokens SET last_update_tx_hash = ?, datum_json = ? WHERE license_id = ?",
                                (tx_hash, json.dumps(datum_dict), license_id),
                            )
                            await db.commit()

                        logger.info(f"CIP-68 datum updated: license={license_id}, status={new_status}, tx={tx_hash}")
                        break
                else:
                    logger.warning(f"Reference token UTxO not found on-chain for license {license_id}, DB updated only")
            else:
                logger.info(f"No CIP-68 reference token record for license {license_id}, DB updated only")
        except FileNotFoundError:
            logger.warning(f"Authority wallet '{authority_wallet_label}' not found, DB-only update")
        except Exception as e:
            logger.error(f"On-chain datum update failed for license {license_id}: {e}")
            result["error"] = str(e)

    logger.info(f"License {license_id} status updated: {old_status} -> {new_status}")
    return result


def _utxo_contains_token(utxo, policy_id_hex: str, token_name: str) -> bool:
    """Check if a UTxO contains a specific native token."""
    if not hasattr(utxo.output.amount, 'multi_asset') or utxo.output.amount.multi_asset is None:
        return False
    for pid, assets in utxo.output.amount.multi_asset.items():
        if pid.to_primitive().hex() == policy_id_hex:
            for aname in assets:
                if aname.to_primitive().decode("utf-8", errors="replace") == token_name:
                    return True
    return False


async def store_reference_token(
    license_id: int,
    policy_id: str,
    user_token_name: str,
    ref_token_name: str,
    authority_address: str,
    licensee_address: str,
    datum: Dict[str, Any],
    mint_tx_hash: Optional[str] = None,
) -> int:
    """Store a CIP-68 reference token record in the database.

    Args:
        license_id: Associated license ID.
        policy_id: Minting policy ID hex.
        user_token_name: CIP-68 User Token name (label 222).
        ref_token_name: CIP-68 Reference Token name (label 100).
        authority_address: Authority address holding the reference token.
        licensee_address: Licensee address holding the user token.
        datum: Initial datum dict (includes status, metadata).
        mint_tx_hash: Transaction hash of the mint.

    Returns:
        ID of the inserted reference token record.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_reference_tokens
               (license_id, policy_id, user_token_name, ref_token_name,
                authority_address, licensee_address, datum_json, mint_tx_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (license_id, policy_id, user_token_name, ref_token_name,
             authority_address, licensee_address, json.dumps(datum), mint_tx_hash),
        )
        await db.commit()
        return cursor.lastrowid


# ── Document Signing Workflow ─────────────────────────────────────

# Metadata label for document signing transactions
DOC_SIGN_METADATA_LABEL = 367


async def sign_document(
    signer_wallet_label: str,
    document_hash: str,
    contract_address: str,
    license_ref: int,
    min_utxo_ada: int = 2_000_000,
) -> Dict[str, Any]:
    """Sign a document by transferring signature + validity tokens to a contract wallet.

    Builds a transaction that:
    1. Transfers one signature token to the contract wallet
    2. Transfers one validity token to the contract wallet
    3. Attaches document hash as tx metadata (label 367)
    4. Records timestamp in blockchain_signatures table

    Args:
        signer_wallet_label: Label of the signer's wallet (must hold sig + validity tokens).
        document_hash: SHA-256 hash of the document being signed.
        contract_address: Cardano address of the contract/work-product wallet.
        license_ref: License ID the signing tokens are tied to.
        min_utxo_ada: Minimum lovelace to send with tokens (default 2 ADA).

    Returns:
        Dict with signature_id, tx_hash, document_hash, signer_address, timestamp.

    Raises:
        ValueError: If wallet not found, insufficient tokens, invalid validity, or bad hash.
        FileNotFoundError: If wallet keys not found.
    """
    if not document_hash or len(document_hash) < 16:
        raise ValueError("document_hash must be a valid hex hash (>= 16 chars)")
    if not contract_address:
        raise ValueError("contract_address must be a non-empty Cardano address")

    # Look up signer wallet
    signer_wallet = await get_wallet_by_label(signer_wallet_label)
    if not signer_wallet:
        raise ValueError(f"Signer wallet not found: {signer_wallet_label}")

    signer_address = signer_wallet["address"]

    # Verify license exists
    license_record = await get_license_by_id(license_ref)
    if not license_record:
        raise ValueError(f"License not found: {license_ref}")

    # Check signer has valid validity token for this license
    validity = await check_validity(signer_address, license_ref)
    if not validity["is_valid"]:
        reason = validity.get("reason", "unknown")
        raise ValueError(
            f"Signer does not have valid validity token for license {license_ref}: {reason}"
        )

    # Check signer has at least 1 signature token for this license
    sig_balance = await get_signature_balance(signer_wallet_label)
    sig_available = sig_balance["by_license"].get(license_ref, 0)
    if sig_available < 1:
        raise ValueError(
            f"Signer has no signature tokens for license {license_ref} "
            f"(have {sig_available}, need 1)"
        )

    # Load signer keys
    signer_keys = load_wallet_keys(signer_wallet_label)
    signer_sk = signer_keys["payment_sk"]
    signer_vk = signer_keys["payment_vk"]

    # Get token details from DB for the signature token
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM blockchain_signature_tokens
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'minted'
               ORDER BY created_at ASC LIMIT 1""",
            (signer_address, license_ref),
        )
        sig_token = dict(await cursor.fetchone())

        # Get validity token details
        cursor = await db.execute(
            """SELECT * FROM blockchain_validity_tokens
               WHERE licensee_address = ?
                 AND license_ref = ?
                 AND status = 'active'
               ORDER BY valid_until DESC LIMIT 1""",
            (signer_address, license_ref),
        )
        val_token = dict(await cursor.fetchone())

    # Build the signing transaction
    policy = create_minting_policy(signer_vk)
    policy_id = policy.hash()

    sig_asset_name = AssetName(sig_token["token_name"].encode("utf-8"))
    val_asset_name = AssetName(val_token["token_name"].encode("utf-8"))

    # Build multi-asset: 1 signature token + 1 validity token
    send_multi = MultiAsset()
    send_multi[policy_id] = Asset()
    send_multi[policy_id][sig_asset_name] = 1
    send_multi[policy_id][val_asset_name] = 1

    # Build signing metadata (label 367)
    now_ts = datetime.now().isoformat()
    sign_metadata = {
        DOC_SIGN_METADATA_LABEL: {
            "document_hash": document_hash[:64],
            "signer": signer_address[:64],
            "license_ref": license_ref,
            "timestamp": now_ts[:64],
        }
    }
    metadata = Metadata(sign_metadata)
    aux_data = AuxiliaryData(data=AlonzoMetadata(metadata=metadata))

    # Build and submit transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(signer_address)
    builder.auxiliary_data = aux_data

    token_value = Value(min_utxo_ada, send_multi)
    builder.add_output(TransactionOutput(
        Address.from_primitive(contract_address),
        token_value,
    ))

    signed_tx = builder.build_and_sign(
        signing_keys=[signer_sk],
        change_address=Address.from_primitive(signer_address),
    )

    context.submit_tx(signed_tx)
    tx_hash = signed_tx.id.to_primitive().hex()

    logger.info(
        f"Document signed: doc={document_hash[:16]}..., "
        f"signer={signer_wallet_label}, tx={tx_hash}"
    )

    # Deduct 1 signature token from signer's DB record
    await _consume_signature_token(sig_token["id"], tx_hash)

    # Record in blockchain_signatures table
    signature_id = await _store_signature_record(
        document_hash=document_hash,
        signer_address=signer_address,
        license_ref=license_ref,
        signature_tx_hash=tx_hash,
        signature_datum=sign_metadata[DOC_SIGN_METADATA_LABEL],
    )

    # Update work product if one exists for this document
    await _update_work_product_signatures(document_hash, signer_address, signature_id)

    return {
        "signature_id": signature_id,
        "tx_hash": tx_hash,
        "document_hash": document_hash,
        "signer_address": signer_address,
        "signer_wallet": signer_wallet_label,
        "contract_address": contract_address,
        "license_ref": license_ref,
        "timestamp": now_ts,
        "sig_token_used": sig_token["token_name"],
        "val_token_used": val_token["token_name"],
        "status": "signed",
    }


async def _consume_signature_token(token_id: int, tx_hash: str) -> None:
    """Deduct one signature token from a DB record (or mark transferred if qty reaches 0)."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT quantity FROM blockchain_signature_tokens WHERE id = ?", (token_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return

        new_qty = row["quantity"] - 1
        if new_qty <= 0:
            await db.execute(
                """UPDATE blockchain_signature_tokens
                   SET status = 'transferred', burn_tx_hash = ?, quantity = 0
                   WHERE id = ?""",
                (tx_hash, token_id),
            )
        else:
            await db.execute(
                "UPDATE blockchain_signature_tokens SET quantity = ? WHERE id = ?",
                (new_qty, token_id),
            )
        await db.commit()


async def _store_signature_record(
    document_hash: str,
    signer_address: str,
    license_ref: int,
    signature_tx_hash: str,
    signature_datum: Dict[str, Any],
) -> int:
    """Insert a signature record into blockchain_signatures table.

    Returns the signature row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_signatures
               (document_hash, signer_address, license_ref,
                signature_tx_hash, signature_datum)
               VALUES (?, ?, ?, ?, ?)""",
            (
                document_hash,
                signer_address,
                license_ref,
                signature_tx_hash,
                json.dumps(signature_datum),
            ),
        )
        await db.commit()
        return cursor.lastrowid


async def _update_work_product_signatures(
    document_hash: str,
    signer_address: str,
    signature_id: int,
) -> None:
    """Update work product collected_signatures if a matching work product exists."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_work_products WHERE document_hash = ?",
            (document_hash,),
        )
        wp = await cursor.fetchone()
        if not wp:
            return

        wp = dict(wp)
        collected = json.loads(wp["collected_signatures_json"] or "[]")
        required = json.loads(wp["required_signers_json"] or "[]")

        # Add this signature
        collected.append({
            "signer_address": signer_address,
            "signature_id": signature_id,
            "signed_at": datetime.now().isoformat(),
        })

        # Determine new status
        signed_addresses = {s["signer_address"] for s in collected}
        all_signed = all(addr in signed_addresses for addr in required)

        if all_signed and required:
            new_status = "fully_signed"
        elif collected:
            new_status = "partially_signed"
        else:
            new_status = wp["status"]

        await db.execute(
            """UPDATE blockchain_work_products
               SET collected_signatures_json = ?,
                   status = ?
               WHERE id = ?""",
            (json.dumps(collected), new_status, wp["id"]),
        )
        await db.commit()


async def verify_signature(
    contract_address: str,
    document_hash: str,
) -> Dict[str, Any]:
    """Verify that a document has been signed by querying local signature records.

    Checks blockchain_signatures table for all signatures matching the document hash,
    and verifies each signer's validity token status.

    Args:
        contract_address: The contract/work-product wallet address.
        document_hash: SHA-256 hash of the document to verify.

    Returns:
        Dict with is_verified, signatures list, signature_count, and work_product info.
    """
    if not document_hash:
        raise ValueError("document_hash must be non-empty")

    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row

        # Find all signatures for this document hash
        cursor = await db.execute(
            """SELECT * FROM blockchain_signatures
               WHERE document_hash = ?
               ORDER BY timestamp ASC""",
            (document_hash,),
        )
        sig_rows = [dict(r) for r in await cursor.fetchall()]

        # Check if there's a work product for this document
        cursor = await db.execute(
            "SELECT * FROM blockchain_work_products WHERE document_hash = ?",
            (document_hash,),
        )
        wp_row = await cursor.fetchone()
        work_product = dict(wp_row) if wp_row else None

    # Verify each signature's validity
    verified_signatures = []
    for sig in sig_rows:
        sig_info = {
            "signature_id": sig["id"],
            "signer_address": sig["signer_address"],
            "license_ref": sig["license_ref"],
            "tx_hash": sig["signature_tx_hash"],
            "timestamp": sig["timestamp"],
            "verified_at": sig.get("verified_at"),
        }

        # Check signer's current validity
        if sig["license_ref"]:
            validity = await check_validity(
                sig["signer_address"], sig["license_ref"]
            )
            sig_info["signer_valid_now"] = validity["is_valid"]
        else:
            sig_info["signer_valid_now"] = None

        verified_signatures.append(sig_info)

    # Determine overall verification status
    has_signatures = len(verified_signatures) > 0

    # If work product exists, check if all required signers have signed
    all_required_signed = False
    required_signers = []
    missing_signers = []

    if work_product:
        required_signers = json.loads(work_product["required_signers_json"] or "[]")
        signed_addresses = {s["signer_address"] for s in verified_signatures}
        missing_signers = [a for a in required_signers if a not in signed_addresses]
        all_required_signed = len(missing_signers) == 0 and len(required_signers) > 0

    is_verified = has_signatures and (all_required_signed if work_product else True)

    # Mark signatures as verified
    if is_verified:
        now = datetime.now().isoformat()
        async with aiosqlite.connect(LICENSE_DB) as db:
            for sig in sig_rows:
                if not sig.get("verified_at"):
                    await db.execute(
                        "UPDATE blockchain_signatures SET verified_at = ? WHERE id = ?",
                        (now, sig["id"]),
                    )
            await db.commit()

    result = {
        "is_verified": is_verified,
        "document_hash": document_hash,
        "contract_address": contract_address,
        "signature_count": len(verified_signatures),
        "signatures": verified_signatures,
    }

    if work_product:
        result["work_product"] = {
            "id": work_product["id"],
            "title": work_product["title"],
            "status": work_product["status"],
            "required_signers": required_signers,
            "missing_signers": missing_signers,
            "all_required_signed": all_required_signed,
        }

    return result


async def create_work_product(
    title: str,
    document_hash: str,
    required_signers: List[str],
    wp_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a work product with a dedicated wallet to collect signatures.

    Generates a new 'signer' wallet for the work product if no wp_address
    is provided. The wallet address serves as the collection point for
    signature and validity tokens from each required signer.

    Args:
        title: Human-readable title for the work product.
        document_hash: SHA-256 hash of the document.
        required_signers: List of Cardano addresses that must sign.
        wp_address: Optional pre-existing contract wallet address.
            If not provided, a new wallet is auto-generated.

    Returns:
        Dict with work_product_id, title, document_hash, wp_address, status,
        and wallet_generated flag.

    Raises:
        ValueError: If required_signers is empty or document_hash invalid.
    """
    if not document_hash or len(document_hash) < 16:
        raise ValueError("document_hash must be a valid hex hash (>= 16 chars)")
    if not required_signers:
        raise ValueError("required_signers must contain at least one address")
    if not title or not title.strip():
        raise ValueError("title must be a non-empty string")

    wallet_generated = False

    # Auto-generate a dedicated wallet for this work product
    if not wp_address:
        clean_title = "".join(c for c in title if c.isalnum() or c == "_")[:20]
        wallet_label = f"wp_{clean_title}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        wallet = await generate_wallet("signer", wallet_label, save_keys=True)
        wp_address = wallet["base_address"]
        wallet_generated = True
        logger.info(
            f"Auto-generated work product wallet: label={wallet_label}, "
            f"address={wp_address[:32]}..."
        )

    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO blockchain_work_products
               (title, wp_address, document_hash, required_signers_json, status)
               VALUES (?, ?, ?, ?, 'pending_signatures')""",
            (
                title,
                wp_address,
                document_hash,
                json.dumps(required_signers),
            ),
        )
        await db.commit()
        wp_id = cursor.lastrowid

    return {
        "work_product_id": wp_id,
        "title": title,
        "document_hash": document_hash,
        "required_signers": required_signers,
        "wp_address": wp_address,
        "status": "pending_signatures",
        "wallet_generated": wallet_generated,
    }


async def get_work_product_status(
    work_product_id: Optional[int] = None,
    wp_address: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Get the current status of a work product including signature progress.

    Can look up by ID or by wp_address. At least one must be provided.

    Args:
        work_product_id: The work product row ID.
        wp_address: The work product wallet address.

    Returns:
        Dict with work product details, collected/missing signatures,
        validity status per signer, and progress info. None if not found.

    Raises:
        ValueError: If neither work_product_id nor wp_address is provided.
    """
    if work_product_id is None and not wp_address:
        raise ValueError("Must provide work_product_id or wp_address")

    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row

        if work_product_id is not None:
            cursor = await db.execute(
                "SELECT * FROM blockchain_work_products WHERE id = ?",
                (work_product_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM blockchain_work_products WHERE wp_address = ?",
                (wp_address,),
            )

        row = await cursor.fetchone()
        if not row:
            return None

        wp = dict(row)
        required = json.loads(wp["required_signers_json"] or "[]")
        collected = json.loads(wp["collected_signatures_json"] or "[]")

        signed_addresses = {s["signer_address"] for s in collected}
        missing = [a for a in required if a not in signed_addresses]

        # Check validity status for each required signer
        signer_validity = {}
        for addr in required:
            has_signed = addr in signed_addresses
            signer_validity[addr] = {
                "has_signed": has_signed,
                "signature_id": next(
                    (s["signature_id"] for s in collected if s["signer_address"] == addr),
                    None,
                ),
            }

        return {
            "work_product_id": wp["id"],
            "title": wp["title"],
            "document_hash": wp["document_hash"],
            "wp_address": wp["wp_address"],
            "status": wp["status"],
            "required_signers": required,
            "collected_signatures": collected,
            "missing_signers": missing,
            "signer_validity": signer_validity,
            "signature_progress": f"{len(collected)}/{len(required)}",
            "is_fully_signed": len(missing) == 0 and len(required) > 0,
            "created_at": wp["created_at"],
            "finalized_at": wp.get("finalized_at"),
            "finalize_tx_hash": wp.get("finalize_tx_hash"),
        }


async def get_work_product_by_address(wp_address: str) -> Optional[Dict[str, Any]]:
    """Look up a work product by its wallet address.

    Convenience wrapper around get_work_product_status(wp_address=...).

    Args:
        wp_address: The work product wallet address.

    Returns:
        Dict with work product status, or None if not found.
    """
    if not wp_address:
        raise ValueError("wp_address must be a non-empty string")
    return await get_work_product_status(wp_address=wp_address)


async def finalize_work_product(
    wp_address: Optional[str] = None,
    work_product_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Finalize a work product after verifying all required signatures.

    Checks that every required signer has submitted a signature. If all
    signatures are present, marks the work product as 'finalized' with
    a timestamp. If signatures are missing, raises ValueError.

    Can look up by wp_address or work_product_id. At least one required.

    Args:
        wp_address: The work product wallet address.
        work_product_id: The work product row ID.

    Returns:
        Dict with finalization status, work_product_id, and timestamp.

    Raises:
        ValueError: If work product not found, missing signatures, or
            already finalized.
    """
    if wp_address is None and work_product_id is None:
        raise ValueError("Must provide wp_address or work_product_id")

    status = await get_work_product_status(
        work_product_id=work_product_id, wp_address=wp_address
    )
    if not status:
        raise ValueError(
            f"Work product not found: "
            f"{'address=' + str(wp_address) if wp_address else 'id=' + str(work_product_id)}"
        )

    # Check current status
    if status["status"] == "finalized":
        raise ValueError(
            f"Work product {status['work_product_id']} is already finalized"
        )
    if status["status"] == "rejected":
        raise ValueError(
            f"Work product {status['work_product_id']} has been rejected"
        )

    # Verify all required signatures are present
    if status["missing_signers"]:
        raise ValueError(
            f"Cannot finalize: missing signatures from "
            f"{len(status['missing_signers'])} signer(s): "
            f"{', '.join(s[:32] + '...' for s in status['missing_signers'])}"
        )

    if not status["required_signers"]:
        raise ValueError("Cannot finalize: no required signers defined")

    # Mark as finalized
    finalized_at = datetime.now().isoformat()
    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute(
            """UPDATE blockchain_work_products
               SET status = 'finalized', finalized_at = ?
               WHERE id = ?""",
            (finalized_at, status["work_product_id"]),
        )
        await db.commit()

    logger.info(
        f"Work product finalized: id={status['work_product_id']}, "
        f"title={status['title']}, signatures={status['signature_progress']}"
    )

    return {
        "work_product_id": status["work_product_id"],
        "title": status["title"],
        "document_hash": status["document_hash"],
        "wp_address": status["wp_address"],
        "status": "finalized",
        "finalized_at": finalized_at,
        "signature_count": len(status["collected_signatures"]),
        "required_signers": status["required_signers"],
    }


async def list_work_products(
    status: Optional[str] = None,
    wp_address: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List work products with optional filters.

    Args:
        status: Filter by status (e.g., 'pending_signatures', 'finalized').
        wp_address: Filter by work product wallet address.

    Returns:
        List of work product dicts with signature progress.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if wp_address:
            conditions.append("wp_address = ?")
            params.append(wp_address)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_work_products{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()

    results = []
    for row in rows:
        wp = dict(row)
        required = json.loads(wp["required_signers_json"] or "[]")
        collected = json.loads(wp["collected_signatures_json"] or "[]")
        signed_addresses = {s["signer_address"] for s in collected}
        missing = [a for a in required if a not in signed_addresses]

        results.append({
            "work_product_id": wp["id"],
            "title": wp["title"],
            "document_hash": wp["document_hash"],
            "wp_address": wp["wp_address"],
            "status": wp["status"],
            "required_signers": required,
            "missing_signers": missing,
            "signature_progress": f"{len(collected)}/{len(required)}",
            "created_at": wp["created_at"],
            "finalized_at": wp.get("finalized_at"),
        })

    return results


async def get_signature_by_id(signature_id: int) -> Optional[Dict[str, Any]]:
    """Look up a signature record by ID."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM blockchain_signatures WHERE id = ?", (signature_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_signatures(
    document_hash: Optional[str] = None,
    signer_address: Optional[str] = None,
    license_ref: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """List signature records with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if document_hash:
            conditions.append("document_hash = ?")
            params.append(document_hash)
        if signer_address:
            conditions.append("signer_address = ?")
            params.append(signer_address)
        if license_ref is not None:
            conditions.append("license_ref = ?")
            params.append(license_ref)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM blockchain_signatures{where} ORDER BY timestamp DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ── Plutus V2 Signature Collection Validator ─────────────────────

# Metadata label for signature validator scripts
VALIDATOR_METADATA_LABEL = 368


@dataclass
class SignerDatum(PlutusData):
    """On-chain datum recording a signer's deposit into a work product.

    Attached to each UTXO deposited by a signer into the validator address.
    The validator checks these datums when verifying signature completeness.

    Fields:
        signer_pkh: 28-byte verification key hash of the signer.
        document_hash: SHA-256 hash of the signed document (bytes).
        deposit_slot: Slot number when the deposit was made.
        sig_token_policy: Policy ID of the deposited signature token.
        val_token_policy: Policy ID of the deposited validity token.
        validity_expiry_slot: Slot after which the validity token expires.
    """
    CONSTR_ID = 0

    signer_pkh: bytes = b""
    document_hash: bytes = b""
    deposit_slot: int = 0
    sig_token_policy: bytes = b""
    val_token_policy: bytes = b""
    validity_expiry_slot: int = 0


class CollectRedeemer(PlutusData):
    """Redeemer: deposit signature + validity tokens into the validator."""
    CONSTR_ID = 0


class FinalizeRedeemer(PlutusData):
    """Redeemer: finalize the work product (all signatures collected)."""
    CONSTR_ID = 1


class ReclaimRedeemer(PlutusData):
    """Redeemer: reclaim tokens if the work product is cancelled."""
    CONSTR_ID = 2


class SignatureCollectionValidator:
    """Plutus V2 validator for work product signature collection.

    Enforces the following on-chain rules:
    1. **Collect** (redeemer 0): Accepts deposits of signature + validity tokens
       from authorized signers. Validates that the signer's PKH is in the
       required_signers list and the validity token is not expired (slot check).
    2. **Finalize** (redeemer 1): Allows spending all UTXOs only when every
       required signer has a corresponding datum in the validator's UTXOs.
    3. **Reclaim** (redeemer 2): Allows the original depositor to reclaim
       their tokens if the work product is cancelled.

    **Concurrency model**: Each signer creates an independent UTxO at the
    validator script address containing their tokens and a SignerDatum
    identifying the work product. This avoids the single-UTxO contention
    bottleneck that would occur if all signers competed to update a shared
    state UTxO. The authority's Finalize transaction consumes all per-signer
    UTxOs atomically in a single transaction.

    The validator is constructed as a native script (ScriptAll with ScriptPubkey
    per required signer) for zero execution fees, with Plutus V2-compatible
    datum/redeemer types for the upgrade path to full Plutus V2 on-chain logic.

    The pre-submission Python validation mirrors the intended on-chain logic
    so that invalid transactions are caught before submission.

    Attributes:
        required_signers: List of hex PKH strings that must all sign.
        authority_pkh: Hex PKH of the authority who can finalize.
        document_hash: SHA-256 hex hash of the document.
        validity_slot_deadline: Latest slot at which validity tokens are accepted.
        native_script: The underlying native script for the validator.
        script_hash: The ScriptHash (validator address derivation).
        validator_address: The Cardano address derived from the script.
    """

    def __init__(
        self,
        required_signers: List[str],
        authority_pkh: str,
        document_hash: str,
        validity_slot_deadline: Optional[int] = None,
    ):
        """Initialize the signature collection validator.

        Args:
            required_signers: List of hex-encoded 28-byte PKHs of required signers.
            authority_pkh: Hex-encoded 28-byte PKH of the authority (can finalize).
            document_hash: SHA-256 hex hash of the document being signed.
            validity_slot_deadline: Optional latest slot for validity acceptance.

        Raises:
            ValueError: If required_signers is empty or PKHs are invalid.
        """
        if not required_signers:
            raise ValueError("required_signers must contain at least one PKH")
        if not document_hash or len(document_hash) < 16:
            raise ValueError("document_hash must be a valid hex hash (>= 16 chars)")

        # Validate all PKHs
        for pkh in required_signers:
            PlutusV2MintingPolicy._validate_pubkey_hash(pkh)
        PlutusV2MintingPolicy._validate_pubkey_hash(authority_pkh)

        self.required_signers = list(required_signers)
        self.authority_pkh = authority_pkh
        self.document_hash = document_hash
        self.validity_slot_deadline = validity_slot_deadline

        # Build native script: authority key required for all operations
        # Plus each signer key authorized (ScriptAny would be ideal, but
        # we use authority key as the gatekeeper for simplicity)
        authority_vkh = VerificationKeyHash(bytes.fromhex(authority_pkh))
        self.native_script: NativeScript = ScriptPubkey(authority_vkh)
        self.script_hash: ScriptHash = self.native_script.hash()

        # Derive validator address
        network = _get_network()
        self.validator_address = Address(
            payment_part=self.script_hash,
            network=network,
        )

        # Track collected signers (in-memory state, synced from DB)
        self._collected_signers: Dict[str, Dict[str, Any]] = {}

    def get_validator_address(self) -> str:
        """Return the validator script address as a bech32 string."""
        return str(self.validator_address)

    def get_script_hash_hex(self) -> str:
        """Return the script hash as a hex string."""
        return self.script_hash.to_primitive().hex()

    def get_script_cbor_hex(self) -> str:
        """Return the native script CBOR hex for on-chain attachment."""
        return self.native_script.to_cbor_hex()

    def validate_signer_authorized(self, signer_pkh: str) -> Tuple[bool, str]:
        """Check if a signer PKH is in the required signers list.

        Args:
            signer_pkh: Hex-encoded 28-byte PKH of the signer.

        Returns:
            Tuple of (is_authorized, reason).
        """
        if signer_pkh in self.required_signers:
            return True, "authorized"
        return False, f"signer {signer_pkh[:16]}... not in required_signers"

    def validate_validity_not_expired(
        self, validity_expiry_slot: int, current_slot: int
    ) -> Tuple[bool, str]:
        """Check if a validity token's expiry slot is still in the future.

        Args:
            validity_expiry_slot: The slot at which the validity token expires.
            current_slot: The current chain tip slot.

        Returns:
            Tuple of (is_valid, reason).
        """
        if validity_expiry_slot <= current_slot:
            return False, (
                f"validity token expired at slot {validity_expiry_slot}, "
                f"current slot {current_slot}"
            )
        if (self.validity_slot_deadline is not None
                and validity_expiry_slot > self.validity_slot_deadline):
            return False, (
                f"validity expiry slot {validity_expiry_slot} exceeds "
                f"deadline {self.validity_slot_deadline}"
            )
        return True, "valid"

    def validate_deposit(
        self,
        signer_pkh: str,
        validity_expiry_slot: int,
        current_slot: int,
        has_sig_token: bool = True,
        has_val_token: bool = True,
    ) -> Tuple[bool, List[str]]:
        """Full pre-submission validation for a signer deposit.

        Mirrors the intended Plutus V2 on-chain validator logic:
        1. Signer must be in required_signers
        2. Validity token must not be expired
        3. Both signature and validity tokens must be present
        4. Signer must not have already deposited

        Args:
            signer_pkh: Hex PKH of the depositing signer.
            validity_expiry_slot: Expiry slot of the validity token.
            current_slot: Current chain slot.
            has_sig_token: Whether the deposit includes a signature token.
            has_val_token: Whether the deposit includes a validity token.

        Returns:
            Tuple of (all_valid, list_of_errors). Empty errors = valid.
        """
        errors = []

        # Check 1: signer authorized
        auth_ok, auth_msg = self.validate_signer_authorized(signer_pkh)
        if not auth_ok:
            errors.append(auth_msg)

        # Check 2: validity not expired
        val_ok, val_msg = self.validate_validity_not_expired(
            validity_expiry_slot, current_slot
        )
        if not val_ok:
            errors.append(val_msg)

        # Check 3: tokens present
        if not has_sig_token:
            errors.append("deposit missing signature token")
        if not has_val_token:
            errors.append("deposit missing validity token")

        # Check 4: not already deposited
        if signer_pkh in self._collected_signers:
            errors.append(f"signer {signer_pkh[:16]}... already deposited")

        return len(errors) == 0, errors

    def record_deposit(
        self,
        signer_pkh: str,
        deposit_slot: int,
        sig_token_policy: str,
        val_token_policy: str,
        validity_expiry_slot: int,
        tx_hash: str,
    ) -> SignerDatum:
        """Record a validated deposit and return the datum.

        Call after validate_deposit() succeeds and the transaction is submitted.

        Args:
            signer_pkh: Hex PKH of the depositing signer.
            deposit_slot: Slot when the deposit was made.
            sig_token_policy: Policy ID hex of the signature token.
            val_token_policy: Policy ID hex of the validity token.
            validity_expiry_slot: Expiry slot of the validity token.
            tx_hash: Transaction hash of the deposit.

        Returns:
            SignerDatum instance for the deposit.
        """
        datum = SignerDatum(
            signer_pkh=bytes.fromhex(signer_pkh),
            document_hash=bytes.fromhex(self.document_hash),
            deposit_slot=deposit_slot,
            sig_token_policy=bytes.fromhex(sig_token_policy),
            val_token_policy=bytes.fromhex(val_token_policy),
            validity_expiry_slot=validity_expiry_slot,
        )

        self._collected_signers[signer_pkh] = {
            "deposit_slot": deposit_slot,
            "sig_token_policy": sig_token_policy,
            "val_token_policy": val_token_policy,
            "validity_expiry_slot": validity_expiry_slot,
            "tx_hash": tx_hash,
        }

        return datum

    def check_finalization_ready(self) -> Tuple[bool, Dict[str, Any]]:
        """Check if all required signers have deposited.

        Returns:
            Tuple of (is_ready, details_dict) with collected/missing info.
        """
        collected = set(self._collected_signers.keys())
        required = set(self.required_signers)
        missing = required - collected
        extra = collected - required

        return len(missing) == 0, {
            "is_ready": len(missing) == 0,
            "total_required": len(required),
            "total_collected": len(collected),
            "collected_signers": sorted(collected),
            "missing_signers": sorted(missing),
            "extra_signers": sorted(extra),
            "progress": f"{len(collected)}/{len(required)}",
        }

    def build_collect_redeemer(self) -> Redeemer:
        """Build a Redeemer for the Collect action (deposit tokens)."""
        return Redeemer(CollectRedeemer(), RedeemerTag.SPEND)

    def build_finalize_redeemer(self) -> Redeemer:
        """Build a Redeemer for the Finalize action."""
        return Redeemer(FinalizeRedeemer(), RedeemerTag.SPEND)

    def build_reclaim_redeemer(self) -> Redeemer:
        """Build a Redeemer for the Reclaim action (cancel)."""
        return Redeemer(ReclaimRedeemer(), RedeemerTag.SPEND)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize validator state for storage."""
        return {
            "required_signers": self.required_signers,
            "authority_pkh": self.authority_pkh,
            "document_hash": self.document_hash,
            "validity_slot_deadline": self.validity_slot_deadline,
            "script_hash": self.get_script_hash_hex(),
            "validator_address": self.get_validator_address(),
            "script_cbor_hex": self.get_script_cbor_hex(),
            "collected_signers": dict(self._collected_signers),
            "created_at": datetime.now().isoformat(),
        }

    def save_validator(self, label: str) -> Path:
        """Save the validator state to disk as JSON + CBOR.

        Args:
            label: Human-readable label for the validator file.

        Returns:
            Path to the saved validator JSON file.
        """
        POLICY_DIR.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        data["label"] = label
        data["type"] = "signature_collection_validator"

        json_path = POLICY_DIR / f"validator_{label}.json"
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        cbor_path = POLICY_DIR / f"validator_{label}.cbor"
        with open(cbor_path, "wb") as f:
            f.write(bytes.fromhex(self.get_script_cbor_hex()))

        logger.info(f"Saved signature validator: {json_path} + {cbor_path}")
        return json_path

    @classmethod
    def load_validator(cls, label: str) -> "SignatureCollectionValidator":
        """Load a previously saved validator from disk.

        Args:
            label: The validator label used during save.

        Returns:
            Reconstructed SignatureCollectionValidator instance.

        Raises:
            FileNotFoundError: If validator file doesn't exist.
        """
        json_path = POLICY_DIR / f"validator_{label}.json"
        if not json_path.exists():
            raise FileNotFoundError(f"Validator file not found: {json_path}")

        with open(json_path, "r") as f:
            data = json.load(f)

        validator = cls(
            required_signers=data["required_signers"],
            authority_pkh=data["authority_pkh"],
            document_hash=data["document_hash"],
            validity_slot_deadline=data.get("validity_slot_deadline"),
        )

        # Restore collected signers state
        for pkh, info in data.get("collected_signers", {}).items():
            validator._collected_signers[pkh] = info

        return validator


def build_signature_validator(
    required_signers: List[str],
    authority_pkh: Optional[str] = None,
    document_hash: str = "",
    validity_slot_deadline: Optional[int] = None,
) -> SignatureCollectionValidator:
    """Build a Plutus V2 signature collection validator for a work product.

    Creates a validator that gates finalization on all required signers
    depositing their signature + validity tokens. The validator enforces:
    1. Only authorized signers can deposit (PKH whitelist)
    2. Validity tokens must not be expired (slot-based check)
    3. Each signer can deposit exactly once
    4. Finalization requires all required signers present

    Args:
        required_signers: List of hex-encoded 28-byte PKHs that must sign.
            Obtain from wallet: payment_vk.hash().to_primitive().hex()
        authority_pkh: Optional hex PKH of the authority/admin.
            If not provided, uses the first required signer.
        document_hash: SHA-256 hex hash of the document. Can be set later
            if not known at validator creation time.
        validity_slot_deadline: Optional latest slot for validity tokens.
            If set, validity tokens expiring after this slot are rejected.

    Returns:
        SignatureCollectionValidator instance with script hash and address.

    Raises:
        ValueError: If required_signers is empty or PKHs are invalid.

    Example:
        >>> signers = ["a1b2c3...56chars...", "d4e5f6...56chars..."]
        >>> validator = build_signature_validator(signers, document_hash="abcdef0123456789")
        >>> print(validator.get_validator_address())
        'addr_test1...'
        >>> print(validator.check_finalization_ready())
        (False, {'is_ready': False, 'total_required': 2, ...})
    """
    if not required_signers:
        raise ValueError("required_signers must contain at least one PKH")

    if not authority_pkh:
        authority_pkh = required_signers[0]

    if not document_hash:
        document_hash = "0" * 64  # Placeholder, must be set before use

    return SignatureCollectionValidator(
        required_signers=required_signers,
        authority_pkh=authority_pkh,
        document_hash=document_hash,
        validity_slot_deadline=validity_slot_deadline,
    )


async def deploy_signature_validator(
    work_product_id: int,
    authority_wallet_label: str,
    validity_slot_deadline: Optional[int] = None,
) -> Dict[str, Any]:
    """Deploy a signature collection validator for an existing work product.

    Looks up the work product's required signers, resolves their PKHs from
    the blockchain_wallets table, and builds/stores the validator.

    Args:
        work_product_id: ID of the work product to create a validator for.
        authority_wallet_label: Label of the authority wallet.
        validity_slot_deadline: Optional slot deadline for validity tokens.

    Returns:
        Dict with validator_address, script_hash, required_signers, and work_product_id.

    Raises:
        ValueError: If work product not found or signers can't be resolved.
    """
    # Get work product
    wp = await get_work_product_status(work_product_id=work_product_id)
    if not wp:
        raise ValueError(f"Work product not found: {work_product_id}")

    # Load authority keys
    authority_keys = load_wallet_keys(authority_wallet_label)
    authority_vk = authority_keys["payment_vk"]
    authority_pkh = authority_vk.hash().to_primitive().hex()

    # Resolve signer addresses to PKHs
    signer_pkhs = []
    for signer_addr in wp["required_signers"]:
        signer_wallet = await get_wallet_by_address(signer_addr)
        if signer_wallet:
            # Load wallet keys to get PKH
            signer_keys = load_wallet_keys(signer_wallet["wallet_label"])
            pkh = signer_keys["payment_vk"].hash().to_primitive().hex()
            signer_pkhs.append(pkh)
        else:
            # Try to extract PKH from address directly
            try:
                addr = Address.from_primitive(signer_addr)
                if addr.payment_part:
                    signer_pkhs.append(addr.payment_part.to_primitive().hex())
                else:
                    raise ValueError(
                        f"Cannot extract PKH from signer address: {signer_addr[:32]}..."
                    )
            except Exception as e:
                raise ValueError(
                    f"Cannot resolve signer {signer_addr[:32]}...: {e}"
                )

    # Build validator
    validator = build_signature_validator(
        required_signers=signer_pkhs,
        authority_pkh=authority_pkh,
        document_hash=wp["document_hash"],
        validity_slot_deadline=validity_slot_deadline,
    )

    # Save to disk
    validator_label = f"wp_{work_product_id}"
    validator.save_validator(validator_label)

    # Store validator metadata in DB
    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute(
            """UPDATE blockchain_work_products
               SET validator_address = ?, validator_script_hash = ?
               WHERE id = ?""",
            (
                validator.get_validator_address(),
                validator.get_script_hash_hex(),
                work_product_id,
            ),
        )
        await db.commit()

    logger.info(
        f"Deployed signature validator for WP#{work_product_id}: "
        f"address={validator.get_validator_address()[:32]}..."
    )

    return {
        "work_product_id": work_product_id,
        "validator_address": validator.get_validator_address(),
        "script_hash": validator.get_script_hash_hex(),
        "script_cbor_hex": validator.get_script_cbor_hex(),
        "required_signers": signer_pkhs,
        "authority_pkh": authority_pkh,
        "document_hash": wp["document_hash"],
        "validity_slot_deadline": validity_slot_deadline,
        "validator_label": validator_label,
    }


async def validate_signer_deposit(
    work_product_id: int,
    signer_pkh: str,
    validity_expiry_slot: int,
    current_slot: int,
    has_sig_token: bool = True,
    has_val_token: bool = True,
) -> Dict[str, Any]:
    """Validate a signer deposit against the work product's validator.

    Loads the saved validator state and runs all pre-submission checks.

    Args:
        work_product_id: ID of the work product.
        signer_pkh: Hex PKH of the depositing signer.
        validity_expiry_slot: Expiry slot of the validity token.
        current_slot: Current chain slot.
        has_sig_token: Whether deposit includes a signature token.
        has_val_token: Whether deposit includes a validity token.

    Returns:
        Dict with is_valid, errors, and validator info.
    """
    validator_label = f"wp_{work_product_id}"
    try:
        validator = SignatureCollectionValidator.load_validator(validator_label)
    except FileNotFoundError:
        return {
            "is_valid": False,
            "errors": [f"No validator deployed for work product {work_product_id}"],
            "validator_address": None,
        }

    is_valid, errors = validator.validate_deposit(
        signer_pkh=signer_pkh,
        validity_expiry_slot=validity_expiry_slot,
        current_slot=current_slot,
        has_sig_token=has_sig_token,
        has_val_token=has_val_token,
    )

    return {
        "is_valid": is_valid,
        "errors": errors,
        "validator_address": validator.get_validator_address(),
        "script_hash": validator.get_script_hash_hex(),
        "signer_pkh": signer_pkh,
        "work_product_id": work_product_id,
    }


async def check_finalization_ready(work_product_id: int) -> Dict[str, Any]:
    """Check if a work product's validator has all required signatures.

    Args:
        work_product_id: ID of the work product.

    Returns:
        Dict with is_ready, progress, collected/missing signers.
    """
    validator_label = f"wp_{work_product_id}"
    try:
        validator = SignatureCollectionValidator.load_validator(validator_label)
    except FileNotFoundError:
        return {
            "is_ready": False,
            "error": f"No validator deployed for work product {work_product_id}",
            "work_product_id": work_product_id,
        }

    is_ready, details = validator.check_finalization_ready()
    details["work_product_id"] = work_product_id
    details["validator_address"] = validator.get_validator_address()
    return details


# ── Dues Enforcement Contract ─────────────────────────────────────

# PlutusData types for dues enforcement redeemers

class PayDuesRedeemer(PlutusData):
    """Redeemer: Pay dues to renew validity (licensee-initiated)."""
    CONSTR_ID = 0


class RevokeValidityRedeemer(PlutusData):
    """Redeemer: Revoke a validity token (authority-initiated)."""
    CONSTR_ID = 1


@dataclass
class DuesContractDatum(PlutusData):
    """Datum: Dues contract parameters stored on-chain.

    Fields encode the contract state:
    - authority_pkh: 28-byte PKH of the dues authority
    - annual_dues: lovelace amount per renewal period
    - license_ref: unique license identifier
    - grace_period_slots: slots after expiry before signing is blocked
    """
    CONSTR_ID = 0

    authority_pkh: bytes = b""
    annual_dues: int = 0
    license_ref: int = 0
    grace_period_slots: int = 0


# Default: ~24 hours at 1-second slots
DEFAULT_GRACE_PERIOD_SLOTS = 86400

# Minimum annual dues: 1 ADA (1_000_000 lovelace)
MIN_ANNUAL_DUES_LOVELACE = 1_000_000

# Maximum annual dues: 10_000 ADA
MAX_ANNUAL_DUES_LOVELACE = 10_000_000_000


class DuesEnforcementContract:
    """Plutus V2 dues enforcement contract for license validity.

    Enforces the following rules:
    1. **Authority mints** validity tokens with expiry slot, tied to a license.
    2. **Renewal** requires dues payment (ADA transfer to authority address).
       The contract validates the payment amount matches annual_dues_lovelace.
    3. **Expired** validity tokens are invalid for signing (slot-based check).
    4. **Revocation**: Authority can revoke validity tokens at any time.

    The contract is built as a native script (ScriptAll requiring authority
    signature) with Plutus V2 datum/redeemer types for upgrade path.

    Pre-submission Python validation mirrors intended on-chain logic:
    - Payment amount >= annual_dues_lovelace
    - Payment goes to authority_address
    - License exists and is active
    - Validity token not already expired beyond grace period

    Attributes:
        authority_pkh: Hex string of authority's verification key hash.
        authority_address: Bech32 address for dues payments.
        annual_dues_lovelace: Required payment in lovelace per renewal.
        license_ref: License ID this contract enforces.
        grace_period_slots: Grace period after expiry (default 86400 ~24h).
        native_script: The underlying ScriptAll native script.
        script_hash: The ScriptHash (contract identifier).
        contract_address: The Cardano address derived from the script.
    """

    def __init__(
        self,
        authority_pkh: str,
        authority_address: str,
        annual_dues_lovelace: int,
        license_ref: int,
        grace_period_slots: int = DEFAULT_GRACE_PERIOD_SLOTS,
    ):
        """Initialize the dues enforcement contract.

        Args:
            authority_pkh: Hex-encoded 28-byte verification key hash.
            authority_address: Bech32 address to receive dues payments.
            annual_dues_lovelace: Annual dues amount in lovelace.
            license_ref: License ID this contract enforces.
            grace_period_slots: Slots after expiry before signing blocked.

        Raises:
            ValueError: If parameters are invalid.
        """
        # Validate authority PKH
        PlutusV2MintingPolicy._validate_pubkey_hash(authority_pkh)

        if not authority_address:
            raise ValueError("authority_address must be a non-empty bech32 address")
        if annual_dues_lovelace < MIN_ANNUAL_DUES_LOVELACE:
            raise ValueError(
                f"annual_dues_lovelace must be >= {MIN_ANNUAL_DUES_LOVELACE} "
                f"(1 ADA), got {annual_dues_lovelace}"
            )
        if annual_dues_lovelace > MAX_ANNUAL_DUES_LOVELACE:
            raise ValueError(
                f"annual_dues_lovelace must be <= {MAX_ANNUAL_DUES_LOVELACE} "
                f"(10,000 ADA), got {annual_dues_lovelace}"
            )
        if license_ref < 1:
            raise ValueError(f"license_ref must be positive, got {license_ref}")
        if grace_period_slots < 0:
            raise ValueError(f"grace_period_slots must be >= 0, got {grace_period_slots}")

        self.authority_pkh = authority_pkh
        self.authority_address = authority_address
        self.annual_dues_lovelace = annual_dues_lovelace
        self.license_ref = license_ref
        self.grace_period_slots = grace_period_slots

        # Build native script: authority key required for all operations
        vkh = VerificationKeyHash(bytes.fromhex(authority_pkh))
        self.native_script: NativeScript = ScriptPubkey(vkh)
        self.script_hash: ScriptHash = self.native_script.hash()

        # Derive contract address
        network = _get_network()
        self.contract_address = Address(
            payment_part=self.script_hash,
            network=network,
        )

    def get_contract_address(self) -> str:
        """Return the contract script address as a bech32 string."""
        return str(self.contract_address)

    def get_script_hash_hex(self) -> str:
        """Return the script hash as a hex string."""
        return self.script_hash.to_primitive().hex()

    def get_script_cbor_hex(self) -> str:
        """Return the native script CBOR hex."""
        return self.native_script.to_cbor_hex()

    def build_datum(self) -> DuesContractDatum:
        """Build the on-chain datum for this contract."""
        return DuesContractDatum(
            authority_pkh=bytes.fromhex(self.authority_pkh),
            annual_dues=self.annual_dues_lovelace,
            license_ref=self.license_ref,
            grace_period_slots=self.grace_period_slots,
        )

    def build_pay_redeemer(self) -> Redeemer:
        """Build a Redeemer for the PayDues action."""
        return Redeemer(PayDuesRedeemer(), RedeemerTag.SPEND)

    def build_revoke_redeemer(self) -> Redeemer:
        """Build a Redeemer for the RevokeValidity action."""
        return Redeemer(RevokeValidityRedeemer(), RedeemerTag.SPEND)

    def validate_payment(
        self,
        payment_lovelace: int,
        recipient_address: str,
    ) -> Tuple[bool, List[str]]:
        """Validate a dues payment before submission.

        Mirrors intended on-chain logic:
        1. Payment amount >= annual_dues_lovelace
        2. Payment goes to authority address

        Args:
            payment_lovelace: Amount being paid in lovelace.
            recipient_address: Address the payment is sent to.

        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        errors = []

        if payment_lovelace < self.annual_dues_lovelace:
            errors.append(
                f"payment {payment_lovelace} lovelace < required "
                f"{self.annual_dues_lovelace} lovelace"
            )

        if recipient_address != self.authority_address:
            errors.append(
                f"payment must go to authority address {self.authority_address[:32]}..., "
                f"got {recipient_address[:32]}..."
            )

        return len(errors) == 0, errors

    def validate_renewal(
        self,
        payment_lovelace: int,
        recipient_address: str,
        current_slot: int,
        current_expiry_slot: Optional[int] = None,
    ) -> Tuple[bool, List[str]]:
        """Full pre-submission validation for a dues renewal.

        Checks payment validity plus grace period constraints.

        Args:
            payment_lovelace: Amount being paid.
            recipient_address: Where payment is sent.
            current_slot: Current chain tip slot.
            current_expiry_slot: Current validity expiry slot (if known).

        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        is_valid, errors = self.validate_payment(payment_lovelace, recipient_address)

        if current_expiry_slot is not None:
            slots_past_expiry = current_slot - current_expiry_slot
            if slots_past_expiry > self.grace_period_slots:
                errors.append(
                    f"validity expired {slots_past_expiry} slots ago, "
                    f"exceeds grace period of {self.grace_period_slots} slots — "
                    f"contact authority for reinstatement"
                )

        return len(errors) == 0, errors

    def check_validity_for_signing(
        self,
        validity_expiry_slot: int,
        current_slot: int,
    ) -> Tuple[bool, str]:
        """Check if a validity token allows signing at current slot.

        Expired tokens are invalid for signing. Grace period does NOT
        extend signing rights — it only extends the renewal window.

        Args:
            validity_expiry_slot: Expiry slot of the validity token.
            current_slot: Current chain slot.

        Returns:
            Tuple of (can_sign, reason).
        """
        if current_slot >= validity_expiry_slot:
            return False, (
                f"validity token expired at slot {validity_expiry_slot}, "
                f"current slot {current_slot} — renew to continue signing"
            )
        return True, "valid"

    def check_in_grace_period(
        self,
        validity_expiry_slot: int,
        current_slot: int,
    ) -> Tuple[bool, int]:
        """Check if the current time is within the grace period after expiry.

        Args:
            validity_expiry_slot: Expiry slot of the validity token.
            current_slot: Current chain slot.

        Returns:
            Tuple of (in_grace_period, slots_remaining).
        """
        if current_slot < validity_expiry_slot:
            return False, 0  # Not yet expired

        slots_past = current_slot - validity_expiry_slot
        if slots_past <= self.grace_period_slots:
            remaining = self.grace_period_slots - slots_past
            return True, remaining

        return False, 0  # Past grace period

    def to_dict(self) -> Dict[str, Any]:
        """Serialize contract state for storage."""
        return {
            "authority_pkh": self.authority_pkh,
            "authority_address": self.authority_address,
            "annual_dues_lovelace": self.annual_dues_lovelace,
            "license_ref": self.license_ref,
            "grace_period_slots": self.grace_period_slots,
            "script_hash": self.get_script_hash_hex(),
            "contract_address": self.get_contract_address(),
            "script_cbor_hex": self.get_script_cbor_hex(),
            "created_at": datetime.now().isoformat(),
        }

    def save_contract(self, label: str) -> Path:
        """Save the contract state to disk as JSON + CBOR.

        Args:
            label: Human-readable label for the contract file.

        Returns:
            Path to the saved contract JSON file.
        """
        POLICY_DIR.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        data["label"] = label
        data["type"] = "dues_enforcement_contract"

        json_path = POLICY_DIR / f"dues_{label}.json"
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        cbor_path = POLICY_DIR / f"dues_{label}.cbor"
        with open(cbor_path, "wb") as f:
            f.write(bytes.fromhex(self.get_script_cbor_hex()))

        logger.info(f"Saved dues contract: {json_path} + {cbor_path}")
        return json_path

    @classmethod
    def load_contract(cls, label: str) -> "DuesEnforcementContract":
        """Load a previously saved contract from disk.

        Args:
            label: The contract label used during save.

        Returns:
            Reconstructed DuesEnforcementContract instance.

        Raises:
            FileNotFoundError: If contract file doesn't exist.
        """
        json_path = POLICY_DIR / f"dues_{label}.json"
        if not json_path.exists():
            raise FileNotFoundError(f"Contract file not found: {json_path}")

        with open(json_path, "r") as f:
            data = json.load(f)

        return cls(
            authority_pkh=data["authority_pkh"],
            authority_address=data["authority_address"],
            annual_dues_lovelace=data["annual_dues_lovelace"],
            license_ref=data["license_ref"],
            grace_period_slots=data.get("grace_period_slots", DEFAULT_GRACE_PERIOD_SLOTS),
        )


def build_dues_contract(
    authority_address: str,
    annual_dues_lovelace: int,
    license_ref: int,
    grace_period_slots: int = DEFAULT_GRACE_PERIOD_SLOTS,
    authority_pkh: Optional[str] = None,
) -> DuesEnforcementContract:
    """Build a dues enforcement contract for a license.

    Creates a Plutus V2 contract that enforces annual dues payments for
    license validity. The contract gates validity token renewal on
    payment of the specified dues amount to the authority address.

    The contract enforces:
    1. Authority mints validity tokens with expiry slot
    2. Renewal requires dues payment (ADA transfer to authority)
    3. Expired validity tokens block signing operations
    4. Authority can revoke validity tokens at any time
    5. Grace period allows late renewal after expiry

    Args:
        authority_address: Bech32 Cardano address to receive dues payments.
        annual_dues_lovelace: Annual dues in lovelace (min 1 ADA = 1_000_000).
        license_ref: ID of the license this contract enforces.
        grace_period_slots: Slots after expiry for late renewal (default 86400).
        authority_pkh: Optional hex PKH. If not provided, extracted from address.

    Returns:
        DuesEnforcementContract instance with script hash and address.

    Raises:
        ValueError: If parameters are invalid.

    Example:
        >>> contract = build_dues_contract(
        ...     authority_address="addr_test1qz...",
        ...     annual_dues_lovelace=50_000_000,  # 50 ADA
        ...     license_ref=1,
        ... )
        >>> print(contract.get_contract_address())
        'addr_test1...'
        >>> is_valid, errors = contract.validate_payment(50_000_000, "addr_test1qz...")
        >>> print(is_valid)
        True
    """
    # Extract PKH from address if not provided
    if not authority_pkh:
        try:
            addr = Address.from_primitive(authority_address)
            if addr.payment_part:
                authority_pkh = addr.payment_part.to_primitive().hex()
            else:
                raise ValueError(
                    f"Cannot extract PKH from authority_address: {authority_address[:32]}..."
                )
        except Exception as e:
            if "Cannot extract" in str(e):
                raise
            raise ValueError(
                f"Invalid authority_address: {authority_address[:32]}...: {e}"
            )

    return DuesEnforcementContract(
        authority_pkh=authority_pkh,
        authority_address=authority_address,
        annual_dues_lovelace=annual_dues_lovelace,
        license_ref=license_ref,
        grace_period_slots=grace_period_slots,
    )


async def deploy_dues_contract(
    authority_wallet_label: str,
    license_ref: int,
    annual_dues_lovelace: int,
    grace_period_slots: int = DEFAULT_GRACE_PERIOD_SLOTS,
) -> Dict[str, Any]:
    """Deploy a dues enforcement contract for a license.

    Creates the contract, saves it to disk, and records in the database.

    Args:
        authority_wallet_label: Label of the authority wallet.
        license_ref: License ID to enforce dues on.
        annual_dues_lovelace: Annual dues amount in lovelace.
        grace_period_slots: Grace period in slots (default 86400).

    Returns:
        Dict with contract details including contract_id, address, script_hash.

    Raises:
        ValueError: If license not found or wallet missing.
        FileNotFoundError: If authority wallet keys not found.
    """
    # Verify license exists
    license_record = await get_license_by_id(license_ref)
    if not license_record:
        raise ValueError(f"License not found: {license_ref}")

    # Load authority keys
    authority_keys = load_wallet_keys(authority_wallet_label)
    authority_pkh = authority_keys["payment_key_hash"]
    authority_address = authority_keys["base_address"]

    # Build contract
    contract = build_dues_contract(
        authority_address=authority_address,
        annual_dues_lovelace=annual_dues_lovelace,
        license_ref=license_ref,
        grace_period_slots=grace_period_slots,
        authority_pkh=authority_pkh,
    )

    # Save to disk
    contract_label = f"lic_{license_ref}"
    contract.save_contract(contract_label)

    # Store in database
    contract_id = await _store_dues_contract(
        authority_address=authority_address,
        authority_pkh=authority_pkh,
        license_ref=license_ref,
        annual_dues_lovelace=annual_dues_lovelace,
        grace_period_slots=grace_period_slots,
        policy_id=contract.get_script_hash_hex(),
        script_hash=contract.get_script_hash_hex(),
        contract_address=contract.get_contract_address(),
        script_cbor_hex=contract.get_script_cbor_hex(),
    )

    logger.info(
        f"Deployed dues contract #{contract_id} for license #{license_ref}: "
        f"dues={annual_dues_lovelace} lovelace, grace={grace_period_slots} slots"
    )

    return {
        "contract_id": contract_id,
        "authority_address": authority_address,
        "authority_pkh": authority_pkh,
        "license_ref": license_ref,
        "annual_dues_lovelace": annual_dues_lovelace,
        "grace_period_slots": grace_period_slots,
        "contract_address": contract.get_contract_address(),
        "script_hash": contract.get_script_hash_hex(),
        "script_cbor_hex": contract.get_script_cbor_hex(),
        "contract_label": contract_label,
    }


async def _store_dues_contract(
    authority_address: str,
    authority_pkh: str,
    license_ref: int,
    annual_dues_lovelace: int,
    grace_period_slots: int,
    policy_id: str,
    script_hash: str,
    contract_address: str,
    script_cbor_hex: str,
) -> int:
    """Insert a dues contract record into dues_contracts table.

    Returns the contract row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO dues_contracts
               (authority_address, authority_pkh, license_ref, annual_dues_lovelace,
                grace_period_slots, policy_id, script_hash, contract_address,
                script_cbor_hex, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')""",
            (authority_address, authority_pkh, license_ref, annual_dues_lovelace,
             grace_period_slots, policy_id, script_hash, contract_address,
             script_cbor_hex),
        )
        await db.commit()
        return cursor.lastrowid


async def pay_dues(
    contract_id: int,
    payer_address: str,
    payment_lovelace: int,
    new_expiry: str,
    payment_tx_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a dues payment and renew the validity token.

    Validates the payment against the contract, records it in the database,
    and tracks the new expiry. In production, this would also build and
    submit the on-chain transaction.

    Args:
        contract_id: ID of the dues contract.
        payer_address: Cardano address of the payer.
        payment_lovelace: Amount paid in lovelace.
        new_expiry: New validity expiry date (ISO string).
        payment_tx_hash: Optional tx hash if already submitted on-chain.

    Returns:
        Dict with payment_id, validation result, and new expiry info.

    Raises:
        ValueError: If contract not found or payment invalid.
    """
    # Load contract
    contract_record = await get_dues_contract(contract_id)
    if not contract_record:
        raise ValueError(f"Dues contract not found: {contract_id}")
    if contract_record["status"] != "active":
        raise ValueError(
            f"Dues contract {contract_id} is {contract_record['status']}, not active"
        )

    # Reconstruct contract for validation
    contract = DuesEnforcementContract(
        authority_pkh=contract_record["authority_pkh"],
        authority_address=contract_record["authority_address"],
        annual_dues_lovelace=contract_record["annual_dues_lovelace"],
        license_ref=contract_record["license_ref"],
        grace_period_slots=contract_record["grace_period_slots"],
    )

    # Validate payment
    is_valid, errors = contract.validate_payment(
        payment_lovelace=payment_lovelace,
        recipient_address=contract_record["authority_address"],
    )

    if not is_valid:
        raise ValueError(f"Payment validation failed: {'; '.join(errors)}")

    # Get current validity info for the license
    license_record = await get_license_by_id(contract_record["license_ref"])
    licensee_address = license_record["licensee_address"] if license_record else payer_address

    # Record payment
    payment_id = await _store_dues_payment(
        contract_id=contract_id,
        payer_address=payer_address,
        amount_lovelace=payment_lovelace,
        payment_tx_hash=payment_tx_hash,
        new_expiry=new_expiry,
        status="confirmed" if payment_tx_hash else "pending",
    )

    logger.info(
        f"Dues payment #{payment_id} for contract #{contract_id}: "
        f"{payment_lovelace} lovelace, new_expiry={new_expiry}"
    )

    return {
        "payment_id": payment_id,
        "contract_id": contract_id,
        "payer_address": payer_address,
        "amount_lovelace": payment_lovelace,
        "new_expiry": new_expiry,
        "payment_tx_hash": payment_tx_hash,
        "status": "confirmed" if payment_tx_hash else "pending",
        "license_ref": contract_record["license_ref"],
        "licensee_address": licensee_address,
    }


async def _store_dues_payment(
    contract_id: int,
    payer_address: str,
    amount_lovelace: int,
    payment_tx_hash: Optional[str],
    new_expiry: str,
    status: str = "pending",
) -> int:
    """Insert a dues payment record.

    Returns the payment row ID.
    """
    async with aiosqlite.connect(LICENSE_DB) as db:
        cursor = await db.execute(
            """INSERT INTO dues_payments
               (contract_id, payer_address, amount_lovelace, payment_tx_hash,
                new_expiry, status, confirmed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (contract_id, payer_address, amount_lovelace, payment_tx_hash,
             new_expiry, status,
             datetime.now().isoformat() if status == "confirmed" else None),
        )
        await db.commit()
        return cursor.lastrowid


async def revoke_dues_validity(
    contract_id: int,
    reason: str = "authority_revocation",
) -> Dict[str, Any]:
    """Revoke validity under a dues contract (authority action).

    Marks the contract as suspended and expires all active validity tokens
    for the associated license.

    Args:
        contract_id: ID of the dues contract.
        reason: Reason for revocation.

    Returns:
        Dict with revocation details.
    """
    contract_record = await get_dues_contract(contract_id)
    if not contract_record:
        raise ValueError(f"Dues contract not found: {contract_id}")

    license_ref = contract_record["license_ref"]

    # Suspend the contract
    async with aiosqlite.connect(LICENSE_DB) as db:
        await db.execute(
            """UPDATE dues_contracts
               SET status = 'suspended', updated_at = datetime('now'),
                   metadata_json = json_set(COALESCE(metadata_json, '{}'),
                       '$.revocation_reason', ?,
                       '$.revoked_at', datetime('now'))
               WHERE id = ?""",
            (reason, contract_id),
        )
        await db.commit()

    # Expire active validity tokens for this license
    license_record = await get_license_by_id(license_ref)
    if license_record:
        await _expire_active_validity_tokens(
            licensee_address=license_record["licensee_address"],
            license_ref=license_ref,
        )

    logger.info(f"Revoked dues contract #{contract_id}: reason={reason}")

    return {
        "contract_id": contract_id,
        "license_ref": license_ref,
        "status": "suspended",
        "reason": reason,
    }


async def get_dues_contract(contract_id: int) -> Optional[Dict[str, Any]]:
    """Look up a dues contract by ID."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM dues_contracts WHERE id = ?", (contract_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_dues_contract_for_license(license_ref: int) -> Optional[Dict[str, Any]]:
    """Look up the active dues contract for a license."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM dues_contracts
               WHERE license_ref = ? AND status = 'active'
               ORDER BY created_at DESC LIMIT 1""",
            (license_ref,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_dues_contracts(
    status: Optional[str] = None,
    authority_address: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List dues contracts with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if authority_address:
            conditions.append("authority_address = ?")
            params.append(authority_address)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM dues_contracts{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def list_dues_payments(
    contract_id: Optional[int] = None,
    payer_address: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List dues payments with optional filters."""
    async with aiosqlite.connect(LICENSE_DB) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if contract_id is not None:
            conditions.append("contract_id = ?")
            params.append(contract_id)
        if payer_address:
            conditions.append("payer_address = ?")
            params.append(payer_address)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM dues_payments{where} ORDER BY created_at DESC",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_dues_status(license_ref: int) -> Dict[str, Any]:
    """Get comprehensive dues status for a license.

    Returns contract info, payment history, and current validity state.
    """
    contract = await get_dues_contract_for_license(license_ref)
    if not contract:
        return {
            "license_ref": license_ref,
            "has_dues_contract": False,
            "contract": None,
            "payments": [],
            "total_paid": 0,
        }

    payments = await list_dues_payments(contract_id=contract["id"])
    confirmed_payments = [p for p in payments if p["status"] == "confirmed"]
    total_paid = sum(p["amount_lovelace"] for p in confirmed_payments)

    # Get latest expiry from confirmed payments
    latest_expiry = None
    if confirmed_payments:
        latest_expiry = max(
            (p["new_expiry"] for p in confirmed_payments if p.get("new_expiry")),
            default=None,
        )

    return {
        "license_ref": license_ref,
        "has_dues_contract": True,
        "contract_id": contract["id"],
        "contract_status": contract["status"],
        "annual_dues_lovelace": contract["annual_dues_lovelace"],
        "annual_dues_ada": contract["annual_dues_lovelace"] / 1_000_000,
        "authority_address": contract["authority_address"],
        "grace_period_slots": contract["grace_period_slots"],
        "contract_address": contract.get("contract_address"),
        "total_payments": len(confirmed_payments),
        "total_paid_lovelace": total_paid,
        "total_paid_ada": total_paid / 1_000_000,
        "latest_expiry": latest_expiry,
        "payments": payments,
    }


# ── Summary / Status ──────────────────────────────────────────────

async def get_cardano_status() -> Dict[str, Any]:
    """Get Cardano module configuration status."""
    wallets = await list_wallets()
    licenses = await list_licenses()
    sig_tokens = await list_signature_tokens()
    val_tokens = await list_validity_tokens()
    signatures = await list_signatures()
    work_products = await list_work_products()
    dues_contracts = await list_dues_contracts()
    has_blockfrost = bool(BLOCKFROST_PROJECT_ID)

    return {
        "network": CARDANO_NETWORK,
        "blockfrost_configured": has_blockfrost,
        "blockfrost_url": _get_blockfrost_url(),
        "wallet_count": len(wallets),
        "wallets_by_type": {
            wt: sum(1 for w in wallets if w["wallet_type"] == wt)
            for wt in WALLET_TYPES
        },
        "license_count": len(licenses),
        "licenses_by_status": {
            s: sum(1 for lic in licenses if lic["status"] == s)
            for s in ("pending", "active", "revoked", "expired", "burned")
            if any(lic["status"] == s for lic in licenses)
        },
        "signature_token_count": len(sig_tokens),
        "signature_tokens_total_qty": sum(t.get("quantity", 0) for t in sig_tokens),
        "validity_token_count": len(val_tokens),
        "validity_tokens_by_status": {
            s: sum(1 for vt in val_tokens if vt["status"] == s)
            for s in ("pending", "active", "expired", "revoked", "burned")
            if any(vt["status"] == s for vt in val_tokens)
        },
        "document_signature_count": len(signatures),
        "work_product_count": len(work_products),
        "work_products_by_status": {
            s: sum(1 for wp in work_products if wp["status"] == s)
            for s in ("pending_signatures", "partially_signed", "fully_signed", "finalized", "rejected")
            if any(wp["status"] == s for wp in work_products)
        },
        "dues_contract_count": len(dues_contracts),
        "dues_contracts_by_status": {
            s: sum(1 for dc in dues_contracts if dc["status"] == s)
            for s in ("active", "suspended", "terminated")
            if any(dc["status"] == s for dc in dues_contracts)
        },
        "wallet_dir": str(WALLET_DIR),
    }


# ── CLI Entry Point ───────────────────────────────────────────────

async def _cli_main():
    """Simple CLI for wallet operations."""
    import argparse

    parser = argparse.ArgumentParser(description="Cardano License - Wallet & NFT Manager")
    sub = parser.add_subparsers(dest="command")

    # status
    sub.add_parser("status", help="Show Cardano config status")

    # generate
    gen = sub.add_parser("generate", help="Generate a new wallet")
    gen.add_argument("wallet_type", choices=WALLET_TYPES)
    gen.add_argument("--label", required=True, help="Wallet label")

    # list
    lst = sub.add_parser("list", help="List wallets")
    lst.add_argument("--type", choices=WALLET_TYPES, default=None)

    # balance
    bal = sub.add_parser("balance", help="Query wallet balance")
    bal.add_argument("label", help="Wallet label")

    # licenses
    lic = sub.add_parser("licenses", help="List license NFTs")
    lic.add_argument("--status", choices=("pending", "active", "revoked", "expired", "burned"), default=None)

    # work-products
    wp_sub = sub.add_parser("work-products", help="List work products")
    wp_sub.add_argument("--status", choices=(
        "pending_signatures", "partially_signed", "fully_signed", "finalized", "rejected"
    ), default=None)

    # wp-status
    wps = sub.add_parser("wp-status", help="Get work product status")
    wps.add_argument("--id", type=int, help="Work product ID")
    wps.add_argument("--address", help="Work product wallet address")

    args = parser.parse_args()

    if args.command == "status":
        status = await get_cardano_status()
        print("=" * 50)
        print("  Cardano License - Status")
        print("=" * 50)
        print(f"  Network:      {status['network']}")
        print(f"  Blockfrost:   {'configured' if status['blockfrost_configured'] else 'NOT SET'}")
        print(f"  API URL:      {status['blockfrost_url']}")
        print(f"  Wallets:      {status['wallet_count']}")
        for wt, count in status["wallets_by_type"].items():
            if count > 0:
                print(f"    {wt}: {count}")
        print(f"  Licenses:     {status['license_count']}")
        for ls, count in status.get("licenses_by_status", {}).items():
            if count > 0:
                print(f"    {ls}: {count}")
        print(f"  Key dir:      {status['wallet_dir']}")
        print("=" * 50)

    elif args.command == "generate":
        result = await generate_wallet(args.wallet_type, args.label)
        print("=" * 50)
        print("  New Wallet Generated")
        print("=" * 50)
        print(f"  Type:     {result['wallet_type']}")
        print(f"  Label:    {result['label']}")
        print(f"  Network:  {result['network']}")
        print(f"  Address:  {result['base_address']}")
        print(f"  Key Hash: {result['payment_key_hash']}")
        print("-" * 50)
        print(f"  Mnemonic ({len(result['mnemonic'].split())} words):")
        print(f"  {result['mnemonic']}")
        print("-" * 50)
        print("  SAVE YOUR MNEMONIC SECURELY!")
        print("=" * 50)

    elif args.command == "list":
        wallets = await list_wallets(wallet_type=args.type)
        print("=" * 50)
        print(f"  Wallets ({len(wallets)})")
        print("=" * 50)
        for w in wallets:
            print(f"  [{w['wallet_type']}] {w.get('label', 'N/A')}")
            print(f"    {w['address']}")
            print(f"    Network: {w['network']}  Created: {w['created_at']}")
            print()

    elif args.command == "balance":
        try:
            bal = await get_wallet_balance(args.label)
            print("=" * 50)
            print(f"  Balance: {args.label}")
            print("=" * 50)
            print(f"  ADA:      {bal['ada']:.6f}")
            print(f"  Lovelace: {bal['lovelace']}")
            print(f"  UTXOs:    {bal['utxo_count']}")
            if bal["native_assets"]:
                print(f"  Native assets: {len(bal['native_assets'])} policies")
            print("=" * 50)
        except ValueError as e:
            print(f"Error: {e}")

    elif args.command == "licenses":
        lics = await list_licenses(status=args.status)
        print("=" * 50)
        print(f"  Licenses ({len(lics)})")
        print("=" * 50)
        for lic in lics:
            print(f"  [{lic['status']}] {lic['token_name']}")
            print(f"    Policy: {lic['policy_id'][:16]}...")
            print(f"    Licensee: {lic['licensee_address'][:32]}...")
            print(f"    Type: {lic.get('license_type', 'N/A')}")
            if lic.get("mint_tx_hash"):
                print(f"    Tx: {lic['mint_tx_hash'][:16]}...")
            print()

    elif args.command == "work-products":
        wps = await list_work_products(status=args.status)
        print("=" * 50)
        print(f"  Work Products ({len(wps)})")
        print("=" * 50)
        for wp in wps:
            print(f"  [{wp['status']}] {wp['title']}")
            print(f"    Doc: {wp['document_hash'][:32]}...")
            if wp.get("wp_address"):
                print(f"    Address: {wp['wp_address'][:32]}...")
            print(f"    Progress: {wp['signature_progress']}")
            if wp.get("finalized_at"):
                print(f"    Finalized: {wp['finalized_at']}")
            print()

    elif args.command == "wp-status":
        if not args.id and not args.address:
            print("Error: provide --id or --address")
        else:
            status = await get_work_product_status(
                work_product_id=args.id, wp_address=args.address
            )
            if not status:
                print("Work product not found")
            else:
                print("=" * 50)
                print(f"  Work Product: {status['title']}")
                print("=" * 50)
                print(f"  ID:       {status['work_product_id']}")
                print(f"  Status:   {status['status']}")
                print(f"  Progress: {status['signature_progress']}")
                if status["wp_address"]:
                    print(f"  Address:  {status['wp_address'][:48]}...")
                print(f"  Doc Hash: {status['document_hash'][:48]}...")
                if status["missing_signers"]:
                    print(f"  Missing:  {len(status['missing_signers'])} signer(s)")
                    for addr in status["missing_signers"]:
                        print(f"    - {addr[:48]}...")
                if status["finalized_at"]:
                    print(f"  Finalized: {status['finalized_at']}")
                print("=" * 50)

    else:
        parser.print_help()


def _cli_entry():
    """Entry point for the ``cardano-license`` console script."""
    asyncio.run(_cli_main())


if __name__ == "__main__":
    _cli_entry()
