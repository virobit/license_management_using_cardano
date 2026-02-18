"""Cardano Transaction Builder Utilities.

Created: 2026-02-16

Transaction building helpers for the Cardano License & Signature system:
- estimate_fee: Estimate transaction fees from a TransactionBody
- build_mint_tx: Build a minting transaction with policy, metadata, and recipient
- build_transfer_tx: Build a token/ADA transfer transaction
- build_multisig_tx: Build a multi-signer transaction
- submit_tx: Submit a signed transaction to the network
- wait_for_confirmation: Poll for on-chain confirmation

All functions are async-compatible. Uses PyCardano for Cardano interactions
and reuses shared config from cardano_license.py.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union

from pycardano import (
    PaymentSigningKey,
    PaymentVerificationKey,
    Address,
    TransactionBuilder,
    TransactionBody,
    TransactionOutput,
    Transaction,
    Value,
    MultiAsset,
    Asset,
    AssetName,
    NativeScript,
    ScriptAll,
    ScriptPubkey,
    AuxiliaryData,
    AlonzoMetadata,
    Metadata,
    UTxO,
)
from pycardano.hash import ScriptHash, TransactionId

from cardano_license.core import (
    get_chain_context,
    load_wallet_keys,
    _get_network,
    LICENSE_DB,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────

MIN_UTXO_LOVELACE = 1_000_000  # Protocol minimum (~1 ADA)
DEFAULT_MIN_UTXO = 2_000_000   # Safe default (~2 ADA) for token outputs
FEE_BUFFER_LOVELACE = 200_000  # Buffer added to estimated fees
MAX_TX_SIZE_BYTES = 16_384     # Max transaction size (16 KB)
CONFIRMATION_POLL_INTERVAL = 5  # Seconds between confirmation polls
DEFAULT_CONFIRMATION_TIMEOUT = 120  # Default timeout for confirmation


# ── Data Classes ──────────────────────────────────────────────────

@dataclass
class TxResult:
    """Result of a built or submitted transaction."""
    tx_hash: str
    signed_tx: Optional[Transaction] = None
    fee_lovelace: int = 0
    inputs_used: int = 0
    outputs_count: int = 0
    mint_assets: Optional[Dict[str, int]] = None
    confirmed: bool = False
    block_height: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "fee_lovelace": self.fee_lovelace,
            "inputs_used": self.inputs_used,
            "outputs_count": self.outputs_count,
            "mint_assets": self.mint_assets,
            "confirmed": self.confirmed,
            "block_height": self.block_height,
            "error": self.error,
        }


@dataclass
class UTxOSelection:
    """Result of UTxO selection for a transaction."""
    selected: List[UTxO]
    total_lovelace: int = 0
    total_assets: Optional[Dict[str, int]] = None
    change_lovelace: int = 0


# ── Fee Estimation ────────────────────────────────────────────────

def estimate_fee(tx_body: TransactionBody) -> int:
    """Estimate the transaction fee from a TransactionBody.

    Uses the Cardano linear fee model: fee = A * tx_size + B
    where A = min_fee_coefficient (44 lovelace/byte on mainnet)
    and B = min_fee_constant (155381 lovelace on mainnet).

    Args:
        tx_body: A PyCardano TransactionBody (built but unsigned).

    Returns:
        Estimated fee in lovelace.
    """
    # Cardano mainnet/testnet fee parameters (Babbage era)
    MIN_FEE_A = 44       # lovelace per byte
    MIN_FEE_B = 155_381  # constant term

    # Serialize to get actual size
    try:
        tx_bytes = tx_body.to_cbor()
        tx_size = len(tx_bytes)
    except Exception:
        # Fallback: estimate size based on inputs/outputs
        n_inputs = len(tx_body.inputs) if tx_body.inputs else 0
        n_outputs = len(tx_body.outputs) if tx_body.outputs else 0
        # ~250 bytes base + ~60 per input + ~80 per output + witness overhead
        tx_size = 250 + (n_inputs * 60) + (n_outputs * 80) + 200

    fee = (MIN_FEE_A * tx_size) + MIN_FEE_B

    # Add buffer for witness signatures (~150 bytes per witness)
    witness_overhead = 150 * max(1, len(tx_body.inputs) if tx_body.inputs else 1)
    fee += MIN_FEE_A * witness_overhead

    return fee


def estimate_fee_from_context(
    n_inputs: int = 1,
    n_outputs: int = 2,
    n_witnesses: int = 1,
    has_mint: bool = False,
    has_metadata: bool = False,
    has_scripts: bool = False,
) -> int:
    """Estimate fee without a tx_body, using heuristics.

    Useful for pre-flight fee checks before building the full tx.

    Args:
        n_inputs: Number of transaction inputs.
        n_outputs: Number of transaction outputs.
        n_witnesses: Number of signing keys.
        has_mint: Whether the transaction mints/burns tokens.
        has_metadata: Whether auxiliary data is attached.
        has_scripts: Whether native scripts are included.

    Returns:
        Estimated fee in lovelace.
    """
    MIN_FEE_A = 44
    MIN_FEE_B = 155_381

    # Base transaction overhead
    base_size = 250

    # Inputs: ~60 bytes each (32-byte tx hash + index + metadata)
    input_size = n_inputs * 60

    # Outputs: ~80 bytes each (address + value)
    output_size = n_outputs * 80

    # Witnesses: ~150 bytes each (verification key + signature)
    witness_size = n_witnesses * 150

    # Minting: ~200 bytes for mint field + policy script
    mint_size = 200 if has_mint else 0

    # Metadata: ~300 bytes average for CIP-25 style metadata
    metadata_size = 300 if has_metadata else 0

    # Scripts: ~200 bytes for native scripts
    script_size = 200 if has_scripts else 0

    total_size = (
        base_size + input_size + output_size + witness_size
        + mint_size + metadata_size + script_size
    )
    fee = (MIN_FEE_A * total_size) + MIN_FEE_B + FEE_BUFFER_LOVELACE

    return fee


# ── UTxO Selection ────────────────────────────────────────────────

def select_utxos(
    available_utxos: List[UTxO],
    required_lovelace: int,
    required_assets: Optional[Dict[str, Dict[str, int]]] = None,
) -> UTxOSelection:
    """Select UTxOs to cover the required amount using largest-first strategy.

    Args:
        available_utxos: List of UTxOs from the wallet.
        required_lovelace: Total lovelace needed (including fees).
        required_assets: Optional dict of {policy_id_hex: {asset_name_hex: quantity}}.

    Returns:
        UTxOSelection with selected UTxOs and change info.

    Raises:
        ValueError: If insufficient funds.
    """
    if not available_utxos:
        raise ValueError("No UTxOs available for selection")

    # Sort UTxOs by lovelace amount descending (largest first for efficiency)
    sorted_utxos = sorted(
        available_utxos,
        key=lambda u: _utxo_lovelace(u),
        reverse=True,
    )

    selected = []
    total_lovelace = 0
    collected_assets: Dict[str, Dict[str, int]] = {}
    assets_satisfied = required_assets is None

    for utxo in sorted_utxos:
        selected.append(utxo)
        total_lovelace += _utxo_lovelace(utxo)

        # Track native assets in this UTxO
        _accumulate_utxo_assets(utxo, collected_assets)

        # Check if we have enough lovelace
        lovelace_ok = total_lovelace >= required_lovelace

        # Check if we have enough of each required asset
        if required_assets:
            assets_satisfied = _assets_satisfied(collected_assets, required_assets)

        if lovelace_ok and assets_satisfied:
            break

    # Verify we collected enough
    if total_lovelace < required_lovelace:
        raise ValueError(
            f"Insufficient lovelace: have {total_lovelace}, need {required_lovelace}"
        )
    if not assets_satisfied:
        raise ValueError(
            f"Insufficient native assets for required tokens"
        )

    change = total_lovelace - required_lovelace

    return UTxOSelection(
        selected=selected,
        total_lovelace=total_lovelace,
        total_assets=_flatten_assets(collected_assets) if collected_assets else None,
        change_lovelace=change,
    )


def _utxo_lovelace(utxo: UTxO) -> int:
    """Extract lovelace amount from a UTxO."""
    output = utxo.output
    if isinstance(output.amount, Value):
        return output.amount.coin
    return output.amount


def _accumulate_utxo_assets(utxo: UTxO, collected: Dict[str, Dict[str, int]]):
    """Add native assets from a UTxO to the collected dict."""
    output = utxo.output
    if isinstance(output.amount, Value) and output.amount.multi_asset:
        for policy_id, assets in output.amount.multi_asset.items():
            pid_hex = policy_id.to_primitive().hex()
            if pid_hex not in collected:
                collected[pid_hex] = {}
            for asset_name, qty in assets.items():
                an_hex = asset_name.to_primitive().hex()
                collected[pid_hex][an_hex] = collected[pid_hex].get(an_hex, 0) + qty


def _assets_satisfied(
    collected: Dict[str, Dict[str, int]],
    required: Dict[str, Dict[str, int]],
) -> bool:
    """Check if collected assets cover all required amounts."""
    for pid, assets in required.items():
        if pid not in collected:
            return False
        for an, qty in assets.items():
            if collected[pid].get(an, 0) < qty:
                return False
    return True


def _flatten_assets(assets: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    """Flatten nested asset dict to {policy_id.asset_name: quantity}."""
    flat = {}
    for pid, inner in assets.items():
        for an, qty in inner.items():
            flat[f"{pid}.{an}"] = qty
    return flat


# ── Transaction Builders ──────────────────────────────────────────

async def build_mint_tx(
    wallet_label: str,
    policy: NativeScript,
    token_name: str,
    metadata: Optional[Dict[int, Any]] = None,
    recipient: Optional[str] = None,
    quantity: int = 1,
    min_utxo_ada: int = DEFAULT_MIN_UTXO,
) -> TxResult:
    """Build a minting transaction.

    Creates a transaction that mints tokens under the given policy and
    optionally sends them to a recipient address.

    Args:
        wallet_label: Label of the wallet funding and signing the tx.
        policy: NativeScript minting policy (e.g., ScriptPubkey).
        token_name: Name of the token to mint (string, will be UTF-8 encoded).
        metadata: Optional metadata dict keyed by label (e.g., {721: {...}} for CIP-25).
        recipient: Address to send minted tokens. If None, sends to wallet itself.
        quantity: Number of tokens to mint (default 1).
        min_utxo_ada: Minimum lovelace to send with tokens (default 2 ADA).

    Returns:
        TxResult with tx_hash, signed_tx, fee, and mint info.

    Raises:
        FileNotFoundError: If wallet keys not found.
        ValueError: If quantity < 1 or transaction build fails.
    """
    if quantity < 1:
        raise ValueError("quantity must be >= 1")

    # Load wallet keys
    wallet_keys = load_wallet_keys(wallet_label)
    payment_sk = wallet_keys["payment_sk"]
    wallet_address = wallet_keys["base_address"]

    # Determine recipient
    recipient_addr = recipient or wallet_address

    # Build mint MultiAsset
    policy_id = policy.hash()
    asset_name = AssetName(token_name.encode("utf-8"))
    mint = MultiAsset()
    mint[policy_id] = Asset()
    mint[policy_id][asset_name] = quantity

    # Build auxiliary data if metadata provided
    aux_data = None
    if metadata:
        aux_data = AuxiliaryData(data=AlonzoMetadata(metadata=Metadata(metadata)))

    # Build transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(wallet_address)
    builder.add_minting_script(policy)
    builder.mint = mint

    if aux_data:
        builder.auxiliary_data = aux_data

    # Output: tokens + min ADA to recipient
    token_value = Value(min_utxo_ada, mint)
    builder.add_output(TransactionOutput(
        Address.from_primitive(recipient_addr),
        token_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[payment_sk],
        change_address=Address.from_primitive(wallet_address),
    )

    tx_hash = signed_tx.id.to_primitive().hex()
    fee = signed_tx.transaction_body.fee if signed_tx.transaction_body.fee else 0

    logger.info(f"Built mint tx: {quantity}x {token_name}, tx={tx_hash}")

    return TxResult(
        tx_hash=tx_hash,
        signed_tx=signed_tx,
        fee_lovelace=fee,
        inputs_used=len(signed_tx.transaction_body.inputs) if signed_tx.transaction_body.inputs else 0,
        outputs_count=len(signed_tx.transaction_body.outputs) if signed_tx.transaction_body.outputs else 0,
        mint_assets={f"{policy_id.to_primitive().hex()}.{token_name}": quantity},
    )


async def build_transfer_tx(
    wallet_label: str,
    recipient: str,
    lovelace: Optional[int] = None,
    tokens: Optional[Dict[str, Dict[str, int]]] = None,
    min_utxo_ada: int = DEFAULT_MIN_UTXO,
) -> TxResult:
    """Build a token/ADA transfer transaction.

    Sends lovelace and/or native tokens from the wallet to a recipient.

    Args:
        wallet_label: Label of the sending wallet.
        recipient: Cardano address of the recipient.
        lovelace: Amount of lovelace to send. If None and tokens given, uses min_utxo_ada.
        tokens: Optional dict of {policy_id_hex: {token_name_str: quantity}} to transfer.
        min_utxo_ada: Minimum lovelace for token outputs (default 2 ADA).

    Returns:
        TxResult with tx_hash, signed_tx, and fee.

    Raises:
        ValueError: If neither lovelace nor tokens specified.
        FileNotFoundError: If wallet keys not found.
    """
    if lovelace is None and not tokens:
        raise ValueError("Must specify lovelace and/or tokens to transfer")

    # Load wallet keys
    wallet_keys = load_wallet_keys(wallet_label)
    payment_sk = wallet_keys["payment_sk"]
    wallet_address = wallet_keys["base_address"]

    # Build output value
    send_lovelace = lovelace if lovelace else min_utxo_ada

    if tokens:
        multi_asset = MultiAsset()
        for policy_id_hex, assets in tokens.items():
            pid = ScriptHash.from_primitive(bytes.fromhex(policy_id_hex))
            multi_asset[pid] = Asset()
            for token_name_str, qty in assets.items():
                asset_name = AssetName(token_name_str.encode("utf-8"))
                multi_asset[pid][asset_name] = qty
        output_value = Value(send_lovelace, multi_asset)
    else:
        output_value = send_lovelace

    # Build transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(wallet_address)
    builder.add_output(TransactionOutput(
        Address.from_primitive(recipient),
        output_value,
    ))

    # Build and sign
    signed_tx = builder.build_and_sign(
        signing_keys=[payment_sk],
        change_address=Address.from_primitive(wallet_address),
    )

    tx_hash = signed_tx.id.to_primitive().hex()
    fee = signed_tx.transaction_body.fee if signed_tx.transaction_body.fee else 0

    logger.info(f"Built transfer tx: {send_lovelace} lovelace to {recipient[:32]}..., tx={tx_hash}")

    return TxResult(
        tx_hash=tx_hash,
        signed_tx=signed_tx,
        fee_lovelace=fee,
        inputs_used=len(signed_tx.transaction_body.inputs) if signed_tx.transaction_body.inputs else 0,
        outputs_count=len(signed_tx.transaction_body.outputs) if signed_tx.transaction_body.outputs else 0,
    )


async def build_multisig_tx(
    signers: List[Dict[str, Any]],
    outputs: List[Dict[str, Any]],
    funding_wallet_label: Optional[str] = None,
) -> TxResult:
    """Build a multi-signature transaction.

    Creates a transaction requiring multiple signers, using ScriptAll
    native script. Each signer dict must have 'wallet_label' (to load keys)
    or 'payment_sk' and 'payment_vk' directly.

    Args:
        signers: List of signer dicts, each with either:
            - 'wallet_label': str (loads keys from file), or
            - 'payment_sk': PaymentSigningKey, 'payment_vk': PaymentVerificationKey
        outputs: List of output dicts, each with:
            - 'address': str (recipient Cardano address)
            - 'lovelace': int (amount to send)
            - 'tokens': Optional dict of {policy_id_hex: {token_name: qty}}
        funding_wallet_label: Wallet to fund the tx. If None, uses first signer.

    Returns:
        TxResult with tx_hash and signed_tx.

    Raises:
        ValueError: If signers list is empty or outputs invalid.
    """
    if not signers:
        raise ValueError("At least one signer is required")
    if not outputs:
        raise ValueError("At least one output is required")

    # Resolve signer keys
    signing_keys: List[PaymentSigningKey] = []
    verification_keys: List[PaymentVerificationKey] = []

    for signer in signers:
        if "wallet_label" in signer:
            keys = load_wallet_keys(signer["wallet_label"])
            signing_keys.append(keys["payment_sk"])
            verification_keys.append(keys["payment_vk"])
        elif "payment_sk" in signer and "payment_vk" in signer:
            signing_keys.append(signer["payment_sk"])
            verification_keys.append(signer["payment_vk"])
        else:
            raise ValueError(
                "Each signer must have 'wallet_label' or 'payment_sk'+'payment_vk'"
            )

    # Determine funding wallet
    if funding_wallet_label:
        funding_keys = load_wallet_keys(funding_wallet_label)
        funding_address = funding_keys["base_address"]
        # Add funding key if not already in signers
        if funding_keys["payment_sk"] not in signing_keys:
            signing_keys.insert(0, funding_keys["payment_sk"])
    else:
        # Use first signer as funder
        if "wallet_label" in signers[0]:
            funding_keys = load_wallet_keys(signers[0]["wallet_label"])
        else:
            funding_keys = signers[0]
        funding_address = funding_keys.get("base_address")
        if not funding_address:
            # Derive address from verification key
            vk = verification_keys[0]
            funding_address = str(Address(vk.hash(), network=_get_network()))

    # Build multisig native script (all signers required)
    multisig_script = ScriptAll(
        [ScriptPubkey(vk.hash()) for vk in verification_keys]
    )

    # Build transaction
    context = get_chain_context()
    builder = TransactionBuilder(context)

    builder.add_input_address(funding_address)

    # Add outputs
    for out in outputs:
        addr = Address.from_primitive(out["address"])
        lovelace = out.get("lovelace", DEFAULT_MIN_UTXO)

        if "tokens" in out and out["tokens"]:
            multi_asset = MultiAsset()
            for pid_hex, assets in out["tokens"].items():
                pid = ScriptHash.from_primitive(bytes.fromhex(pid_hex))
                multi_asset[pid] = Asset()
                for tn_str, qty in assets.items():
                    multi_asset[pid][AssetName(tn_str.encode("utf-8"))] = qty
            output_value = Value(lovelace, multi_asset)
        else:
            output_value = lovelace

        builder.add_output(TransactionOutput(addr, output_value))

    # Build and sign with all keys
    signed_tx = builder.build_and_sign(
        signing_keys=signing_keys,
        change_address=Address.from_primitive(funding_address),
    )

    tx_hash = signed_tx.id.to_primitive().hex()
    fee = signed_tx.transaction_body.fee if signed_tx.transaction_body.fee else 0

    logger.info(f"Built multisig tx: {len(signers)} signers, {len(outputs)} outputs, tx={tx_hash}")

    return TxResult(
        tx_hash=tx_hash,
        signed_tx=signed_tx,
        fee_lovelace=fee,
        inputs_used=len(signed_tx.transaction_body.inputs) if signed_tx.transaction_body.inputs else 0,
        outputs_count=len(signed_tx.transaction_body.outputs) if signed_tx.transaction_body.outputs else 0,
    )


# ── Submission & Confirmation ─────────────────────────────────────

async def submit_tx(signed_tx: Transaction) -> TxResult:
    """Submit a signed transaction to the Cardano network.

    Args:
        signed_tx: A fully signed PyCardano Transaction.

    Returns:
        TxResult with tx_hash and submission status.
    """
    tx_hash = signed_tx.id.to_primitive().hex()

    try:
        context = get_chain_context()
        context.submit_tx(signed_tx)
        logger.info(f"Transaction submitted: {tx_hash}")

        fee = signed_tx.transaction_body.fee if signed_tx.transaction_body.fee else 0

        return TxResult(
            tx_hash=tx_hash,
            signed_tx=signed_tx,
            fee_lovelace=fee,
            inputs_used=len(signed_tx.transaction_body.inputs) if signed_tx.transaction_body.inputs else 0,
            outputs_count=len(signed_tx.transaction_body.outputs) if signed_tx.transaction_body.outputs else 0,
        )
    except Exception as e:
        logger.error(f"Transaction submission failed: {tx_hash} — {e}")
        return TxResult(
            tx_hash=tx_hash,
            error=str(e),
        )


async def wait_for_confirmation(
    tx_hash: str,
    timeout: int = DEFAULT_CONFIRMATION_TIMEOUT,
    poll_interval: int = CONFIRMATION_POLL_INTERVAL,
) -> TxResult:
    """Wait for a transaction to appear on-chain.

    Polls Blockfrost for the transaction until it's confirmed or timeout.

    Args:
        tx_hash: Transaction hash to wait for.
        timeout: Maximum seconds to wait (default 120).
        poll_interval: Seconds between polls (default 5).

    Returns:
        TxResult with confirmed=True and block_height if found,
        or confirmed=False with error if timeout.
    """
    import requests

    from cardano_license.core import BLOCKFROST_PROJECT_ID, _get_blockfrost_url

    if not BLOCKFROST_PROJECT_ID:
        return TxResult(
            tx_hash=tx_hash,
            error="BLOCKFROST_PROJECT_ID not set — cannot poll for confirmation",
        )

    base_url = _get_blockfrost_url()
    headers = {"project_id": BLOCKFROST_PROJECT_ID}
    url = f"{base_url}/txs/{tx_hash}"

    start = time.monotonic()
    elapsed = 0.0

    while elapsed < timeout:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                block_height = data.get("block_height")
                logger.info(f"Transaction confirmed: {tx_hash} at block {block_height}")
                return TxResult(
                    tx_hash=tx_hash,
                    confirmed=True,
                    block_height=block_height,
                    fee_lovelace=int(data.get("fees", 0)),
                )
            elif resp.status_code == 404:
                # Not yet on-chain, keep polling
                pass
            else:
                logger.warning(f"Blockfrost error polling tx {tx_hash}: {resp.status_code}")
        except requests.RequestException as e:
            logger.warning(f"Network error polling tx {tx_hash}: {e}")

        await asyncio.sleep(poll_interval)
        elapsed = time.monotonic() - start

    logger.warning(f"Transaction not confirmed within {timeout}s: {tx_hash}")
    return TxResult(
        tx_hash=tx_hash,
        confirmed=False,
        error=f"Confirmation timeout after {timeout}s",
    )


# ── Convenience Functions ─────────────────────────────────────────

async def build_and_submit_mint(
    wallet_label: str,
    policy: NativeScript,
    token_name: str,
    metadata: Optional[Dict[int, Any]] = None,
    recipient: Optional[str] = None,
    quantity: int = 1,
    wait_confirm: bool = False,
    confirm_timeout: int = DEFAULT_CONFIRMATION_TIMEOUT,
) -> TxResult:
    """Build, submit, and optionally wait for a minting transaction.

    Combines build_mint_tx + submit_tx + optional wait_for_confirmation.
    """
    result = await build_mint_tx(
        wallet_label=wallet_label,
        policy=policy,
        token_name=token_name,
        metadata=metadata,
        recipient=recipient,
        quantity=quantity,
    )
    if result.error:
        return result

    submit_result = await submit_tx(result.signed_tx)
    if submit_result.error:
        return submit_result

    if wait_confirm:
        return await wait_for_confirmation(result.tx_hash, timeout=confirm_timeout)

    return submit_result


async def build_and_submit_transfer(
    wallet_label: str,
    recipient: str,
    lovelace: Optional[int] = None,
    tokens: Optional[Dict[str, Dict[str, int]]] = None,
    wait_confirm: bool = False,
    confirm_timeout: int = DEFAULT_CONFIRMATION_TIMEOUT,
) -> TxResult:
    """Build, submit, and optionally wait for a transfer transaction.

    Combines build_transfer_tx + submit_tx + optional wait_for_confirmation.
    """
    result = await build_transfer_tx(
        wallet_label=wallet_label,
        recipient=recipient,
        lovelace=lovelace,
        tokens=tokens,
    )
    if result.error:
        return result

    submit_result = await submit_tx(result.signed_tx)
    if submit_result.error:
        return submit_result

    if wait_confirm:
        return await wait_for_confirmation(result.tx_hash, timeout=confirm_timeout)

    return submit_result


def calculate_min_utxo(
    has_tokens: bool = False,
    n_distinct_assets: int = 0,
    n_distinct_policies: int = 0,
) -> int:
    """Calculate minimum UTxO value for a given output.

    Cardano requires a minimum ADA for UTxOs carrying native tokens.
    The formula scales with the number of distinct assets and policies.

    Args:
        has_tokens: Whether the output carries native tokens.
        n_distinct_assets: Number of distinct asset names.
        n_distinct_policies: Number of distinct policy IDs.

    Returns:
        Minimum lovelace required.
    """
    if not has_tokens:
        return MIN_UTXO_LOVELACE

    # Babbage-era min UTxO calculation (simplified)
    # Base: 1 ADA + 0.4 ADA per policy + 0.1 ADA per asset
    base = MIN_UTXO_LOVELACE
    policy_cost = n_distinct_policies * 400_000
    asset_cost = n_distinct_assets * 100_000

    return base + policy_cost + asset_cost
