"""Cardano License — Professional credential verification on Cardano.

NFT-based licenses, signature tokens, validity tokens, and Plutus V2
smart contracts for professional credential management.
"""

__version__ = "2.0.0"

# ── Core: wallets, chain, minting ────────────────────────────────

from cardano_license.core import (
    # Wallet generation & key management
    generate_wallet,
    create_authority_wallet,
    create_licensee_wallet,
    derive_keys_from_mnemonic,
    save_wallet_keys,
    load_wallet_keys,
    # Wallet queries
    store_wallet_metadata,
    get_wallet_by_label,
    get_wallet_by_address,
    list_wallets,
    get_wallet_balance,
    get_wallet_utxos,
    # Chain context
    get_chain_context,
    query_balance,
    query_utxos,
    # Minting policies
    create_minting_policy,
    build_minting_policy,
    attach_minting_policy,
    PlutusV2MintingPolicy,
    MintAction,
    BurnAction,
    validate_token_metadata_format,
    # Authority registry
    register_minting_authority,
    is_registered_authority,
    get_authority_policy,
    list_registered_authorities,
    # License NFTs
    mint_license_nft,
    build_cip25_metadata,
    get_license_by_id,
    get_license_by_tx_hash,
    list_licenses,
    # Signature tokens
    mint_signature_tokens,
    get_signature_balance,
    transfer_signature_token,
    get_signature_token_by_id,
    list_signature_tokens,
    # Validity tokens
    mint_validity_token,
    check_validity,
    renew_validity,
    revoke_validity_token,
    get_validity_token_by_id,
    list_validity_tokens,
    # Document signing & work products
    sign_document,
    verify_signature,
    create_work_product,
    get_work_product_status,
    get_work_product_by_address,
    finalize_work_product,
    list_work_products,
    list_signatures,
    get_signature_by_id,
    DOC_SIGN_METADATA_LABEL,
    # Signature validators (Plutus V2)
    SignatureCollectionValidator,
    SignerDatum,
    CollectRedeemer,
    FinalizeRedeemer,
    ReclaimRedeemer,
    build_signature_validator,
    deploy_signature_validator,
    validate_signer_deposit,
    check_finalization_ready,
    # Dues enforcement
    DuesEnforcementContract,
    DuesContractDatum,
    PayDuesRedeemer,
    RevokeValidityRedeemer,
    build_dues_contract,
    deploy_dues_contract,
    pay_dues,
    revoke_dues_validity,
    get_dues_contract,
    get_dues_contract_for_license,
    get_dues_status,
    list_dues_contracts,
    list_dues_payments,
    # Configuration & constants
    LICENSE_DB,
    WALLET_DIR,
    POLICY_DIR,
    BLOCKFROST_PROJECT_ID,
    CARDANO_NETWORK,
    PAYMENT_PATH,
    STAKE_PATH,
    VALID_REDEEMER_ACTIONS,
    REQUIRED_TOKEN_METADATA_FIELDS,
    REQUIRED_LICENSE_FIELDS,
    DEFAULT_GRACE_PERIOD_SLOTS,
    MIN_ANNUAL_DUES_LOVELACE,
    MAX_ANNUAL_DUES_LOVELACE,
    CIP25_METADATA_LABEL,
    WALLET_TYPES,
    # Status
    get_cardano_status,
)

# ── Transaction utilities ────────────────────────────────────────

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
)

# ── Schema initialization ────────────────────────────────────────

from cardano_license.schema import init_db

__all__ = [
    "__version__",
    # Wallets
    "generate_wallet",
    "create_authority_wallet",
    "create_licensee_wallet",
    "derive_keys_from_mnemonic",
    "save_wallet_keys",
    "load_wallet_keys",
    "store_wallet_metadata",
    "get_wallet_by_label",
    "get_wallet_by_address",
    "list_wallets",
    "get_wallet_balance",
    "get_wallet_utxos",
    # Chain
    "get_chain_context",
    "query_balance",
    "query_utxos",
    # Policies
    "create_minting_policy",
    "build_minting_policy",
    "attach_minting_policy",
    "PlutusV2MintingPolicy",
    "MintAction",
    "BurnAction",
    "validate_token_metadata_format",
    # Authority
    "register_minting_authority",
    "is_registered_authority",
    "get_authority_policy",
    "list_registered_authorities",
    # Licenses
    "mint_license_nft",
    "build_cip25_metadata",
    "get_license_by_id",
    "get_license_by_tx_hash",
    "list_licenses",
    # Signature tokens
    "mint_signature_tokens",
    "get_signature_balance",
    "transfer_signature_token",
    "get_signature_token_by_id",
    "list_signature_tokens",
    # Validity
    "mint_validity_token",
    "check_validity",
    "renew_validity",
    "revoke_validity_token",
    "get_validity_token_by_id",
    "list_validity_tokens",
    # Documents
    "sign_document",
    "verify_signature",
    "create_work_product",
    "get_work_product_status",
    "get_work_product_by_address",
    "finalize_work_product",
    "list_work_products",
    "list_signatures",
    "get_signature_by_id",
    "DOC_SIGN_METADATA_LABEL",
    # Validators
    "build_signature_validator",
    "deploy_signature_validator",
    "validate_signer_deposit",
    "check_finalization_ready",
    # Dues
    "build_dues_contract",
    "deploy_dues_contract",
    "pay_dues",
    "revoke_dues_validity",
    "get_dues_contract",
    "get_dues_contract_for_license",
    "get_dues_status",
    "list_dues_contracts",
    "list_dues_payments",
    # Tx utils
    "TxResult",
    "UTxOSelection",
    "estimate_fee",
    "estimate_fee_from_context",
    "select_utxos",
    "build_mint_tx",
    "build_transfer_tx",
    "build_multisig_tx",
    "submit_tx",
    "wait_for_confirmation",
    "build_and_submit_mint",
    "build_and_submit_transfer",
    "calculate_min_utxo",
    # Schema
    "init_db",
    "get_cardano_status",
]
