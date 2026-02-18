"""Quickstart example for cardano-license.

Demonstrates:
  1. Database initialization
  2. Authority and licensee wallet creation
  3. License NFT minting (requires funded wallet + Blockfrost key)
  4. Signature token minting
  5. Validity token minting
  6. Document signing
  7. Work product management

Prerequisites:
  pip install -e .
  export BLOCKFROST_PROJECT_ID=preprodXXXXXX
  export CARDANO_LICENSE_PASSWORD=your-password
"""

import asyncio
from cardano_license import (
    init_db,
    create_authority_wallet,
    create_licensee_wallet,
    mint_license_nft,
    mint_signature_tokens,
    mint_validity_token,
    sign_document,
    create_work_product,
    get_work_product_status,
    get_cardano_status,
)


async def main():
    # 1. Initialize database tables
    await init_db()
    print("Database initialized.\n")

    # 2. Show system status
    status = await get_cardano_status()
    print(f"Network: {status['network']}")
    print(f"Blockfrost configured: {status['blockfrost_configured']}\n")

    # 3. Create wallets (offline — no Blockfrost needed)
    authority = await create_authority_wallet("demo_authority")
    print(f"Authority wallet created: {authority['base_address'][:48]}...")
    print(f"  Mnemonic: {authority['mnemonic'][:40]}...\n")

    licensee = await create_licensee_wallet("demo_licensee")
    print(f"Licensee wallet created: {licensee['base_address'][:48]}...")
    print(f"  Mnemonic: {licensee['mnemonic'][:40]}...\n")

    # ── Steps 4-7 require funded wallets + Blockfrost ──
    if not status["blockfrost_configured"]:
        print("Set BLOCKFROST_PROJECT_ID and fund wallets to continue.")
        print("Faucet: https://docs.cardano.org/cardano-testnets/tools/faucet/")
        return

    # 4. Mint license NFT
    license_metadata = {
        "license_type": "professional_engineer",
        "licensee_name": "Jane Doe, PE",
        "issuing_authority": "State Board of Engineering",
        "issue_date": "2026-01-15",
        "expiry_date": "2028-01-15",
        "jurisdiction": "California",
        "license_number": "PE-CA-12345",
    }
    result = await mint_license_nft(
        authority_wallet_label="demo_authority",
        licensee_address=licensee["base_address"],
        license_metadata=license_metadata,
    )
    print(f"License NFT minted! tx={result['tx_hash'][:16]}...")
    license_id = result["license_id"]

    # 5. Mint signature tokens (10 tokens tied to this license)
    sig_result = await mint_signature_tokens(
        authority_wallet_label="demo_authority",
        licensee_address=licensee["base_address"],
        token_count=10,
        license_ref=license_id,
    )
    print(f"Signature tokens minted: {sig_result['quantity']}x")

    # 6. Mint validity token (valid for 2 years)
    val_result = await mint_validity_token(
        authority_wallet_label="demo_authority",
        licensee_address=licensee["base_address"],
        license_ref=license_id,
        valid_until="2028-01-15T00:00:00",
    )
    print(f"Validity token minted: valid until {val_result['valid_until']}")

    # 7. Create a work product and sign it
    import hashlib
    doc_hash = hashlib.sha256(b"Engineering Report v1.0").hexdigest()

    wp = await create_work_product(
        title="Bridge Inspection Report",
        document_hash=doc_hash,
        required_signers=[licensee["base_address"]],
    )
    print(f"\nWork product created: {wp['title']}")

    # Sign the document
    sig = await sign_document(
        signer_wallet_label="demo_licensee",
        document_hash=doc_hash,
        license_ref=license_id,
    )
    print(f"Document signed: tx={sig['signature_tx_hash'][:16]}...")

    # Check work product status
    wp_status = await get_work_product_status(work_product_id=wp["work_product_id"])
    print(f"Work product status: {wp_status['status']}")
    print(f"Signatures: {wp_status['signature_progress']}")


if __name__ == "__main__":
    asyncio.run(main())
