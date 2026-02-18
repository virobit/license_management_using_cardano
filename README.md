# Cardano License

Professional credential verification on the Cardano blockchain using NFT-based licenses, signature tokens, validity tokens, and Plutus V2 smart contracts.

## Overview

This system allows licensing authorities to issue, manage, and verify professional credentials entirely on-chain:

- **License NFTs** (CIP-25) — One NFT per professional license, carrying metadata (licensee, authority, jurisdiction, dates)
- **Signature Tokens** — Fungible tokens consumed when a licensee signs a document, creating an on-chain audit trail
- **Validity Tokens** — Time-bounded tokens representing current license validity, renewable by the authority
- **Work Products** — Multi-signer documents with wallet-based signature collection and finalization
- **Dues Enforcement** — Smart contract logic for annual dues payment tracking and license validity gating
- **Plutus V2 Contracts** — Authority-gated minting policies and signature collection validators

See [`docs/`](docs/) for the full research paper and architecture.

## Installation

```bash
pip install -e .
```

Or with dev dependencies:

```bash
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- A [Blockfrost](https://blockfrost.io) API key (free tier works for testnet)

## Configuration

All settings via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `BLOCKFROST_PROJECT_ID` | *(required for chain ops)* | Blockfrost API key |
| `CARDANO_NETWORK` | `testnet` | Network: `testnet`, `mainnet`, `preprod`, `preview` |
| `CARDANO_LICENSE_DIR` | `~/.cardano-license/` | Base directory for data |
| `CARDANO_LICENSE_DB` | `{DIR}/license.db` | SQLite database path |
| `CARDANO_LICENSE_PASSWORD` | *(interactive prompt)* | Encryption password for wallet keys |

Copy `.env.example` and fill in your values:

```bash
cp .env.example .env
source .env
```

## Quick Start

```python
import asyncio
from cardano_license import (
    init_db,
    create_authority_wallet,
    create_licensee_wallet,
    mint_license_nft,
)

async def main():
    await init_db()

    authority = await create_authority_wallet("my_authority")
    licensee = await create_licensee_wallet("my_licensee")

    # Fund authority wallet with test ADA from the faucet, then:
    result = await mint_license_nft(
        authority_wallet_label="my_authority",
        licensee_address=licensee["base_address"],
        license_metadata={
            "license_type": "professional_engineer",
            "licensee_name": "Jane Doe, PE",
            "issuing_authority": "State Board",
            "issue_date": "2026-01-15",
            "expiry_date": "2028-01-15",
            "jurisdiction": "California",
            "license_number": "PE-CA-12345",
        },
    )
    print(f"License minted: {result['tx_hash']}")

asyncio.run(main())
```

See [`examples/quickstart.py`](examples/quickstart.py) for a complete walkthrough.

## CLI

```bash
cardano-license status            # Show network config and counts
cardano-license generate authority --label my_authority
cardano-license list              # List all wallets
cardano-license balance my_authority
cardano-license licenses          # List all license NFTs
cardano-license work-products     # List work products
```

## Testing

```bash
# Unit tests (no Blockfrost needed)
pytest tests/test_license.py tests/test_contracts.py tests/test_tx_utils.py -v

# Integration tests (requires funded testnet wallet)
export BLOCKFROST_PROJECT_ID=preprodXXXXXX
pytest tests/test_testnet.py -v -m integration --timeout=300
```

## Architecture

```
┌─────────────────────────────────────────────┐
│              Licensing Authority             │
│  - Issues License NFTs (CIP-25)             │
│  - Mints signature & validity tokens        │
│  - Deploys dues enforcement contracts       │
└────────────────────┬────────────────────────┘
                     │ on-chain
┌────────────────────▼────────────────────────┐
│              Cardano Blockchain              │
│  - ScriptPubkey minting policies            │
│  - CIP-25 metadata (license details)        │
│  - Plutus V2 signature validators           │
│  - Time-bounded validity tokens             │
└────────────────────┬────────────────────────┘
                     │ verify
┌────────────────────▼────────────────────────┐
│              Licensed Professional          │
│  - Holds license NFT in wallet              │
│  - Signs documents (consumes sig tokens)    │
│  - Renews validity tokens annually          │
│  - Pays dues via smart contract             │
└─────────────────────────────────────────────┘
```

## License

MIT — see [LICENSE](LICENSE).
