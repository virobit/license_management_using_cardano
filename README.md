# Cardano License

Professional credential verification on the Cardano blockchain using NFT-based licenses, signature tokens, validity tokens, and Plutus V2 smart contracts.

## Overview

This system allows licensing authorities to issue, manage, and verify professional credentials entirely on-chain:

- **License NFTs** (CIP-25/CIP-68) — One NFT per professional license, carrying metadata (licensee, authority, jurisdiction, dates)
- **Signature Tokens** — Fungible tokens consumed when a licensee signs a document, creating an on-chain audit trail
- **Validity Tokens** — Time-bounded tokens representing current license validity, renewable by the authority
- **Work Products** — Multi-signer documents with wallet-based signature collection and atomic finalization
- **Dues Enforcement** — Plutus V2 contract for annual dues payment tracking and license validity gating
- **SignatureCollectionValidator** — Authority-gated Plutus V2 contract managing concurrent multi-party signing via independent UTxOs

See [`docs/`](docs/) for the full research paper (v3.1) and 128-page study guide.

## Prerequisites

- **Python 3.10+** (Ubuntu 24.04 ships 3.12)
- **Git**
- A free [Blockfrost](https://blockfrost.io) API key (preprod network recommended)
- Test ADA from the [Cardano faucet](https://docs.cardano.org/cardano-testnets/tools/faucet/)

## Installation (Linux / Ubuntu)

### 1. System packages

Ubuntu 24.04+ enforces PEP 668, which blocks global pip installs. You **must** use a virtual environment.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
```

### 2. Clone the repository

```bash
git clone https://github.com/virobit/license_management_using_cardano.git
cd license_management_using_cardano
```

### 3. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install the package

```bash
pip install -e .
```

Or with dev/test dependencies:

```bash
pip install -e ".[dev]"
```

### 5. Verify installation

```bash
python -c "import cardano_license; print(cardano_license.__version__)"
```

## Configuration

### 1. Get a Blockfrost API key

1. Sign up at [blockfrost.io](https://blockfrost.io) (free tier is sufficient)
2. Create a project and select **Preprod** network
3. Copy your Project ID (starts with `preprod...`)

### 2. Set environment variables

```bash
cp .env.example .env
nano .env    # or your preferred editor
```

Fill in your values:

```
BLOCKFROST_PROJECT_ID=preprodYourKeyHere
CARDANO_NETWORK=preprod
```

Then load them:

```bash
source .env
```

### Environment variable reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `BLOCKFROST_PROJECT_ID` | *(required for chain ops)* | Blockfrost API key |
| `CARDANO_NETWORK` | `testnet` | Network: `testnet`, `mainnet`, `preprod`, `preview` |
| `CARDANO_LICENSE_DIR` | `~/.cardano-license/` | Base directory for data |
| `CARDANO_LICENSE_DB` | `{DIR}/license.db` | SQLite database path |
| `CARDANO_LICENSE_PASSWORD` | *(interactive prompt)* | Encryption password for wallet keys |

## Quick Start

### Step 1: Create wallets and initialize the database

```bash
cd examples
python quickstart.py
```

This creates an authority wallet and a licensee wallet. Save the printed addresses and mnemonics securely.

### Step 2: Fund the authority wallet

Copy the authority wallet address from the output above and request test ADA:

- [Cardano Testnet Faucet](https://docs.cardano.org/cardano-testnets/tools/faucet/) — paste the `addr_test1...` address
- You need at least 5 tADA for minting operations

Verify funding:

```bash
cardano-license balance demo_authority
```

### Step 3: Mint a license and sign a document

Once funded, run the quickstart again — it will proceed past wallet creation and mint a license NFT, signature tokens, a validity token, and sign a test document:

```bash
python quickstart.py
```

### Using the Python API directly

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

## CLI

```bash
cardano-license status            # Show network config and wallet counts
cardano-license generate authority --label my_authority
cardano-license generate licensee --label jane_doe
cardano-license list              # List all wallets
cardano-license balance my_authority
cardano-license licenses          # List all license NFTs
cardano-license work-products     # List work products
```

## Testing

```bash
# Unit tests (no Blockfrost needed)
pytest tests/test_license.py tests/test_contracts.py tests/test_tx_utils.py -v

# Integration tests (requires funded testnet wallet + Blockfrost key)
export BLOCKFROST_PROJECT_ID=preprodXXXXXX
pytest tests/test_testnet.py -v -m integration --timeout=300
```

## Architecture

```
┌─────────────────────────────────────────────┐
│              Licensing Authority             │
│  - Issues License NFTs (CIP-25/CIP-68)      │
│  - Mints signature & validity tokens        │
│  - Deploys Plutus V2 validators             │
└────────────────────┬────────────────────────┘
                     │ on-chain
┌────────────────────▼────────────────────────┐
│              Cardano Blockchain              │
│  - ScriptPubkey minting policies            │
│  - CIP-68 datum metadata (mutable status)   │
│  - SignatureCollectionValidator (Plutus V2)  │
│  - DuesEnforcementContract (Plutus V2)      │
│  - Time-bounded validity tokens             │
└────────────────────┬────────────────────────┘
                     │ verify
┌────────────────────▼────────────────────────┐
│              Licensed Professional          │
│  - Holds license NFT in CIP-30 wallet      │
│  - Signs documents (deposits sig tokens)    │
│  - Renews validity tokens annually          │
│  - Pays dues via smart contract             │
└─────────────────────────────────────────────┘
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `pip: command not found` | Activate your venv: `source .venv/bin/activate` |
| `externally-managed-environment` | Use a venv (see Installation step 3) — do **not** use `--break-system-packages` |
| `python3-venv` not found by apt | Run `sudo apt update` first — your apt sources may need refreshing |
| `Blockfrost configured: False` | Set `BLOCKFROST_PROJECT_ID` in `.env` and run `source .env` |
| `Insufficient funds` | Fund the authority wallet via the [faucet](https://docs.cardano.org/cardano-testnets/tools/faucet/) (need ~5 tADA) |

## Documentation

- **[Research Paper (v3.1)](docs/Blockchain_Credential_Verification_Cardano_Architecture_v3.1.pdf)** — Full system architecture and formal design
- **[Study Guide](docs/Cardano_Credential_Verification_Study_Guide.pdf)** — 128-page companion covering blockchain fundamentals, eUTxO, smart contracts, privacy, and legal compliance

## License

MIT — see [LICENSE](LICENSE).
