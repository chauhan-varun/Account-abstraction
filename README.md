# Account Abstraction (ERC-4337) Implementation

A minimal implementation of ERC-4337 Account Abstraction using Foundry, enabling users to interact with the Ethereum blockchain through smart contract wallets instead of traditional EOAs (Externally Owned Accounts).

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Smart Contracts](#smart-contracts)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Network Support](#network-support)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Author](#author)
- [License](#license)

## 🔍 Overview

This project implements a minimal ERC-4337 compliant smart contract account that allows users to:
- Execute transactions through a smart contract wallet
- Pay gas fees using the account's balance
- Validate operations using ECDSA signatures
- Interact with the EntryPoint contract for user operation bundling

ERC-4337 introduces Account Abstraction without requiring protocol changes, allowing for more flexible and secure user experiences on Ethereum.

## ✨ Features

- **ERC-4337 Compliance**: Full implementation of the IAccount interface
- **Single Owner Model**: Simple ownership structure with one authorized signer
- **Signature Validation**: ECDSA signature verification using Ethereum signed message format
- **Gas Prefunding**: Automatic gas payment to EntryPoint contract
- **Minimal Overhead**: Optimized for gas efficiency
- **Multi-Chain Support**: Compatible with Ethereum Mainnet, Sepolia, Arbitrum, and local networks
- **Comprehensive Testing**: Foundry-based test suite
- **Deployment Scripts**: Ready-to-use deployment and helper scripts

## 🏗️ Architecture

The project follows the ERC-4337 specification with the following flow:

1. **User Operation Creation**: Users create a `PackedUserOperation` containing transaction details
2. **Signature Generation**: The user signs the operation hash with their private key
3. **EntryPoint Submission**: The operation is submitted to the EntryPoint contract
4. **Validation**: EntryPoint calls `validateUserOp` on the MinimalAccount
5. **Execution**: If valid, the operation is executed through the `execute` function

```
User → PackedUserOperation → EntryPoint → MinimalAccount → Target Contract
                                    ↓
                              Signature Validation
                              Gas Prefunding
```

## 📝 Smart Contracts

### MinimalAccount.sol

The core smart contract implementing account abstraction functionality.

**Key Components:**

- **IAccount Interface**: Implements ERC-4337 account interface
- **Ownable**: Single owner access control using OpenZeppelin
- **Signature Validation**: ECDSA recovery and verification
- **Execute Function**: Allows owner to execute arbitrary transactions

**Functions:**

- `validateUserOp()`: Validates user operations and handles gas prefunding
- `execute()`: Executes transactions on behalf of the account
- `getEntryPoint()`: Returns the EntryPoint contract address

**Security Features:**

- Only EntryPoint can call `validateUserOp`
- Only owner can call `execute`
- Ethereum signed message hash format prevents signature reuse
- Silent failure on prefund transfer to prevent DoS attacks

### DeployMinimal.s.sol

Deployment script for the MinimalAccount contract.

- Deploys MinimalAccount with appropriate EntryPoint
- Transfers ownership to configured account
- Compatible with multiple networks via HelperConfig

### HelperConfig.s.sol

Network configuration helper providing:

- EntryPoint addresses for each network
- USDC/token addresses
- Account addresses for deployment
- Mock deployment for local testing (Anvil)

**Supported Networks:**
- Ethereum Mainnet (Chain ID: 1)
- Ethereum Sepolia (Chain ID: 11155111)
- Arbitrum Mainnet (Chain ID: 42161)
- zkSync Mainnet (Chain ID: 324)
- Local Anvil (Chain ID: 31337)

### SendPackedUserOp.sol

Script for creating and sending packed user operations (implementation pending).

## 🚀 Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Git
- An Ethereum wallet with test ETH (for testnet deployments)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Account-abstraction.git
cd Account-abstraction
```

2. Install dependencies:
```bash
forge install
```

3. Build the project:
```bash
forge build
```

## 📖 Usage

### Build

Compile the smart contracts:

```bash
forge build
```

### Test

Run the test suite:

```bash
forge test
```

Run tests with verbosity:

```bash
forge test -vvv
```

Run specific test:

```bash
forge test --match-test testOwnerCanExecuteCommands
```

### Format

Format your Solidity code:

```bash
forge fmt
```

### Gas Snapshots

Generate gas usage reports:

```bash
forge snapshot
```

### Local Deployment

1. Start a local Anvil node:
```bash
anvil
```

2. Deploy the contracts (in a new terminal):
```bash
forge script script/DeployMinimal.s.sol:DeployMinimal --rpc-url http://localhost:8545 --broadcast
```

### Testnet Deployment

Deploy to Sepolia testnet:

```bash
forge script script/DeployMinimal.s.sol:DeployMinimal --rpc-url $SEPOLIA_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify
```

**Environment Variables:**
- `SEPOLIA_RPC_URL`: Your Sepolia RPC endpoint
- `PRIVATE_KEY`: Your deployer wallet private key
- `ETHERSCAN_API_KEY`: For contract verification

### Mainnet Deployment

⚠️ **WARNING**: Ensure you've thoroughly tested on testnets before mainnet deployment.

```bash
forge script script/DeployMinimal.s.sol:DeployMinimal --rpc-url $MAINNET_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify
```

## 🌐 Network Support

| Network | Chain ID | EntryPoint | Supported |
|---------|----------|------------|-----------|
| Ethereum Mainnet | 1 | 0x0000000071727De22E5E9d8BAf0edAc6f37da032 | ✅ |
| Ethereum Sepolia | 11155111 | 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 | ✅ |
| Arbitrum Mainnet | 42161 | 0x0000000071727De22E5E9d8BAf0edAc6f37da032 | ✅ |
| zkSync Mainnet | 324 | Native AA Support | ✅ |
| Local Anvil | 31337 | Deployed Mock | ✅ |

## 📁 Project Structure

```
Account-abstraction/
├── src/
│   ├── ethereum/
│   │   └── MinimalAccount.sol          # Main account abstraction contract
│   └── zkSync/
│       └── MinimalAccount.sol          # zkSync version (pending)
├── script/
│   ├── DeployMinimal.s.sol            # Deployment script
│   ├── HelperConfig.s.sol             # Network configuration
│   └── SendPackedUserOp.sol           # User operation sender
├── test/
│   └── ethereum/
│       └── MinimumAccountTest.t.sol   # Test suite
├── lib/
│   ├── account-abstraction/           # ERC-4337 reference implementation
│   ├── forge-std/                     # Foundry standard library
│   ├── openzeppelin-contracts/        # OpenZeppelin contracts
│   ├── foundry-devops/                # Deployment tools
│   └── foundry-era-contracts/         # zkSync support
├── foundry.toml                       # Foundry configuration
└── README.md
```

## 🧪 Testing

The project includes comprehensive tests covering:

### Test Coverage

- **Owner Execution**: Verifies owner can execute commands
- **Access Control**: Ensures non-owners cannot execute commands
- **ERC20 Integration**: Tests minting tokens through the account

### Running Tests

```bash
# Run all tests
forge test

# Run with gas reporting
forge test --gas-report

# Run with coverage
forge coverage

# Run specific test file
forge test --match-path test/ethereum/MinimumAccountTest.t.sol
```

## 📦 Dependencies

- **Foundry**: Development framework
- **OpenZeppelin Contracts**: Security-audited contract libraries
  - Ownable: Access control
  - ECDSA: Signature verification
  - MessageHashUtils: Ethereum signed message handling
- **Account Abstraction**: ERC-4337 reference implementation
  - IAccount interface
  - PackedUserOperation
  - EntryPoint contract
- **Foundry DevOps**: Deployment utilities
- **Foundry Era Contracts**: zkSync compatibility

## 👨‍💻 Author

**Varun Chauhan**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Additional Resources

- [ERC-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337)
- [Foundry Book](https://book.getfoundry.sh/)
- [Account Abstraction Documentation](https://docs.alchemy.com/docs/account-abstraction-overview)
- [OpenZeppelin Documentation](https://docs.openzeppelin.com/)

## ⚠️ Security Considerations

This is a minimal implementation for educational and development purposes. Before using in production:

1. **Audit**: Get the contracts professionally audited
2. **Test Coverage**: Ensure comprehensive test coverage (>95%)
3. **Upgrade Path**: Consider implementing upgradeability if needed
4. **Multi-sig**: Consider multi-signature support for high-value accounts
5. **Rate Limiting**: Implement rate limiting for sensitive operations
6. **Gas Limits**: Carefully test gas limits for complex operations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Known Issues

- zkSync MinimalAccount implementation is pending
- SendPackedUserOp script needs completion for full user operation flow

---

Built with ❤️ using Foundry and ERC-4337
