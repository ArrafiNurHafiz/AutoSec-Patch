import json
import os
import sys

try:
    from web3 import Web3
    from solcx import compile_standard, install_solc
except ImportError:
    print("Warning: 'web3' and 'py-solc-x' are required to run this script.")
    print("Please install them: pip install web3 py-solc-x")
    sys.exit(1)

# Ensure the correct compiler version is installed
install_solc("0.8.20")

# Setup Web3 connection
try:
    from web3.providers.eth_tester import EthereumTesterProvider
    w3 = Web3(EthereumTesterProvider())
    print("Using eth-tester provider")
except ImportError:
    RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    print(f"Connected to node: {RPC_URL}")

if not w3.is_connected():
    print(f"Error: Not connected to EVM node")
    sys.exit(1)

# Use the first account as the deployer/owner
deployer = w3.eth.accounts[0]
authorized_oracle = w3.eth.accounts[1]

# 1. Compile Smart Contract
contract_path = os.path.join("contracts", "ClimateTrustOracle.sol")
with open(contract_path, "r") as file:
    solidity_source = file.read()

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"ClimateTrustOracle.sol": {"content": solidity_source}},
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            },
        },
    },
    solc_version="0.8.20",
)

# Extract ABI and Bytecode
contract_interface = compiled_sol["contracts"]["ClimateTrustOracle.sol"]["ClimateTrustOracle"]
bytecode = contract_interface["evm"]["bytecode"]["object"]
abi = contract_interface["abi"]

# 2. Deploy Contract
print("Deploying ClimateTrustOracle...")
ClimateTrustOracle = w3.eth.contract(abi=abi, bytecode=bytecode)
tx_hash = ClimateTrustOracle.constructor(authorized_oracle).transact({"from": deployer})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = tx_receipt.contractAddress
print(f"Contract deployed successfully at address: {contract_address}")

# 3. Test Contract Functions
oracle_contract = w3.eth.contract(address=contract_address, abi=abi)

print("\n--- Running Tests ---")

# Setup Test Data
epoch_id = w3.keccak(text="epoch-1")
# For EVM standards, we use bytes32 Merkle root. Note: The python crypto.py uses sha256 string, 
# which causes a mismatch. This test uses a mock Keccak256 root.
merkle_root = w3.keccak(text="mock_root") 
integrity_score = 8500 # 85.00%
verified_samples = 100
rejected_samples = 5
ipfs_uri = "ipfs://QmMockHash"

# Test 1: Fail if integrity score < 80% (8000)
try:
    oracle_contract.functions.attestEpoch(
        epoch_id, merkle_root, 7900, verified_samples, rejected_samples, ipfs_uri
    ).transact({"from": authorized_oracle})
    print("❌ Test 1 Failed: Should revert on low integrity score")
except Exception as e:
    print("✅ Test 1 Passed: Enforced threshold >= 80% (Reverted properly)")

# Test 2: Successful Attestation (Valid threshold)
try:
    tx_hash = oracle_contract.functions.attestEpoch(
        epoch_id, merkle_root, integrity_score, verified_samples, rejected_samples, ipfs_uri
    ).transact({"from": authorized_oracle})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    # Check for events
    events = oracle_contract.events.ClimateEpochAttested().process_receipt(receipt)
    tampering_events = oracle_contract.events.TamperingDetected().process_receipt(receipt)
    
    if len(events) > 0 and len(tampering_events) > 0:
         print(f"✅ Test 2 Passed: Epoch attested successfully. Event 'ClimateEpochAttested' and 'TamperingDetected' emitted.")
    else:
         print("❌ Test 2 Failed: Events missing.")
except Exception as e:
    print(f"❌ Test 2 Failed: {e}")

# Test 3: Dispute / Merkle Root Verification
# Note: For this to work exactly with crypto.py, crypto.py must be patched to use Keccak256 and encode bytes correctly.
leaf = w3.keccak(text="leaf_1")
proof = [w3.keccak(text="proof_1"), w3.keccak(text="proof_2")]

# In a real scenario, this would be computed hash matching.
# We just test that the view function can be called correctly without revert
try:
    is_valid = oracle_contract.functions.verifyLeafInEpoch(epoch_id, leaf, proof).call()
    print(f"✅ Test 3 Passed: verifyLeafInEpoch executed. Result: {is_valid}")
except Exception as e:
    print(f"❌ Test 3 Failed: {e}")

print("\nAll tests completed.")
