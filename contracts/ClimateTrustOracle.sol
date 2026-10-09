// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @dev Minimal ERC20 implementation for Hackathon
 */
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract ERC20 is IERC20 {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;
    string public name;
    string public symbol;
    uint8 public decimals = 18;

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        uint256 currentAllowance = _allowances[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        unchecked {
            _approve(sender, msg.sender, currentAllowance - amount);
        }
        return true;
    }

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");
        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[sender] = senderBalance - amount;
        }
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");
        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}

/**
 * @title ClimateTrustOracle
 * @notice Decentralized, adversarial-resilient AI Oracle for climate and emissions telemetry.
 * @dev Records cryptographic Merkle roots of AI-verified climate epochs and verifies inclusion proofs.
 * Built for ClimateChain Global Hackathon 2026 (IEEE Blockchain - Track 4).
 */
contract ClimateTrustOracle is ERC20 {
    address public owner;
    address public authorizedOracle;
    uint16 public constant MIN_INTEGRITY_SCORE = 8000; // 80.00% minimum integrity requirement

    // Custom Errors for Gas Optimization
    error Unauthorized();
    error InvalidOracleAddress();
    error EpochAlreadyAttested();
    error IntegrityScoreTooLow();
    error InvalidMerkleRoot();
    error EpochNotFound();

    // Minimized struct to only store Merkle Root and IPFS CID (Gas optimization)
    struct EpochAttestation {
        bytes32 merkleRoot;
        bool exists;
        string ipfsMetadataUri;  // IPFS CID containing ZK-Proofs and full raw data
    }

    // Mapping from epochId (bytes32) to EpochAttestation
    mapping(bytes32 => EpochAttestation) public attestations;
    bytes32[] public epochHistory;

    // Events
    event ClimateEpochAttested(
        bytes32 indexed epochId,
        bytes32 indexed merkleRoot,
        uint16 integrityScore,
        uint32 verifiedSamples,
        uint32 rejectedSamples,
        address indexed oracle
    );

    event TamperingDetected(
        bytes32 indexed epochId,
        uint32 rejectedSamples,
        string explanation
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != authorizedOracle && msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address _authorizedOracle) ERC20("Verified Carbon Credit", "VCC") {
        owner = msg.sender;
        authorizedOracle = _authorizedOracle;
    }

    function setAuthorizedOracle(address _newOracle) external onlyOwner {
        if (_newOracle == address(0)) revert InvalidOracleAddress();
        authorizedOracle = _newOracle;
    }

    /**
     * @notice Submits a verified climate telemetry epoch to the blockchain.
     * @param epochId Unique identifier of the observation epoch
     * @param merkleRoot Cryptographic root of verified observation leaves
     * @param integrityScore AI-calculated integrity score (basis points: 0 - 10000)
     * @param verifiedSamples Count of clean verified telemetry points
     * @param rejectedSamples Count of adversarial tampered telemetry points quarantined
     * @param ipfsMetadataUri IPFS hash linking to full audit evidence, ZK-Proofs, and AI logs
     */
    function attestEpoch(
        bytes32 epochId,
        bytes32 merkleRoot,
        uint16 integrityScore,
        uint32 verifiedSamples,
        uint32 rejectedSamples,
        string calldata ipfsMetadataUri
    ) external onlyOracle {
        if (attestations[epochId].exists) revert EpochAlreadyAttested();
        if (integrityScore < MIN_INTEGRITY_SCORE) revert IntegrityScoreTooLow();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();

        // Only store the essentials to save gas
        attestations[epochId] = EpochAttestation({
            merkleRoot: merkleRoot,
            exists: true,
            ipfsMetadataUri: ipfsMetadataUri
        });

        epochHistory.push(epochId);

        // Mint VCC tokens: 1 VCC per verified sample
        if (verifiedSamples > 0) {
            uint256 mintAmount = uint256(verifiedSamples) * 10**decimals;
            _mint(msg.sender, mintAmount);
        }

        // Emitting the full data as events (cheaper than storage)
        emit ClimateEpochAttested(
            epochId,
            merkleRoot,
            integrityScore,
            verifiedSamples,
            rejectedSamples,
            msg.sender
        );

        if (rejectedSamples > 0) {
            emit TamperingDetected(
                epochId,
                rejectedSamples,
                "Adversarial data poisoning or spoofing quarantined by AI Engine"
            );
        }
    }

    /**
     * @notice Cryptographically verifies that a specific telemetry data point was part of an attested epoch.
     * @param epochId The attested epoch identifier
     * @param leaf The hash of the specific telemetry observation
     * @param proof The Merkle sibling proof path
     */
    function verifyLeafInEpoch(
        bytes32 epochId,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (!attestations[epochId].exists) revert EpochNotFound();
        bytes32 root = attestations[epochId].merkleRoot;

        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == root;
    }

    function getTotalEpochs() external view returns (uint256) {
        return epochHistory.length;
    }
}
