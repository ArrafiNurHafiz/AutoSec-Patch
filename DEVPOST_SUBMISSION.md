# ClimateTrust AI Oracle - Devpost Submission

## Inspiration
In global carbon markets and ESG auditing, environmental telemetry dictates billions of dollars. But blockchains face a critical vulnerability: **"Garbage In, Garbage On-Chain."** If industrial emitters manipulate their local emissions sensors to evade carbon taxes, the blockchain immutably seals fraudulent data. We built ClimateTrust to bridge the gap between AI forensics and blockchain consensus, ensuring that only mathematically and physically verified environmental telemetry enters smart contracts.

## What it does
ClimateTrust is a 100% software, cloud-native **AI Verification Mesh & Cryptographic Oracle**. It ingests public climate/GHG APIs, quarantines adversarial telemetry manipulations via multi-agent physics-informed heuristics, and attests verified epochs directly into EVM smart contracts using Merkle proofs.

## How we built it
- **Ingestion & AI Verification:** Python-based engine that runs three multi-agent checks: Atmospheric Physics Verifier (detects stoichiometric decoupling), Spatial-Temporal Anomaly Detector (flags divergence from regional neighbors), and Entropy & Replay Detector (spots synthetic flatlines).
- **IPFS & Zero-Knowledge Proofs:** To scale on-chain storage and protect proprietary sensor coordinates, we offload raw telemetry data to IPFS. Simultaneously, we generate ZK-Proofs to mathematically guarantee data integrity without leaking sensitive information.
- **Smart Contract & ERC-20 Tokenomics:** Solidity contract (`ClimateTrustOracle.sol`) enforces an 80% consensus integrity threshold. For compliant epochs, it only stores the IPFS CID and Merkle Root, and immediately mints "Verified Carbon Credit" (ERC-20) tokens to incentivize honest reporting.
- **WebSocket Dashboard:** An interactive HTML cockpit providing real-time observation grids, AI threat forensic logs, ZK-Proof artifacts, and live-streaming on-chain token minting events via WebSockets.

## Challenges we ran into
Ensuring scalable on-chain verification for massive climate data streams was a major hurdle. We solved this by using Merkle Trees to compress data into a single 32-byte root hash per epoch, keeping gas costs minimal and constant.

## Accomplishments that we're proud of
We successfully integrated a fully operational pipeline with 7/7 passing unit tests, demonstrating that multi-agent heuristics can autonomously catch sophisticated data spoofing and prevent fraudulent data from tainting the ledger.

## What we learned
We learned the profound importance of bridging domain-specific physics (like atmospheric combustion markers) with Web3 technologies to create truly trustless environmental monitoring systems.

## What's next for ClimateTrust AI Oracle
- Expanding the AI Verification Mesh to ingest and cross-reference satellite imagery.
- Deploying the Oracle nodes across decentralized networks (e.g., Chainlink DONs) for horizontal scaling.
- Piloting the platform with real-world ESG auditors in preparation for UN COP 31 compliance mandates.
