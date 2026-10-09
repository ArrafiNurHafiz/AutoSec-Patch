# ClimateTrust AI Oracle — Demo Video Pitch Script (3–5 Minutes)

> **Submission for ClimateChain Global Hackathon 2026**  
> **Track:** Track 4 — Climate Data & Environmental Monitoring (IEEE Blockchain Technical Group)  
> **Presenter:** Arrafi Nur Hafiz & Team

---

## ⏱️ Video Timeline & Scene Breakdown

### 🎬 Scene 1: The Problem & Context (0:00 – 0:45)
* **Visual:** Slide showcasing the UN COP 31 logo, carbon trading graphs, and the headline: *"Garbage In, Garbage On-Chain: The Climate Oracle Dilemma"*.
* **Speaker:**
  > "Hello judges and fellow climate innovators. In global carbon markets, ESG auditing, and UN climate pacts, environmental telemetry dictates billions of dollars in tax liabilities and carbon credits.
  > But blockchains face a fundamental vulnerability: **Garbage In, Garbage On-Chain**.
  > If industrial emitters manipulate their local emissions sensors to evade carbon taxes, or if API feeds suffer from cyber tampering and sensor spoofing, the blockchain immutably seals fraudulent data.
  > Today, we present **ClimateTrust AI Oracle** — an adversarial-resilient AI verification and cryptographic attestation engine designed to guarantee integrity for decentralized climate data."

---

### 🎬 Scene 2: Solution Architecture (0:45 – 1:30)
* **Visual:** System architecture diagram showing Data Ingestion → AI Verification Mesh → IPFS Storage / ZK-Proofs → Solidity Smart Contract (ERC-20 Minting) → WebSocket Dashboard.
* **Speaker:**
  > "ClimateTrust is a 100% software, cloud-native architecture.
  > Instead of trusting raw API payloads, our **AI Verification Mesh** runs three multi-agent heuristics to detect anomalies like stoichiometric decoupling and spatial spoofing.
  > Verified data is packaged with **Zero-Knowledge Proofs (ZK-Proofs)**—proving data integrity without leaking sensitive sensor coordinates—and stored immutably on **IPFS**.
  > Finally, our EVM smart contract verifies the Merkle Root and IPFS CID. If the integrity threshold exceeds 80%, the contract automatically mints **ERC-20 Verified Carbon Credits**, directly linking physical truth to decentralized finance."

---

### 🎬 Scene 3: Live Terminal & Pipeline Execution (1:30 – 2:30)
* **Visual:** Screen recording running the CLI: `python3 -m climatetrust.cli run --samples 5 --output cockpit_climate.html`.
* **Speaker:**
  > "Let's see ClimateTrust in action.
  > We trigger the verification pipeline across 15 observation nodes.
  > Notice the CLI terminal: The AI engine processes the stream and quarantines 3 distinct adversarial attacks.
  > The system calculates an 80.00% Integrity Score. It immediately generates the ZK-Proofs and uploads the raw epoch data to IPFS.
  > Then, it executes an on-chain transaction to `ClimateTrustOracle.sol`, which validates the IPFS CID and successfully mints the ERC-20 carbon tokens to the verifiers."

---

### 🎬 Scene 4: The Interactive WebSocket Cockpit (2:30 – 3:30)
* **Visual:** Browser showing `cockpit_climate.html` in dark mode. Zooming into the WebSocket live-stream, IPFS CIDs, and ZK-Proof artifacts.
* **Speaker:**
  > "Opening our interactive Cockpit Dashboard, powered by real-time WebSockets:
  > In the top panel, we see live high-level telemetry: 15 total observations, 12 verified clean points, and 3 quarantined threats.
  > The AI Adversarial Findings table clearly flags an under-reporting attack where PM2.5 decoupled from CO2, and a spatial spoofing attempt.
  > In the bottom panel, auditors can inspect the IPFS CID, the generated ZK-Proof artifacts, and the real-time ERC-20 token minting event streaming directly from the blockchain."

---

### 🎬 Scene 5: UN COP 31 Impact, Scalability & Conclusion (3:30 – 4:15)
* **Visual:** Summary slide highlighting UN COP 31 goals, Technical Innovation, and Scalability.
* **Speaker:**
  > "Why does this matter?
  > The success of the UN COP 31 agenda relies entirely on data we can trust. By mathematically verifying environmental telemetry and preventing data manipulation at the source, ClimateTrust provides a real-world foundation for:
  > - Verifiable compliance with National Emission Pledges (NDCs).
  > - Transparent, fraud-free carbon credit issuance.
  > 
  > **Scalability?** Because we compress massive data streams into a single O(log N) Merkle Root per epoch, on-chain gas costs remain minimal regardless of how many sensors we ingest. It's a 100% software, cloud-native architecture ready to scale globally.
  >
  > We've brought true technical innovation to the Oracle problem. ClimateTrust is open-source, fully tested, and ready for deployment. Thank you!"
