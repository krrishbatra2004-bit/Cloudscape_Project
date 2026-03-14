# 🕸️ Project CloudScape 5.2 Titan
**Sovereign-Forensic Multi-Cloud Intelligence Mesh**

![Version](https://img.shields.io/badge/Version-5.2.0-00FF41)
![Status](https://img.shields.io/badge/Status-Production_Ready-blue)
![Architecture](https://img.shields.io/badge/Architecture-Decoupled_Microservices-orange)

## 📖 Executive Summary
Project CloudScape Titan is a highly distributed, multi-tenant Cloud Detection and Response (CDR) engine. Abandoning traditional linear scanning, it utilizes a **Recursive Graph-Correlation Fabric** backed by Neo4j. By concurrently ingesting multiple isolated cloud environments (AWS/Azure) directly or via emulators (LocalStack/Azurite), CloudScape intelligently discovers hidden, cross-account attack paths—specifically IAM Identity Trusts, VPC Peerings, and RBAC vulnerabilities.

## 🏗️ System Architecture & Topologies
CloudScape is designed with strict separation of concerns, heavily prioritizing decoupled execution and modular scale.

* **`frontend/`**: The modern User Interface layer (Managed by the Frontend/UI Team).
* **`backend/`**: The Sovereign-Forensic Core Engine. Contains:
  * **`src/core`**: Orchestration logic, unified configuration, and cross-project trust correlation.
  * **`src/discovery`**: AWS and Azure asynchronous extraction engine implementations.
  * **`src/intelligence`**: Graph mapping and algorithmic risk scoring capabilities.
  * **`src/simulation`**: Synthetic APT state generation and enterprise LocalStack seeder.
* **`scripts/`**: Advanced PowerShell orchestration tools for lifecycle, network diagnostics, and teardowns.
* **The Forensic Vault**: Namespaced JSON data outputs logged in `backend/forensics/` serving as chronological, immutable traces.
* **The Container Mesh**: A synchronized Docker deployment comprising `Neo4j`, `LocalStack`, `Redis`, and `MongoDB`.

---

## ⚙️ Prerequisites & Dependencies

### 1. Core Systems
* **Python 3.10+** (Recommend 3.12)
* **Docker Engine** (Compose V2+)
* **PowerShell 5.1+**

### 2. Environment Setup
Clone the repository and automatically spin up the ecosystem:

```powershell
# Navigate to the Project Root
cd D:\Cloudscape_Project

# Run the Master Launch Orchestrator (Creates .venv, installs dependencies, boots Docker, runs checks)
.\scripts\launch_nexus.ps1
```

## 🚀 Execution & Interaction

CloudScape provides comprehensive run commands for any granular task. It operates via the `.ps1` wrapper scripts or via direct Python entry points. **For a full, exhaustive list of every possible execution command, please read the `run.txt` file located in the root directory.**

### Quick-Start Guide
1. Activate virtual environment: `.\.venv\Scripts\activate.ps1`
2. Start the Graph & Emulators: `.\scripts\launch_nexus.ps1`
3. Optional Graph Seeding: `python backend/scripts/mesh_seeder.py`
4. Run standard forensic scan: `python backend/main.py --mode HYBRID`
5. Shutdown the ecosystem safely: `.\scripts\soft_reset.ps1`

## 🛡️ Operational Modes
The `main.py` pipeline utilizes specific extraction logic based on the mode provided:
- **`MOCK`**: Pure synthetic environment. Generates randomized local states without connecting to Docker. Fast unit testing.
- **`LIVE`**: Pure production extraction. Connects directly to real AWS/Azure via identities. Highly sensitive.
- **`HYBRID`**: Emulated local deployment. Connects to LocalStack/Azurite dockers. Perfect for testing exploits safely.

---

*Project Titan: "Visibility is absolute. Trust is an edge."*