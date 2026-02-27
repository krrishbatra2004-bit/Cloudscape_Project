# 🕸️ Project Cloudscape 2026
**Enterprise Cloud Security Posture & Graph Correlation Fabric**

![Version](https://img.shields.io/badge/Version-2.0.0-00FF41)
![Status](https://img.shields.io/badge/Status-Production_Ready-blue)
![Architecture](https://img.shields.io/badge/Architecture-Multi--Tenant-orange)

## 📖 Executive Summary
Project Cloudscape is a distributed, multi-tenant Cloud Detection and Response (CDR) engine. It abandons traditional linear scanning in favor of a **Recursive Graph-Correlation Fabric**. By leveraging asynchronous execution and Neo4j Cypher mapping, Cloudscape ingests multiple isolated cloud environments (AWS/Azure) and autonomously discovers hidden, cross-account attack paths—specifically Identity Trusts and VPC Peering vulnerabilities.

## 🏗️ System Architecture & Topologies
* **The Logic Tier (D: Drive):** Houses the Asynchronous Orchestrator, the dynamic Discovery Engines (AWS/Azure), and the Trust Resolver.
* **The Forensic Tier (E: Drive):** A strictly namespaced, timestamped JSON data vault that caches immutable raw cloud state before graph ingestion.
* **The Mesh Infrastructure:** A multi-container Docker deployment simulating an enterprise hub-and-spoke cloud model via LocalStack and Azurite.

---

## ⚙️ Prerequisites & Installation

### 1. Core Dependencies
* **Python 3.10+**
* **Docker Desktop** (Engine v24.0+)
* **Git**

### 2. Environment Setup
Clone the repository and install the strict dependency matrix:
```bash
# Navigate to the Project Root (D: Drive)
cd D:\Cloudscape_Project

# Create and activate an isolated virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install Core Engines
pip install -r requirements.txt