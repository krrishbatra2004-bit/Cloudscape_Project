# CloudScape Nexus 5.2 Titan
**Sovereign-Forensic Multi-Cloud Intelligence Mesh**

![Version](https://img.shields.io/badge/Version-5.2.0-00FF41)
![Status](https://img.shields.io/badge/Status-Production_Ready-blue)
![Architecture](https://img.shields.io/badge/Architecture-Decoupled_Microservices-orange)

## Executive Summary
CloudSCAPE Titan is a multi-tenant Cloud Detection and Response (CDR) engine. It utilizes a **Recursive Graph-Correlation Fabric** backed by Neo4j to concurrently ingest multiple isolated cloud environments (AWS/Azure) directly or via emulators (LocalStack/Azurite), discovering hidden cross-account attack paths — specifically IAM Identity Trusts, VPC Peerings, and RBAC vulnerabilities.

## Project Structure

```
Cloudscape_Project/
├── backend/                        # Python Backend Engine
│   ├── main.py                     # Entry point (--api for REST server)
│   ├── config/                     # settings.yaml, tenants.yaml
│   ├── src/
│   │   ├── api/server.py           # aiohttp REST API (port 4000)
│   │   ├── core/                   # Orchestrator, RBAC, correlation
│   │   ├── discovery/              # AWS/Azure async extraction
│   │   ├── intelligence/           # Risk scoring, policy engine
│   │   ├── simulation/             # Mock data (state_factory, seeders)
│   │   └── utils/                  # DB tools, logger, config loader
│   ├── data/                       # Manifests & temp data
│   ├── forensics/                  # BSON ledger, logs, reports, snapshots
│   └── scripts/soft_reset.py
│
├── web_ui/                         # React Frontend (Vite)
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx / main.jsx      # App shell & routing
│       ├── index.css / App.css     # Global styles
│       ├── components/             # Graph3D, NodePanel, TopNav, SideNav
│       ├── pages/                  # Dashboard, InfrastructureMap, BlastRadius, etc.
│       ├── services/               # api.js (Axios), websocket.js
│       └── stores/                 # useStore.js (Zustand state)
│
├── scripts/                        # PowerShell launch & reset scripts
├── volume/                         # Docker volume mounts (Neo4j, Redis, etc.)
├── docker-compose.yml              # Container mesh definition
├── requirements.txt                # Python dependencies (min versions)
├── requirements_env.txt            # Frozen pip environment snapshot
└── run.txt                         # Full command reference manual
```

## Quick Start

### 1. Backend
```powershell
.\.venv\Scripts\activate.ps1
python backend/main.py --mode MOCK --api
```
The API server starts on **http://localhost:4000**.

### 2. Frontend
```powershell
cd web_ui
npm install          # first time only
npm run dev -- --port 5173
```
Open **http://localhost:5173** in your browser.

### 3. Docker Services (optional, for HYBRID/LIVE modes)
```powershell
docker compose up -d
```

## API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/graph` | GET | Full graph topology (nodes + edges) |
| `/api/assets` | GET | Asset inventory listing |
| `/api/blast-radius/:id` | GET | Blast radius from a specific node |

## Operational Modes
| Mode | Description |
|------|-------------|
| **MOCK** | Synthetic environment. No Docker required. Fast testing. |
| **LIVE** | Production extraction. Connects to real AWS/Azure. |
| **HYBRID** | Emulated deployment. Connects to LocalStack/Azurite. |

## Frontend Pages
| Page | Path | Description |
|------|------|-------------|
| Mission Dashboard | `/` | Security overview with metrics & charts |
| Multi-Cloud Topology | `/map` | Interactive 3D infrastructure graph |
| Blast Radius Engine | `/blast-radius` | APT kill chain impact analysis |
| Forensic Timeline | `/timeline` | State snapshot time-travel |
| Security Events | `/events` | Live alerts & drift detections |

---

*CloudSCAPE Titan: "Visibility is absolute. Trust is an edge."*