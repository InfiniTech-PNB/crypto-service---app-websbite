# KavachAI Crypto Service

> **Post-Quantum Cryptography (PQC) Readiness Scanner**
> Built for PNB Hackathon 2026 by **InfiniTech**

This microservice handles the heavy lifting of discovering domain assets and analyzing their TLS configurations for quantum-vulnerable cryptography using tools like Nmap, OpenSSL, and testssl.sh.

---

## 📌 Table of Contents

- [Features](#-features)
- [Architecture & Flow](#-architecture--flow)
- [Tech Stack](#️-tech-stack)
- [Project Structure](#-project-structure)
- [Local Setup (First Time)](#-local-setup-first-time)
- [Running the Server](#-running-the-server)
- [API Endpoints](#-api-endpoints)
- [Team](#-team)

---

## 🚀 Features

| Feature | Description |
|---|---|
| **Asset Discovery** | Discovers subdomains and associated infrastructure |
| **Service Detection** | Identifies services running on discovered assets |
| **TLS Cryptographic Analysis** | Analyzes TLS configurations, including versions, cipher suites, key exchanges, and signature algorithms |
| **PQC Readiness Evaluation** | Checks for classical algorithms vulnerable to quantum attacks and identifies PQC hybrid support |
| **CBOM Generation** | Generates Cryptographic Bill of Materials |
| **PQC Migration Recommendations** | Suggests recommended PQC algorithms like ML-KEM-768 (Kyber) and CRYSTALS-Dilithium |

---

## 🔄 Architecture & Flow

1. **Asset Discovery**: Discovers domain subdomains and their associated IP addresses.
2. **Crypto Scanner**: Receives discovered assets and queries their services.
   - For a **soft** scan, it uses Nmap and OpenSSL.
   - For a **deep** scan, it also incorporates `testssl.sh`.
3. **PQC Evaluation**: Utilizes OpenSSL PQC Provider and `liboqs` to determine if hybrid post-quantum TLS is supported on the target.
4. **Analysis & Recommendations**: Identifies algorithms vulnerable to quantum threats (e.g., RSA, ECDSA, X25519) and recommends post-quantum replacements.

---

## 🛠️ Tech Stack

### Backend & Framework
| Technology | Version | Purpose |
|---|---|---|
| **Python** | 3.12.8 | Primary language |
| **FastAPI** | — | Web framework for the API |

### System & Security Tools
| Technology | Purpose |
|---|---|
| **Nmap** | Port scanning and service detection |
| **OpenSSL** | TLS handshakes and certificate extraction |
| **testssl.sh** | Deep TLS security analysis script |
| **liboqs** | Open Quantum Safe cryptographic algorithms |
| **oqs-provider**| OpenSSL PQC Provider |

---

## 📂 Project Structure

```text
crypto-service/
│
├── asset_discovery/        # Discovery modules and resolver
├── crypto_scanner/         # Cryptographic scanners (OpenSSL, Nmap, testssl)
├── liboqs/                 # Open Quantum Safe cryptographic algorithms
├── oqs-provider/           # OpenSSL PQC Provider
├── testssl.sh/             # Deep TLS security analysis script
├── main.py                 # FastAPI Server entry point
└── requirements.txt        # Python dependencies
```

---

## ⚙️ Local Setup (First Time)

### OS Requirements & Windows Support

> ⚠️ **Important for Windows Users**: Because this service heavily relies on `testssl.sh` (a bash script) and requires compiling C libraries (`liboqs` and `oqs-provider`), **native Windows execution is not recommended**. 
> 
> **How to run on Windows:**
> Use **WSL (Windows Subsystem for Linux)**. We highly recommend installing **Ubuntu on WSL2** and running all commands below inside the WSL Ubuntu terminal. Docker is also a great alternative.

### Prerequisites (Linux / WSL / macOS)
- Python >= 3.12.8
- System Tools: `nmap`, `openssl`, `git`, `curl`
  - Ubuntu / Debian (or WSL): `sudo apt update && sudo apt install nmap openssl git curl build-essential cmake`
  - macOS: `brew install nmap openssl cmake`

### Setup

1. **Clone & Navigate**
   ```bash
   git clone <repository-url>
   cd crypto-service
   ```

2. **Clone Required External Tools**
   These tools must be cloned into the project root:
   ```bash
   git clone https://github.com/open-quantum-safe/liboqs.git
   git clone https://github.com/open-quantum-safe/oqs-provider.git
   git clone https://github.com/drwetter/testssl.sh.git
   ```

3. **Create and activate a Python Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

*(Note: There are no `.env` files required for this service. The system relies on standard tool binaries being available in your PATH.)*

---

## 🏃 Running the Server

### Start the FastAPI Service
```bash
cd crypto-service
uvicorn main:app --reload --port 8000
```

- The server runs at `http://localhost:8000`
- Interactive Swagger API docs are available at `http://localhost:8000/docs`

---

## 📊 API Endpoints

### Health Check
- `GET /health`: Returns the service status to verify the API is running.

### Asset Discovery
- `POST /discover`: Discovers all public-facing assets for the given domain. This runs a full pipeline including passive subdomain discovery, active DNS brute force, DNS resolution, port scanning, and asset classification.

### Crypto Scan
- `POST /scan`: Scans selected assets for TLS and cryptographic configuration. Analyzes TLS versions, cipher suites, key exchange algorithms, and certificates to evaluate quantum readiness.

### CBOM Generation
- `POST /cbom`: Generates a standard Cryptographic Bill of Materials (CBOM) based on scan results. Collects assets, algorithms, keys, protocols, and certificates used across scanned targets.

---

## 👤 Team

- **Author:** InfiniTech
- **Event:** PNB Hackathon 2026
