# KavachAI Crypto Service

Post-Quantum Cryptography (PQC) Readiness Scanner for discovering domain assets and analyzing TLS configurations for quantum-vulnerable cryptography.

---

## 🚀 Features

- **Asset Discovery**: Discovers subdomains and associated infrastructure.
- **Service Detection**: Identifies services running on discovered assets.
- **TLS Cryptographic Analysis**: Analyzes TLS configurations, including versions, cipher suites, key exchanges, and signature algorithms.
- **PQC Readiness Evaluation**: Checks for classical algorithms vulnerable to quantum attacks and identifies PQC hybrid support.
- **CBOM Generation**: Generates Cryptographic Bill of Materials.
- **PQC Migration Recommendations**: Suggests recommended PQC algorithms like ML-KEM-768 (Kyber) and CRYSTALS-Dilithium.

---

## 🔄 Architecture / Execution Flow

1. **Asset Discovery**: Discovers domain subdomains and their associated IP addresses.
2. **Crypto Scanner**: Receives discovered assets and queries their services.
   - For a **soft** scan, it uses Nmap and OpenSSL.
   - For a **deep** scan, it also incorporates `testssl.sh`.
3. **PQC Evaluation**: Utilizes OpenSSL PQC Provider and `liboqs` to determine if hybrid post-quantum TLS is supported on the target.
4. **Analysis & Recommendations**: Identifies algorithms vulnerable to quantum threats (e.g., RSA, ECDSA, X25519) and recommends post-quantum replacements.

---

## 🛠️ Technology Stack

### Backend
- **Language**: Python 3.12.8
- **Framework**: FastAPI
- **System Tools**: Nmap, OpenSSL, git, curl
- **Security Tools**: testssl.sh
- **Quantum-Safe Cryptography**: liboqs, oqs-provider

---

## 📂 Project Structure

```text
crypto-service/
├── asset_discovery/        # Discovery modules and resolver
├── crypto_scanner/         # Cryptographic scanners (OpenSSL, Nmap, testssl)
├── liboqs/                 # Open Quantum Safe cryptographic algorithms
├── oqs-provider/           # OpenSSL PQC Provider
├── testssl.sh/             # Deep TLS security analysis script
├── main.py                 # FastAPI Server entry point
└── requirements.txt        # Python dependencies
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python >= 3.12.8
- System Tools: `nmap`, `openssl`, `git`, `curl`
  - Ubuntu / Debian: `sudo apt install nmap openssl git curl`
  - MacOS: `brew install nmap openssl`

### Setup
1. Navigate to the crypto service folder:
   ```bash
   cd crypto-service
   ```
2. Create and activate a Python Virtual Environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Clone required external tools in the project root:
   ```bash
   git clone https://github.com/open-quantum-safe/liboqs.git
   git clone https://github.com/open-quantum-safe/oqs-provider.git
   git clone https://github.com/drwetter/testssl.sh.git
   ```

*(Note: There are no `.env` files required for this service configuration. Any system execution relies on paths set or tool binaries present.)*

---

## 🏃 Running the Application

### Start the Crypto Service
```bash
cd crypto-service
uvicorn main:app --reload --port 8000
```
The server will start at `http://localhost:8000`
Swagger API docs will be available at `http://localhost:8000/docs`

---

## 📊 API Endpoints

### Health Check
- `GET /health`: Returns the service status.

### Asset Discovery
- `POST /discover`: Discovers all public-facing assets for the given domain. This runs a full pipeline including passive subdomain discovery, active DNS brute force, DNS resolution, port scanning, and asset classification.

### Crypto Scan
- `POST /scan`: Scans selected assets for TLS and cryptographic configuration. Analyzes TLS versions, cipher suites, key exchange algorithms, and certificates to evaluate quantum readiness.

### CBOM Generation
- `POST /cbom`: Generates a standard Cryptographic Bill of Materials (CBOM) based on scan results. Collects assets, algorithms, keys, protocols, and certificates used across scanned targets.

---

## 👤 Team Information
This service is part of the KavachAI project.
Team: InfiniTech

---
