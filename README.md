# PQC Crypto Scanner

Post-Quantum Cryptography (PQC) Readiness Scanner for discovering domain assets and analyzing TLS configurations for quantum-vulnerable cryptography.

The scanner performs:

* **Asset discovery**
* **Service detection**
* **TLS cryptographic analysis**
* **PQC readiness evaluation**
* **CBOM generation**
* **PQC migration recommendations**

---

# Architecture

The scanner consists of multiple components:

* **Asset Discovery**
  Discovers subdomains and associated infrastructure.

* **Crypto Scanner**
  Analyzes TLS configuration of discovered assets.

* **OpenSSL PQC Provider**
  Enables hybrid post-quantum TLS support.

* **testssl.sh**
  Performs deep TLS security analysis.

* **liboqs**
  Open Quantum Safe cryptographic algorithms.

---

# Repository Structure

```
crypto-service
│
├── asset_discovery
│   ├── discovery
│   ├── scanner.py
│   └── resolver.py
│
├── crypto_scanner
│   ├── openssl_scanner.py
│   ├── nmap_scanner.py
│   ├── testssl_scanner.py
│   ├── parser.py
│   └── sanitizer.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

# Prerequisites

The scanner requires the following software installed:

### Python

```
Python >= 3.10
```

### System tools

Install:

```
nmap
openssl
git
curl
```

Ubuntu / Debian:

```
sudo apt update
sudo apt install nmap openssl git curl
```

MacOS:

```
brew install nmap openssl
```

---

# Clone the Repository

```
git clone https://github.com/<org>/crypto-service.git
cd crypto-service
```

---

# Create Python Virtual Environment

```
python3 -m venv venv
source venv/bin/activate
```

Windows:

```
venv\Scripts\activate
```

---

# Install Python Dependencies

```
pip install -r requirements.txt
```

---

# Clone Required External Tools

The scanner depends on several external cryptographic projects.

Clone them in the project root.

### liboqs

```
git clone https://github.com/open-quantum-safe/liboqs.git
```

### oqs-provider

```
git clone https://github.com/open-quantum-safe/oqs-provider.git
```

### testssl.sh

```
git clone https://github.com/drwetter/testssl.sh.git
```

After cloning, the folder structure should look like:

```
crypto-service
│
├── asset_discovery
├── crypto_scanner
│
├── liboqs
├── oqs-provider
├── testssl.sh
│
├── main.py
└── requirements.txt
```

---

# Running the Scanner API

Start the FastAPI service:

```
uvicorn main:app --reload --port 8000
```

Server will start at:

```
http://localhost:8000
```

Swagger API docs:

```
http://localhost:8000/docs
```

---

# Example API Usage

## Asset Discovery

```
POST /discover
```

Request:

```
{
  "domain": "github.com"
}
```

---

## Crypto Scan

```
POST /scan
```

Request:

```
{
  "assets": [
    {
      "host": "github.com",
      "ip": "20.207.73.82",
      "services": [
        {
          "port": 443,
          "protocol_name": "HTTPS"
        }
      ]
    }
  ],
  "scan_type": "soft"
}
```

Scan types:

```
soft  → OpenSSL + Nmap
deep  → OpenSSL + Nmap + testssl.sh
```

---

# Example Response

```
{
  "host": "github.com",
  "port": 443,
  "tls_version": "TLSv1.3",
  "cipher": "TLS_AES_128_GCM_SHA256",
  "key_exchange": "X25519",
  "signature_algorithm": "ecdsa-with-SHA256"
}
```

---

# Supported Cryptographic Analysis

The scanner detects:

* TLS versions
* Cipher suites
* Key exchange algorithms
* Signature algorithms
* Key sizes
* Certificate metadata
* Perfect Forward Secrecy
* PQC hybrid support
* Weak ciphers
* Known vulnerabilities

---

# Post-Quantum Cryptography Analysis

The scanner identifies:

### Classical algorithms vulnerable to quantum attacks

* RSA
* ECDSA
* ECDH
* X25519
* X448

### Recommended PQC algorithms

Key Exchange:

```
ML-KEM-768 (Kyber)
```

Digital Signatures:

```
CRYSTALS-Dilithium
Falcon
SPHINCS+
```

---

# Running in Development Mode

```
uvicorn main:app --reload
```

---

# Contributing

1. Fork repository
2. Create feature branch

```
git checkout -b feature/new-scanner
```

3. Commit changes

```
git commit -m "added new scanner module"
```

4. Push branch

```
git push origin feature/new-scanner
```

5. Create pull request.

---

# License

MIT License
