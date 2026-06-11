# Random-Username-and-Password-Generator
# 🔐 CryptoGen - Cryptographically Secure Credential Generator

**Enterprise-grade password and username generator with zero-knowledge architecture, production-ready security, and full offline PWA support.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-000000?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?logo=docker)](https://www.docker.com)
[![Tests](https://img.shields.io/badge/Tests-30%2B-passing-brightgreen)](tests/test_crypto.py)

## ✨ Overview

**CryptoGen** is a modern, security-first credential generator that combines cryptographically secure randomness with advanced password strength analysis, zero-knowledge architecture, and enterprise features.

Built with defense-in-depth principles, it never exposes raw passwords in API responses, uses one-time retrieval tokens, and provides full offline capability through a Progressive Web App (PWA).

### Why CryptoGen?

- **True Cryptographic Security**: Powered by Python's `secrets` module (OS CSPRNG) + additional entropy mixing
- **Zero-Knowledge Design**: Passwords are never returned directly in responses
- **Production Ready**: Docker + Nginx stack with hardened security headers
- **Extensible**: Plugin architecture for custom password strategies
- **Auditable**: Comprehensive event-driven audit logging
- **Offline First**: Full client-side generation using Web Crypto API

## 🚀 Key Features

### Core Security
- **AES-256-GCM** authenticated encryption
- **PBKDF2** & **Scrypt** key derivation
- **SHA3-512** + **HMAC-SHA256** integrity verification
- **One-time retrieval tokens** (30-second TTL, single use)
- **CSRF Protection** (double-submit cookie pattern)
- **Rate Limiting** (server + Nginx layer)

### Advanced Enhancements
- **Plugin Architecture** — Extensible password strategies (`plugins.py`)
- **Event-Driven Audit System** — Security logging without sensitive data (`audit.py`)
- **Secure Database** — SQLAlchemy ORM with soft-delete (`database.py`)
- **Comprehensive Test Suite** — 30+ security-focused tests
- **Offline PWA** — Full functionality via Service Worker + WebCrypto
- **Production Deployment** — Docker + Nginx reverse proxy

### Password Generation Strategies
- `random` — Pure cryptographic randomness
- `passphrase` — Diceware-style memorable passphrases
- `pattern` — Structured pattern-based passwords
- `hybrid` — Combination of words + randomness
- **Memorable** & **PIN** strategies via plugin system

##  Tech Stack

**Backend:**
- Python 3.11+
- Flask
- cryptography
- SQLAlchemy
- Gunicorn

**Frontend:**
- HTML5 + Tailwind-inspired CSS
- Vanilla JavaScript + Web Crypto API
- Service Worker (PWA)

**Deployment:**
- Docker + docker-compose
- Nginx (reverse proxy + security hardening)

## 📸 Screenshots

<img width="1913" height="902" alt="image" src="https://github.com/user-attachments/assets/d0da337e-ad97-4a28-87b2-70b9830100f8" />
<img width="1917" height="903" alt="image" src="https://github.com/user-attachments/assets/32aacd17-9f8c-45a6-b866-018dcd447be1" />


- Modern dark-themed UI with matrix rain background
- Real-time strength meter with entropy visualization
- Batch generation table
- Cryptographic details panel

# Project Structure
Bashcryptogen/

├── server.py                 
├── plugins.py                
├── audit.py                  
├── database.py               
├── requirements.txt          
├── templates/
│   └── index.html            
├── static/
│   └── sw.js                 
├── tests/
│   ├── __init__.py
│   └── test_crypto.py        
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── manifest.json            
├── ENHANCEMENTS.md          
├── SETUP.md                 
├── QUICK_REFERENCE.md       
└── COMPLETION.md            

## 🏁 Quick Start

### Using Docker (Recommended for Production)


# Clone the repository
git clone <your-repo-url>
cd cryptogen

# Start full stack (Flask + Nginx)
docker-compose up -d

# Access at https://localhost (self-signed cert warning expected in dev)

Local Development :-

# 1. Clone and enter directory
git clone <your-repo-url>
cd cryptogen

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run development server
python server.py

API Documentation :-

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/9560a5e6-95f8-48fe-9e8f-334e966c3a3a" />

Security Features :-

Never stores plaintext passwords
One-time use tokens with automatic destruction
CSRF protection on all mutating endpoints
Input validation with strict whitelisting
Sliding window rate limiting
Security headers via Nginx (CSP, HSTS, X-Frame-Options, etc.)
Audit logging with anomaly detection
Non-root Docker container with read-only filesystem

Testing :-

# Run full test suite
pytest tests/test_crypto.py -v

# With coverage report
pytest tests/test_crypto.py -v --cov=server --cov-report=html

# Specific test classes
pytest tests/test_crypto.py::TestCryptoVault -v

Production Deployment :-

# docker-compose up -d --build

# View logs
docker-compose logs -f cryptogen

# Scale workers
docker-compose up -d --scale cryptogen=4

# License :- 

This project is licensed under the MIT License - see the LICENSE file for details.
