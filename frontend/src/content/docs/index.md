---
title: Introduction
description: Overview of UseCallManager security services
order: 1
category: getting-started
---

# UseCallManager Security Services

A modern implementation of security services for Cisco IP Phone systems, providing CAPF (Certificate Authority Proxy Function) and TVS (Trust Verification Service) capabilities.

## What is UseCallManager?

UseCallManager provides the essential security infrastructure that Cisco IP Phones need to establish secure communications:

- **CAPF (Certificate Authority Proxy Function)** - Issues and manages Locally Significant Certificates (LSCs) for phones
- **TVS (Trust Verification Service)** - Provides certificate validation and trust verification
- **Security Tools** - Generate ITL files and encrypt device configurations

## Key Features

### Certificate Management
- Issue LSCs to Cisco IP Phones via SCEP-like protocol
- Support for RSA (1024-2048 bit) and EC (secp256r1, secp384r1, secp521r1) keys
- Device lifecycle management (pending, issued, expired states)

### Trust Verification
- ITL (Initial Trust List) file generation with certificate chains
- Config file encryption for device-specific secure configuration delivery
- PKCS#1 v1.5 signatures with SHA-512 for integrity

### Modern Architecture
- FastAPI backend with SQLite/PostgreSQL database
- Astro frontend with React islands for interactive components
- Docker Compose deployment with Caddy reverse proxy
- RESTful APIs for integration with external configuration services

## Getting Started

1. [Installation & Setup](./installation) - Deploy the services
2. [API Reference](./api-overview) - Integrate with your configuration service
3. [Security Best Practices](./security-best-practices) - Secure your deployment

## Architecture

```
┌─────────────┐
│ Cisco Phone │ ──┬─→ CAPF Protocol (port 3804) ──→ Certificate Issuance
└─────────────┘   │
                  └─→ HTTPS API ──→ ITL Files, Config Encryption

┌──────────────────┐
│ Config Service   │ ──→ HTTPS API ──→ Generate ITL, Encrypt Configs
└──────────────────┘
```

The CAPF protocol handles certificate enrollment from phones, while the HTTPS APIs provide integration points for configuration services to generate ITL files and encrypt device-specific configurations.
