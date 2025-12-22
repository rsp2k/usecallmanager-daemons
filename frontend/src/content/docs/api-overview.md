---
title: API Overview
description: RESTful APIs for device management and security operations
order: 3
category: api
---

# API Overview

UseCallManager provides RESTful APIs for managing devices, certificates, and security operations.

## Base URLs

When deployed behind Caddy reverse proxy:

- **CAPF API**: `https://{domain}/api/capf/api/v1/`
- **TVS API**: `https://{domain}/api/tvs/api/v1/`

Direct access (internal):
- **CAPF API**: `http://capf:8082/api/v1/`
- **TVS API**: `http://tvs:8081/api/v1/`

## Authentication

Currently, the APIs do not require authentication. **In production, you should secure these endpoints** using one of:

- Network isolation (internal-only access)
- API keys
- OAuth 2.0
- mTLS (mutual TLS)

## Content Types

All APIs use JSON:

```http
Content-Type: application/json
Accept: application/json
```

Binary endpoints (ITL files, certificates) return:
```http
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="..."
```

## Error Responses

Standard error format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

HTTP status codes:
- `200` - Success
- `201` - Created
- `204` - No Content (successful deletion)
- `400` - Bad Request (validation error)
- `404` - Not Found
- `500` - Internal Server Error

## API Categories

### Device Management APIs

Manage Cisco IP Phones and their certificates:

- `GET /devices` - List devices
- `POST /devices` - Add a device
- `GET /devices/{name}` - Get device details
- `PATCH /devices/{name}/operation` - Update operation mode
- `DELETE /devices/{name}` - Remove device
- `GET /devices/{name}/certificate` - Download device certificate

[Full Device API Reference →](./api-devices)

### Security APIs

Generate ITL files and encrypt configurations:

- `POST /itl-file` - Generate ITLFile.tlv
- `POST /encrypt-config` - Encrypt device configuration

[Full Security API Reference →](./api-security)

### System APIs

Health checks and statistics:

- `GET /health` - Service health status
- `GET /stats` - Service statistics
- `GET /issuer-certificate` - Get issuer certificate info

## Quick Examples

### Check Service Health

```bash
curl https://{domain}/api/capf/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "version": "4.0.0",
  "database": "connected"
}
```

### List Devices

```bash
curl https://{domain}/api/capf/api/v1/devices?limit=10
```

Response:
```json
{
  "devices": [
    {
      "name": "SEP001122334455",
      "operation": "install",
      "key_type": "RSA",
      "key_size": 2048,
      "status": "issued",
      "created_at": "2025-12-22T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

### Generate ITL File

```bash
curl -X POST https://{domain}/api/capf/api/v1/itl-file \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": [{
      "pem": "-----BEGIN CERTIFICATE-----\n...",
      "roles": ["CCM", "TFTP"]
    }],
    "signer": {
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
      "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
    }
  }' \
  -o ITLFile.tlv
```

## Integration Examples

### Configuration Service Integration

Example workflow for a configuration service that needs to generate ITL files and encrypted configs:

```python
import requests

API_BASE = "https://usecallmanager.example.com/api/capf/api/v1"

# 1. Generate ITL file
itl_response = requests.post(
    f"{API_BASE}/itl-file",
    json={
        "certificates": [
            {"pem": cucm_cert, "roles": ["CCM", "TFTP"]},
            {"pem": tftp_cert, "roles": ["TFTP"]},
        ],
        "signer": {
            "certificate_pem": signer_cert,
            "private_key_pem": signer_key,
        },
    },
)
itl_data = itl_response.content  # Binary ITLFile.tlv

# 2. Encrypt device config
config_response = requests.post(
    f"{API_BASE}/encrypt-config",
    json={
        "device_name": "SEP001122334455",
        "config_xml": "<device>...</device>",
    },
)
encrypted_config = config_response.content  # Binary .enc.sgn

# 3. Serve files to phone
# - ITLFile.tlv → https://tftp.example.com/ITLFile.tlv
# - Encrypted config → https://tftp.example.com/SEP001122334455.cnf.xml.enc.sgn
```

## Rate Limiting

No rate limiting is currently implemented. For production deployments, consider adding rate limiting at the reverse proxy level (Caddy, nginx) or using a dedicated API gateway.

## Versioning

APIs are versioned via URL path (`/api/v1/`). Breaking changes will increment the version number.

## OpenAPI Documentation

Interactive API documentation is available at:

- CAPF: `https://{domain}/api/capf/docs`
- TVS: `https://{domain}/api/tvs/docs`

Powered by FastAPI's automatic OpenAPI generation.
