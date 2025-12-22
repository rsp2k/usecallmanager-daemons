---
title: Security API Reference
description: ITL generation and config encryption endpoints
order: 5
category: api
---

# Security API Reference

Security APIs for generating ITL (Initial Trust List) files and encrypting device configurations.

## Generate ITL File

Generate an ITLFile.tlv containing trusted certificates for Cisco IP Phones.

**Endpoint**: `POST /api/v1/itl-file`

### Request Body

```json
{
  "certificates": [
    {
      "pem": "-----BEGIN CERTIFICATE-----\n...",
      "roles": ["CCM", "TFTP"]
    }
  ],
  "signer": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
  }
}
```

#### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificates` | Array | Yes | List of certificates to include in ITL |
| `certificates[].pem` | String | Yes | PEM-encoded X.509 certificate |
| `certificates[].roles` | Array | Yes | Certificate roles (see below) |
| `signer.certificate_pem` | String | Yes | Signer certificate (PEM) |
| `signer.private_key_pem` | String | Yes | Signer private key (PEM) |

#### Certificate Roles

| Role | Code | Description |
|------|------|-------------|
| `SAST` | 0 | System Administrator Security Token (max 2) |
| `CCM` | 1 | Cisco CallManager |
| `CCM+TFTP` | 2 | CallManager with TFTP |
| `TFTP` | 3 | TFTP server only |
| `CAPF` | 4 | Certificate Authority Proxy Function |
| `APP-SERVER` | 7 | Application server |
| `TVS` | 21 | Trust Verification Service |

### Response

**Content-Type**: `application/octet-stream`
**Content-Disposition**: `attachment; filename=ITLFile.tlv`

Binary ITL file in TLV (Tag-Length-Value) format.

### Example

```bash
curl -X POST https://example.com/api/capf/api/v1/itl-file \
  -H "Content-Type: application/json" \
  -d @itl-request.json \
  -o ITLFile.tlv
```

### Validation Rules

- Maximum 2 SAST certificates per ITL file
- RSA keys must be ≤ 2048 bits (phone hardware limitation)
- EC keys must use supported curves: secp256r1, secp384r1, secp521r1
- All certificates must be valid X.509 format
- Signer private key must match signer certificate

### ITL File Format

The generated ITL file uses TLV encoding:

```
Header:
  - VERSION (0x01): 2 bytes = 0x0101
  - LENGTH (0x02): 4 bytes = total file length
  - SIGNER (0x03): Signer information
  - HASH_ALGORITHM (0x08): 1 byte = 0x02 (SHA-512)
  - SIGNATURE (0x0C): PKCS#1 v1.5 SHA-512 signature

Records (per certificate):
  - CERTIFICATE (0x09): DER-encoded X.509
  - PUBLIC_KEY (0x07): SubjectPublicKeyInfo
  - ROLE (0x04): 2-byte role code
```

## Encrypt Config

Encrypt XML configuration for a specific device using hybrid encryption.

**Endpoint**: `POST /api/v1/encrypt-config`

### Request Body

```json
{
  "device_name": "SEP001122334455",
  "config_xml": "<?xml version=\"1.0\"?><device>...</device>"
}
```

#### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `device_name` | String | Yes | Device name (SEP + MAC address) |
| `config_xml` | String | Yes | XML configuration content |

**Device Name Format**: Must match pattern `^SEP[0-9A-F]{12}$`

### Response

**Content-Type**: `application/octet-stream`
**Content-Disposition**: `attachment; filename={device_name}.cnf.xml.enc.sgn`

Binary encrypted configuration file.

### Example

```bash
curl -X POST https://example.com/api/capf/api/v1/encrypt-config \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "SEP001122334455",
    "config_xml": "<?xml version=\"1.0\"?><device>...</device>"
  }' \
  -o SEP001122334455.cnf.xml.enc.sgn
```

### Prerequisites

The device **must have a certificate (LSC)** in the database. If the device doesn't exist or has no certificate, the endpoint returns `404 Not Found`.

To ensure the device has a certificate:
1. Add the device via Device Management UI or API
2. Set operation to `install`
3. Wait for phone to request certificate via CAPF protocol
4. Verify device status is `issued`

### Encryption Format

The encrypted config uses hybrid encryption:

```
Header (TLV):
  - FILE_ID (0x70): 2 bytes = 0x0002
  - FILE_LENGTH (0x71): 4 bytes = total length
  - RESERVED (0x72): 16 bytes padding

Encryption Block:
  - DEVICE_NAME (0x01): Device identifier
  - ENCRYPTED_KEY (0x02): RSA-PKCS1v15 encrypted AES key
  - IV (0x03): 16 bytes AES-CBC initialization vector
  - ENCRYPTED_DATA (0x04): AES-128-CBC encrypted config

Footer:
  - SIGNATURE (0x0C): PKCS#1 v1.5 SHA-512 signature
```

**Encryption Details**:
- Random 128-bit AES key generated per file
- AES-128-CBC with PKCS#7 padding
- AES key wrapped with device's RSA public key (PKCS#1 v1.5)
- Entire file signed with signer's private key

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| `404` | `Device not found` | Device doesn't exist in database |
| `404` | `Device has no certificate` | Device exists but hasn't enrolled |
| `400` | `Invalid device name format` | Device name doesn't match SEP pattern |
| `500` | `Encryption failed` | Internal encryption error |

## Security Considerations

### Private Key Handling

**Never** transmit signer private keys over untrusted networks:
- Use internal network communication only
- Consider using HSM (Hardware Security Module) for key storage
- Implement key rotation policies

### Certificate Validation

The APIs perform basic validation but do not check:
- Certificate expiration dates
- Certificate chains (intermediate CAs)
- Certificate revocation status (CRL/OCSP)

Ensure certificates are valid before submission.

### ITL File Distribution

ITL files should be:
- Served over HTTPS from TFTP server
- Updated when certificates expire or are revoked
- Signed by a trusted SAST certificate

### Config File Security

Encrypted configs contain sensitive data (passwords, credentials):
- Store securely on TFTP/HTTP server
- Use HTTPS for delivery to phones
- Implement access controls
- Rotate encryption keys periodically

## Use Cases

### 1. Initial Phone Provisioning

Generate ITL file with trust chain:

```json
{
  "certificates": [
    {"pem": "...", "roles": ["SAST"]},
    {"pem": "...", "roles": ["CCM", "TFTP"]},
    {"pem": "...", "roles": ["CAPF"]}
  ],
  "signer": {
    "certificate_pem": "...",  // SAST cert
    "private_key_pem": "..."
  }
}
```

### 2. Secure Config Delivery

After device has LSC, encrypt configuration:

```json
{
  "device_name": "SEP001122334455",
  "config_xml": "<?xml version=\"1.0\"?><device><sshPassword>secret</sshPassword></device>"
}
```

Phone decrypts using its LSC private key.

### 3. Certificate Renewal

Update ITL file when certificates are renewed:
1. Generate new certificates
2. Create new ITL file with updated certs
3. Deploy to TFTP server
4. Phones download on next restart

## Testing

### Verify ITL File

```bash
# Generate ITL
curl -X POST ... -o ITLFile.tlv

# Check file header (should start with 0x0100)
xxd ITLFile.tlv | head

# Verify file size matches header LENGTH field
ls -l ITLFile.tlv
```

### Test Encryption/Decryption

The endpoint includes validation - successful response indicates:
- Device certificate was found
- Encryption completed without errors
- Signature was generated successfully

For deeper validation, attempt to decrypt using the device's private key (requires test setup).
