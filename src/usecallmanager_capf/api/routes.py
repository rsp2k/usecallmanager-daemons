"""CAPF API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from usecallmanager_capf.api.schemas import (
    DeviceCreate,
    DeviceListResponse,
    DeviceOperationUpdate,
    DeviceResponse,
    EncryptConfigRequest,
    HealthResponse,
    IssuerCertificateResponse,
    ITLFileRequest,
    StatsResponse,
)
from usecallmanager_capf.db.repository import DeviceRepository
from usecallmanager_capf.protocol.server import CapfConnection

router = APIRouter()


def get_repository() -> DeviceRepository:
    """Dependency to get repository - will be overridden at app creation."""
    raise NotImplementedError("Repository not configured")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    from usecallmanager_capf.service import _config

    return HealthResponse(
        status="healthy",
        service="capf",
        protocol_port=_config.protocol_port if _config else 3804,
        api_port=_config.api_port if _config else 8082,
    )


@router.get("/issuer-certificate", response_model=IssuerCertificateResponse)
async def get_issuer_certificate():
    """Get details about the CAPF issuer/root certificate."""
    import binascii

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    from usecallmanager_capf.service import _config

    if _config is None or not _config.issuer_cert_file:
        raise HTTPException(status_code=500, detail="Issuer certificate not configured")

    try:
        with open(_config.issuer_cert_file, "rb") as f:
            pem_data = f.read()

        # Parse certificate (skip private key if present)
        cert = None
        for line in pem_data.split(b"\n"):
            if b"BEGIN CERTIFICATE" in line:
                start = pem_data.find(b"-----BEGIN CERTIFICATE-----")
                end = pem_data.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
                cert_pem = pem_data[start:end]
                cert = x509.load_pem_x509_certificate(cert_pem)
                break

        if cert is None:
            raise HTTPException(status_code=500, detail="No certificate found in issuer file")

        # Extract subject and issuer as readable strings
        subject = ", ".join(attr.rfc4514_string() for attr in cert.subject)
        issuer = ", ".join(attr.rfc4514_string() for attr in cert.issuer)

        # Serial number
        serial_hex = format(cert.serial_number, "x")

        # Fingerprints
        sha256_fp = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode().upper()
        sha256_fp = ":".join(sha256_fp[i : i + 2] for i in range(0, len(sha256_fp), 2))
        sha1_fp = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode().upper()
        sha1_fp = ":".join(sha1_fp[i : i + 2] for i in range(0, len(sha1_fp), 2))

        # Public key info
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_algorithm = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_algorithm = f"EC ({pub_key.curve.name})"
            key_size = pub_key.key_size
        else:
            key_algorithm = "Unknown"
            key_size = 0

        # Signature algorithm
        sig_alg = cert.signature_algorithm_oid._name

        # Check if CA
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            is_ca = False

        # PEM output (certificate only)
        cert_pem_str = cert.public_bytes(serialization.Encoding.PEM).decode()

        return IssuerCertificateResponse(
            subject=subject,
            issuer=issuer,
            serial_number=serial_hex,
            not_valid_before=cert.not_valid_before_utc.isoformat(),
            not_valid_after=cert.not_valid_after_utc.isoformat(),
            fingerprint_sha256=sha256_fp,
            fingerprint_sha1=sha1_fp,
            public_key_algorithm=key_algorithm,
            public_key_size=key_size,
            signature_algorithm=sig_alg,
            is_ca=is_ca,
            pem=cert_pem_str,
        )

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Issuer certificate file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading certificate: {e}")


@router.get("/stats", response_model=StatsResponse)
async def get_stats(repo: Annotated[DeviceRepository, Depends(get_repository)]):
    """Get service statistics."""
    return StatsResponse(
        total_devices=repo.count(),
        pending_install=repo.count(operation="install"),
        pending_fetch=repo.count(operation="fetch"),
        pending_delete=repo.count(operation="delete"),
        active_connections=CapfConnection.client_count,
    )


@router.get("/devices", response_model=DeviceListResponse)
async def list_devices(
    repo: Annotated[DeviceRepository, Depends(get_repository)],
    limit: int = 100,
    offset: int = 0,
    operation: str | None = None,
):
    """List all devices."""
    devices = repo.list_all(limit=limit, offset=offset, operation=operation)
    total = repo.count(operation=operation)

    return DeviceListResponse(
        items=[DeviceResponse.from_orm_model(d) for d in devices],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/devices/{device_name}", response_model=DeviceResponse)
async def get_device(
    device_name: str,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Get a device by name."""
    device = repo.get_by_name(device_name)

    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    return DeviceResponse.from_orm_model(device)


@router.post("/devices", response_model=DeviceResponse, status_code=201)
async def add_device(
    data: DeviceCreate,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Add or update a device."""
    try:
        device = repo.add_or_update(
            device_name=data.device_name,
            operation=data.operation,
            authentication=data.authentication,
            password=data.password,
            key_size=data.key_size,
            curve_name=data.curve_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return DeviceResponse.from_orm_model(device)


@router.patch("/devices/{device_name}/operation", response_model=DeviceResponse)
async def update_device_operation(
    device_name: str,
    data: DeviceOperationUpdate,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Update a device's scheduled operation."""
    existing = repo.get_by_name(device_name)
    if existing is None:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        device = repo.add_or_update(
            device_name=device_name,
            operation=data.operation,
            authentication=data.authentication,
            password=data.password,
            key_size=data.key_size,
            curve_name=data.curve_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return DeviceResponse.from_orm_model(device)


@router.delete("/devices/{device_name}", status_code=204)
async def delete_device(
    device_name: str,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Delete a device."""
    if not repo.remove(device_name):
        raise HTTPException(status_code=404, detail="Device not found")


@router.get("/devices/{device_name}/certificate")
async def export_device_certificate(
    device_name: str,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Export a device's certificate as PEM."""
    pem = repo.export_certificate(device_name)
    if pem is None:
        raise HTTPException(status_code=404, detail="Device not found or no certificate")

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(content=pem, media_type="application/x-pem-file")


# Security APIs for ITL generation and config encryption


@router.post("/itl-file")
async def generate_itl_file(data: ITLFileRequest):
    """Generate an ITL (Initial Trust List) file.

    The ITL file contains trusted certificates that phones use to verify
    TLS connections to infrastructure services.

    Returns the binary ITL file as application/octet-stream.
    """
    from fastapi.responses import Response

    from usecallmanager_capf.security.itl import ITLBuilder

    try:
        builder = ITLBuilder()

        for cert_entry in data.certificates:
            builder.add_certificate(cert_entry.pem, cert_entry.roles)

        itl_bytes = builder.build(
            signer_cert_pem=data.signer.certificate_pem,
            signer_key_pem=data.signer.private_key_pem,
        )

        return Response(
            content=itl_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=ITLFile.tlv"},
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ITL generation failed: {e}") from e


@router.post("/encrypt-config")
async def encrypt_config_file(
    data: EncryptConfigRequest,
    repo: Annotated[DeviceRepository, Depends(get_repository)],
):
    """Encrypt a configuration file for a specific device.

    The encrypted file can only be decrypted by the target device using
    its private key (LSC). Returns the binary .enc.sgn file.

    Requires:
    - Device must exist in the database
    - Device must have a certificate (LSC) installed
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from fastapi.responses import Response

    from usecallmanager_capf.security.encryption import encrypt_config
    from usecallmanager_capf.service import _config

    # Get device certificate
    device = repo.get_by_name(data.device_name)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.certificate is None:
        raise HTTPException(
            status_code=400,
            detail="Device does not have a certificate installed",
        )

    # Load issuer certificate and key for signing
    if _config is None or not _config.issuer_cert_file:
        raise HTTPException(
            status_code=500, detail="Issuer certificate not configured"
        )

    try:
        with open(_config.issuer_cert_file, "rb") as f:
            issuer_data = f.read()

        # Parse issuer cert and key
        signer_cert = x509.load_pem_x509_certificate(issuer_data)
        signer_key = serialization.load_pem_private_key(issuer_data, password=None)

        # Parse device certificate
        device_cert = x509.load_pem_x509_certificate(device.certificate.encode())

        # Encrypt the config
        encrypted = encrypt_config(
            config_xml=data.config_xml,
            device_name=data.device_name,
            device_cert=device_cert,
            signer_cert=signer_cert,
            signer_key=signer_key,
        )

        filename = f"{data.device_name}.cnf.xml.enc.sgn"
        return Response(
            content=encrypted,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=500, detail="Issuer certificate file not found"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Config encryption failed: {e}"
        ) from e
