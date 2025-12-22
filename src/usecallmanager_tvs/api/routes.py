"""TVS API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from usecallmanager_tvs.api.schemas import (
    CertificateListResponse,
    CertificateResponse,
    HealthResponse,
    RoleType,
    StatsResponse,
)
from usecallmanager_tvs.db.repository import CertificateRepository
from usecallmanager_tvs.protocol.server import TvsConnection

router = APIRouter()


def get_repository() -> CertificateRepository:
    """Dependency to get repository - will be overridden at app creation."""
    raise NotImplementedError("Repository not configured")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    from usecallmanager_tvs.service import _config

    return HealthResponse(
        status="healthy",
        service="tvs",
        protocol_port=_config.protocol_port if _config else 2445,
        api_port=_config.api_port if _config else 8081,
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats(repo: Annotated[CertificateRepository, Depends(get_repository)]):
    """Get service statistics."""
    return StatsResponse(
        total_certificates=repo.count(),
        active_connections=TvsConnection.client_count,
    )


@router.get("/certificates", response_model=CertificateListResponse)
async def list_certificates(
    repo: Annotated[CertificateRepository, Depends(get_repository)],
    limit: int = 100,
    offset: int = 0,
):
    """List all certificates."""
    certificates = repo.list_all(limit=limit, offset=offset)
    total = repo.count()

    return CertificateListResponse(
        items=[CertificateResponse.from_orm_with_roles(c) for c in certificates],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/certificates/{certificate_hash}", response_model=CertificateResponse)
async def get_certificate(
    certificate_hash: str,
    repo: Annotated[CertificateRepository, Depends(get_repository)],
):
    """Get a certificate by hash."""
    cert = repo.get_by_hash(certificate_hash)
    if cert is None:
        cert = repo.get_by_hash_prefix(certificate_hash)

    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return CertificateResponse.from_orm_with_roles(cert)


@router.post("/certificates", response_model=CertificateResponse, status_code=201)
async def add_certificate(
    repo: Annotated[CertificateRepository, Depends(get_repository)],
    file: Annotated[UploadFile, File()],
    roles: Annotated[list[RoleType] | None, Form()] = None,
    ttl: Annotated[int, Form(ge=1, le=2592000)] = 86400,
):
    """Add a certificate from PEM file."""
    if roles is None or len(roles) == 0:
        raise HTTPException(status_code=400, detail="At least one role is required")

    pem_data = await file.read()

    try:
        cert = repo.add_from_pem(pem_data, roles, ttl)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return CertificateResponse.from_orm_with_roles(cert)


@router.delete("/certificates/{certificate_hash}", status_code=204)
async def delete_certificate(
    certificate_hash: str,
    repo: Annotated[CertificateRepository, Depends(get_repository)],
):
    """Delete a certificate by hash."""
    if not repo.remove(certificate_hash):
        raise HTTPException(status_code=404, detail="Certificate not found")


@router.get("/certificates/{certificate_hash}/export")
async def export_certificate(
    certificate_hash: str,
    repo: Annotated[CertificateRepository, Depends(get_repository)],
):
    """Export a certificate as PEM."""
    pem = repo.export_pem(certificate_hash)
    if pem is None:
        raise HTTPException(status_code=404, detail="Certificate not found")

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(content=pem, media_type="application/x-pem-file")
