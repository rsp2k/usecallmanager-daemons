"""Pydantic schemas for TVS API."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field

RoleType = Literal["SAST", "CCM", "CCM+TFTP", "TFTP", "CAPF", "APP-SERVER", "TVS"]


class CertificateCreate(BaseModel):
    """Request body for adding a certificate."""

    roles: list[RoleType]
    ttl: Annotated[int, Field(ge=1, le=2592000)] = 86400


class CertificateResponse(BaseModel):
    """Response for a single certificate."""

    certificate_hash: str
    serial_number: str
    subject_name: str
    issuer_name: str
    roles: list[str]
    ttl: int

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_roles(cls, obj):
        """Create from ORM object, splitting roles string."""
        return cls(
            certificate_hash=obj.certificate_hash,
            serial_number=obj.serial_number,
            subject_name=obj.subject_name,
            issuer_name=obj.issuer_name,
            roles=obj.roles.split(",") if obj.roles else [],
            ttl=obj.ttl,
        )


class CertificateListResponse(BaseModel):
    """Response for listing certificates."""

    items: list[CertificateResponse]
    total: int
    limit: int
    offset: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    protocol_port: int
    api_port: int


class StatsResponse(BaseModel):
    """Statistics response."""

    total_certificates: int
    active_connections: int
