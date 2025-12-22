"""Pydantic schemas for CAPF API."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

OperationType = Literal["install", "fetch", "delete", "none"]
AuthenticationType = Literal["password", "certificate", "no password"]
CurveType = Literal["secp256r1", "secp384r1", "secp521r1"]


class DeviceCreate(BaseModel):
    """Request body for adding/updating a device."""

    device_name: Annotated[str, Field(pattern=r"^SEP[0-9A-F]{12}$")]
    operation: OperationType
    authentication: AuthenticationType = "no password"
    password: Annotated[str | None, Field(min_length=4, max_length=15)] = None
    key_size: Annotated[int | None, Field(None)] = None
    curve_name: CurveType | None = None

    @field_validator("key_size")
    @classmethod
    def validate_key_size(cls, v):
        if v is not None and v not in (512, 1024, 2048, 3072, 4096):
            raise ValueError("key_size must be 512, 1024, 2048, 3072, or 4096")
        return v


class DeviceOperationUpdate(BaseModel):
    """Request body for updating device operation."""

    operation: OperationType
    authentication: AuthenticationType = "no password"
    password: Annotated[str | None, Field(min_length=4, max_length=15)] = None
    key_size: Annotated[int | None, Field(None)] = None
    curve_name: CurveType | None = None

    @field_validator("key_size")
    @classmethod
    def validate_key_size(cls, v):
        if v is not None and v not in (512, 1024, 2048, 3072, 4096):
            raise ValueError("key_size must be 512, 1024, 2048, 3072, or 4096")
        return v


class DeviceResponse(BaseModel):
    """Response for a single device."""

    device_name: str
    operation: str
    authentication: str | None
    key_size: int | None
    curve_name: str | None
    has_certificate: bool
    serial_number: str | None
    not_valid_before: str | None
    not_valid_after: str | None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_model(cls, obj):
        """Create from ORM object."""
        return cls(
            device_name=obj.device_name,
            operation=obj.operation,
            authentication=obj.authentication,
            key_size=obj.key_size,
            curve_name=obj.curve_name,
            has_certificate=obj.certificate is not None,
            serial_number=obj.serial_number,
            not_valid_before=obj.not_valid_before,
            not_valid_after=obj.not_valid_after,
        )


class DeviceListResponse(BaseModel):
    """Response for listing devices."""

    items: list[DeviceResponse]
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

    total_devices: int
    pending_install: int
    pending_fetch: int
    pending_delete: int
    active_connections: int


class IssuerCertificateResponse(BaseModel):
    """Issuer/root certificate details."""

    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    fingerprint_sha256: str
    fingerprint_sha1: str
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm: str
    is_ca: bool
    pem: str
