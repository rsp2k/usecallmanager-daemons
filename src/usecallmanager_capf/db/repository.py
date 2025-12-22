"""Repository pattern for CAPF device operations."""

import logging
import re
from collections.abc import Sequence

from sqlalchemy.orm import Session, scoped_session

from usecallmanager_capf.db.models import Device
from usecallmanager_capf.protocol.constants import (
    VALID_AUTHENTICATIONS,
    VALID_CURVES,
    VALID_KEY_SIZES,
    VALID_OPERATIONS,
)

logger = logging.getLogger(__name__)


class DeviceRepository:
    """Repository for device CRUD operations."""

    def __init__(self, session: scoped_session[Session]):
        self.session = session

    def get_by_name(self, device_name: str) -> Device | None:
        """Get a device by its name."""
        return self.session.query(Device).filter_by(device_name=device_name).first()

    def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
        operation: str | None = None,
    ) -> Sequence[Device]:
        """List devices with optional filtering."""
        query = self.session.query(Device)

        if operation:
            query = query.filter_by(operation=operation)

        return query.order_by(Device.device_name).limit(limit).offset(offset).all()

    def count(self, operation: str | None = None) -> int:
        """Count devices with optional filtering."""
        query = self.session.query(Device)
        if operation:
            query = query.filter_by(operation=operation)
        return query.count()

    def add_or_update(
        self,
        device_name: str,
        operation: str,
        authentication: str = "no password",
        password: str | None = None,
        key_size: int | None = None,
        curve_name: str | None = None,
    ) -> Device:
        """Add or update a device configuration."""
        # Validate device name
        if not re.match(r"^SEP[0-9A-F]{12}$", device_name):
            raise ValueError(f"Invalid device name: {device_name}")

        # Validate operation
        if operation not in VALID_OPERATIONS:
            raise ValueError(f"Invalid operation: {operation}")

        # Validate authentication
        if authentication not in VALID_AUTHENTICATIONS:
            raise ValueError(f"Invalid authentication: {authentication}")

        # Validate password
        if authentication == "password":
            if not password or len(password) < 4 or len(password) > 15:
                raise ValueError("Password must be 4-15 characters")

        # Validate key size or curve
        if operation == "install":
            if key_size is not None and curve_name is not None:
                raise ValueError("Cannot specify both key_size and curve_name")
            if key_size is None and curve_name is None:
                key_size = 2048  # Default

            if key_size is not None and key_size not in VALID_KEY_SIZES:
                raise ValueError(f"Invalid key size: {key_size}")

            if curve_name is not None and curve_name not in VALID_CURVES:
                raise ValueError(f"Invalid curve: {curve_name}")

        # Upsert device
        existing = self.get_by_name(device_name)
        if existing:
            existing.operation = operation
            existing.authentication = authentication
            existing.password = password if authentication == "password" else None
            existing.key_size = key_size if operation == "install" else None
            existing.curve_name = curve_name if operation == "install" else None
            device = existing
        else:
            device = Device(
                device_name=device_name,
                operation=operation,
                authentication=authentication,
                password=password if authentication == "password" else None,
                key_size=key_size if operation == "install" else None,
                curve_name=curve_name if operation == "install" else None,
            )
            self.session.add(device)

        self.session.commit()

        if operation == "install":
            if key_size:
                logger.info("Scheduled install on %s with RSA %d using %s", device_name, key_size, authentication)
            elif curve_name:
                logger.info("Scheduled install on %s with EC %s using %s", device_name, curve_name, authentication)
        elif operation == "fetch":
            logger.info("Scheduled fetch on %s using %s", device_name, authentication)
        elif operation == "delete":
            logger.info("Scheduled delete on %s using %s", device_name, authentication)
        elif operation == "none":
            logger.info("Scheduled no operation on %s using %s", device_name, authentication)

        return device

    def update_after_install(
        self,
        device_name: str,
        serial_number: str,
        certificate: str,
        not_valid_before: str,
        not_valid_after: str,
    ):
        """Update device after successful certificate installation."""
        device = self.get_by_name(device_name)
        if device:
            device.operation = "none"
            device.serial_number = serial_number
            device.certificate = certificate
            device.not_valid_before = not_valid_before
            device.not_valid_after = not_valid_after
            self.session.commit()

    def update_after_delete(self, device_name: str):
        """Update device after successful certificate deletion."""
        device = self.get_by_name(device_name)
        if device:
            device.operation = "none"
            device.serial_number = None
            device.certificate = None
            device.not_valid_before = None
            device.not_valid_after = None
            self.session.commit()

    def remove(self, device_name: str) -> bool:
        """Remove a device."""
        device = self.get_by_name(device_name)
        if device is None:
            return False

        self.session.delete(device)
        self.session.commit()

        logger.info("Removed %s", device_name)
        return True

    def export_certificate(self, device_name: str) -> str | None:
        """Export a device's certificate as PEM."""
        device = self.get_by_name(device_name)
        if device is None or device.certificate is None:
            return None
        return device.certificate
