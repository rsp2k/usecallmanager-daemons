"""SQLAlchemy models for CAPF devices database."""

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Device(Base):
    """Device record for CAPF certificate enrollment."""

    __tablename__ = "devices"

    device_name = Column(String(15), primary_key=True)  # SEP + 12 hex digits
    operation = Column(String(10), nullable=False, default="none")
    authentication = Column(String(15), default="no password")
    password = Column(String(16), nullable=True)
    key_size = Column(Integer, nullable=True)  # RSA: 512-4096
    curve_name = Column(String(15), nullable=True)  # EC curves
    certificate = Column(Text, nullable=True)  # PEM format
    serial_number = Column(String(64), nullable=True)
    not_valid_before = Column(String(19), nullable=True)  # YYYY-MM-DD HH:MM:SS
    not_valid_after = Column(String(19), nullable=True)

    @property
    def has_certificate(self) -> bool:
        """Check if device has an installed certificate."""
        return self.certificate is not None

    def __repr__(self) -> str:
        return f"<Device name={self.device_name} operation={self.operation}>"
