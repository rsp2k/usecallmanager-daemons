"""SQLAlchemy models for TVS certificates database."""

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Certificate(Base):
    """Certificate record for TVS verification."""

    __tablename__ = "certificates"

    certificate_hash = Column(String(64), primary_key=True)
    serial_number = Column(String(64), nullable=False)
    subject_name = Column(Text, nullable=False)
    issuer_name = Column(Text, nullable=False)
    certificate = Column(Text, nullable=False)  # PEM format
    roles = Column(String(100), nullable=False)  # Comma-separated
    ttl = Column(Integer, default=86400)

    @property
    def roles_list(self) -> list[str]:
        """Get roles as a list."""
        return self.roles.split(",") if self.roles else []

    @roles_list.setter
    def roles_list(self, values: list[str]):
        """Set roles from a list."""
        self.roles = ",".join(values)

    def __repr__(self) -> str:
        return f"<Certificate hash={self.certificate_hash[:16]}... roles={self.roles}>"
