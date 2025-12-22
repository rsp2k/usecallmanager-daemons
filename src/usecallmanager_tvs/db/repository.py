"""Repository pattern for TVS certificate operations."""

import binascii
import logging
from collections.abc import Sequence

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.orm import Session, scoped_session

from usecallmanager_tvs.db.models import Certificate
from usecallmanager_tvs.protocol.constants import VALID_ROLES

logger = logging.getLogger(__name__)


class CertificateRepository:
    """Repository for certificate CRUD operations."""

    def __init__(self, session: scoped_session[Session]):
        self.session = session

    def get_by_hash(self, certificate_hash: str) -> Certificate | None:
        """Get a certificate by its hash."""
        return self.session.query(Certificate).filter_by(certificate_hash=certificate_hash).first()

    def get_by_hash_prefix(self, hash_prefix: str) -> Certificate | None:
        """Get a certificate by hash prefix (for CLI convenience)."""
        return (
            self.session.query(Certificate).filter(Certificate.certificate_hash.like(f"{hash_prefix}%")).first()
        )

    def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[Certificate]:
        """List all certificates."""
        return (
            self.session.query(Certificate)
            .order_by(Certificate.subject_name)
            .limit(limit)
            .offset(offset)
            .all()
        )

    def count(self) -> int:
        """Count total certificates."""
        return self.session.query(Certificate).count()

    def add_from_pem(self, pem_data: bytes, roles: list[str], ttl: int = 86400) -> Certificate:
        """Add a certificate from PEM data."""
        # Validate roles
        invalid_roles = set(roles) - VALID_ROLES
        if invalid_roles:
            raise ValueError(f"Invalid roles: {invalid_roles}")

        # Parse certificate
        try:
            cert = x509.load_pem_x509_certificate(pem_data, backends.default_backend())
        except ValueError as e:
            raise ValueError(f"Invalid PEM certificate: {e}") from e

        # Validate public key type
        public_key = cert.public_key()
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise ValueError("Certificate must have RSA or EC public key")

        # Extract certificate data
        serial_number = cert.serial_number
        serial_number_bytes = serial_number.to_bytes((serial_number.bit_length() + 7) // 8, byteorder="big")
        serial_number_hex = binascii.hexlify(serial_number_bytes).decode("utf-8")

        subject_name = ",".join([attr.rfc4514_string() for attr in cert.subject])
        issuer_name = ",".join([attr.rfc4514_string() for attr in cert.issuer])

        certificate_hash = cert.fingerprint(hashes.SHA256())
        certificate_hash_hex = binascii.hexlify(certificate_hash).decode("utf-8")

        # Sort roles in canonical order
        role_order = ["SAST", "CCM", "CCM+TFTP", "TFTP", "CAPF", "APP-SERVER", "TVS"]
        sorted_roles = sorted(roles, key=lambda r: role_order.index(r) if r in role_order else 999)
        roles_str = ",".join(sorted_roles)

        # Upsert certificate
        existing = self.get_by_hash(certificate_hash_hex)
        if existing:
            existing.roles = roles_str
            existing.ttl = ttl
            certificate = existing
        else:
            certificate = Certificate(
                certificate_hash=certificate_hash_hex,
                serial_number=serial_number_hex,
                subject_name=subject_name,
                issuer_name=issuer_name,
                certificate=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                roles=roles_str,
                ttl=ttl,
            )
            self.session.add(certificate)

        self.session.commit()

        logger.info("Added %s <%s> with %s", certificate_hash_hex, subject_name, roles_str)
        return certificate

    def remove(self, certificate_hash: str) -> bool:
        """Remove a certificate by hash or hash prefix."""
        cert = self.get_by_hash(certificate_hash)
        if cert is None:
            cert = self.get_by_hash_prefix(certificate_hash)

        if cert is None:
            return False

        self.session.delete(cert)
        self.session.commit()

        logger.info("Removed %s <%s>", cert.certificate_hash, cert.subject_name)
        return True

    def export_pem(self, certificate_hash: str) -> str | None:
        """Export a certificate as PEM."""
        cert = self.get_by_hash(certificate_hash)
        if cert is None:
            cert = self.get_by_hash_prefix(certificate_hash)

        if cert is None:
            return None

        return cert.certificate
