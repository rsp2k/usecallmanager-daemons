"""ITL (Initial Trust List) file generation.

ITL files contain X.509 certificates that Cisco IP phones use to verify
TLS connections to call managers, TFTP servers, and other infrastructure.

The file format is TLV-encoded with:
1. Header (version, length, signer info)
2. Certificate records (one per trusted cert)
3. Digital signature (PKCS#1 v1.5 with SHA-512)

References:
- https://usecallmanager.nz/device-security.html
- https://github.com/usecallmanagernz/certutils
"""

import struct
from dataclasses import dataclass, field
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from usecallmanager_capf.security.tlv import (
    HashAlgorithm,
    ITLHeaderTag,
    ITLRecordTag,
    ROLE_NAME_TO_CODE,
    RoleCode,
    SignatureAlgorithm,
    TLVWriter,
)


# Maximum SAST certificates allowed per ITL file
MAX_SAST_CERTS = 2

# ITL file version (1.1)
ITL_VERSION_MAJOR = 1
ITL_VERSION_MINOR = 1


@dataclass
class ITLCertificate:
    """A certificate entry for an ITL file.

    Attributes:
        certificate: Parsed X.509 certificate object
        roles: List of role names this certificate serves
    """

    certificate: x509.Certificate
    roles: list[str]

    @property
    def role_codes(self) -> list[RoleCode]:
        """Convert role names to numeric codes."""
        codes = []
        for role in self.roles:
            if role in ROLE_NAME_TO_CODE:
                codes.append(ROLE_NAME_TO_CODE[role])
        return codes


@dataclass
class ITLBuilder:
    """Builder for creating ITL files.

    Example:
        builder = ITLBuilder()
        builder.add_certificate(ccm_cert_pem, ["CCM", "TFTP"])
        builder.add_certificate(capf_cert_pem, ["CAPF"])
        itl_bytes = builder.build(signer_cert_pem, signer_key_pem)
    """

    certificates: list[ITLCertificate] = field(default_factory=list)

    def add_certificate(
        self, pem: str | bytes, roles: Sequence[str]
    ) -> "ITLBuilder":
        """Add a certificate with specified roles.

        Args:
            pem: PEM-encoded X.509 certificate
            roles: List of role names (SAST, CCM, TFTP, CAPF, etc.)

        Returns:
            Self for method chaining

        Raises:
            ValueError: If certificate is invalid or too many SAST certs
        """
        if isinstance(pem, str):
            pem = pem.encode("utf-8")

        cert = x509.load_pem_x509_certificate(pem)
        role_list = list(roles)

        # Validate roles
        for role in role_list:
            if role not in ROLE_NAME_TO_CODE:
                raise ValueError(f"Unknown role: {role}")

        # Check SAST limit
        if "SAST" in role_list:
            current_sast = sum(
                1 for c in self.certificates if "SAST" in c.roles
            )
            if current_sast >= MAX_SAST_CERTS:
                raise ValueError(
                    f"Maximum {MAX_SAST_CERTS} SAST certificates allowed"
                )

        # Validate key size for RSA (phones limited to 2048-bit max)
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            if pub_key.key_size > 2048:
                raise ValueError(
                    f"RSA key size {pub_key.key_size} exceeds phone limit of 2048"
                )
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            valid_curves = {"secp256r1", "secp384r1", "secp521r1"}
            if pub_key.curve.name not in valid_curves:
                raise ValueError(
                    f"EC curve {pub_key.curve.name} not supported"
                )

        self.certificates.append(ITLCertificate(certificate=cert, roles=role_list))
        return self

    def _build_certificate_record(self, entry: ITLCertificate) -> bytes:
        """Build a TLV-encoded certificate record."""
        writer = TLVWriter()
        cert = entry.certificate

        # Certificate DER encoding
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Subject name
        subject = cert.subject.rfc4514_string()

        # Issuer name
        issuer = cert.issuer.rfc4514_string()

        # Serial number as hex string
        serial_hex = format(cert.serial_number, "x")

        # Public key DER (SubjectPublicKeyInfo)
        pub_key_der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Build the record
        # Write role for each assigned role
        for role_code in entry.role_codes:
            writer.write_uint16(ITLRecordTag.ROLE, role_code)

        # Certificate metadata
        writer.write_string(ITLRecordTag.SUBJECT_NAME, subject)
        writer.write_string(ITLRecordTag.ISSUER_NAME, issuer)
        writer.write_string(ITLRecordTag.SERIAL_NUMBER, serial_hex)

        # Public key
        writer.write_bytes(ITLRecordTag.PUBLIC_KEY, pub_key_der)

        # Full certificate
        writer.write_bytes(ITLRecordTag.CERTIFICATE, cert_der)

        return writer.getvalue()

    def _build_signer_info(self, signer_cert: x509.Certificate) -> bytes:
        """Build the signer information TLV block."""
        writer = TLVWriter()

        # Signer name (subject CN)
        try:
            cn = signer_cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
        except (IndexError, AttributeError):
            cn = signer_cert.subject.rfc4514_string()

        writer.write_string(ITLHeaderTag.SIGNER_NAME, str(cn))

        # Serial number
        serial_hex = format(signer_cert.serial_number, "x")
        writer.write_string(ITLHeaderTag.SERIAL_NUMBER, serial_hex)

        # Issuer
        issuer = signer_cert.issuer.rfc4514_string()
        writer.write_string(ITLHeaderTag.ISSUER, issuer)

        return writer.getvalue()

    def _build_signature_info(
        self, signer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    ) -> tuple[bytes, HashAlgorithm, SignatureAlgorithm]:
        """Build signature algorithm info and return metadata."""
        writer = TLVWriter()

        if isinstance(signer_key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
            # Get public key for modulus info
            if hasattr(signer_key, "public_key"):
                pub = signer_key.public_key()
            else:
                pub = signer_key
            numbers = pub.public_numbers()

            writer.write_uint8(ITLHeaderTag.HASH_ALGORITHM, HashAlgorithm.SHA512)
            writer.write_uint8(
                ITLHeaderTag.SIGNATURE_ALGORITHM, SignatureAlgorithm.RSA_SHA512
            )

            # RSA modulus and exponent lengths in bits
            modulus_bits = pub.key_size
            exponent_bits = numbers.e.bit_length()
            writer.write_uint16(ITLHeaderTag.SIGNATURE_MODULUS_LEN, modulus_bits)
            writer.write_uint16(ITLHeaderTag.SIGNATURE_EXPONENT_LEN, exponent_bits)

            return writer.getvalue(), HashAlgorithm.SHA512, SignatureAlgorithm.RSA_SHA512

        elif isinstance(signer_key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
            curve_name = signer_key.curve.name if hasattr(signer_key, "curve") else "secp256r1"

            # Choose signature algorithm based on curve
            if curve_name == "secp384r1":
                sig_alg = SignatureAlgorithm.ECDSA_SHA384
            elif curve_name == "secp521r1":
                sig_alg = SignatureAlgorithm.ECDSA_SHA512
            else:
                sig_alg = SignatureAlgorithm.ECDSA_SHA256

            writer.write_uint8(ITLHeaderTag.HASH_ALGORITHM, HashAlgorithm.SHA512)
            writer.write_uint8(ITLHeaderTag.SIGNATURE_ALGORITHM, sig_alg)

            return writer.getvalue(), HashAlgorithm.SHA512, sig_alg

        else:
            raise ValueError(f"Unsupported key type: {type(signer_key)}")

    def build(
        self,
        signer_cert_pem: str | bytes,
        signer_key_pem: str | bytes,
    ) -> bytes:
        """Build the complete ITL file.

        Args:
            signer_cert_pem: PEM-encoded signer certificate
            signer_key_pem: PEM-encoded signer private key

        Returns:
            Complete ITL file as bytes

        Raises:
            ValueError: If no certificates added or signing fails
        """
        if not self.certificates:
            raise ValueError("No certificates added to ITL")

        # Parse signer credentials
        if isinstance(signer_cert_pem, str):
            signer_cert_pem = signer_cert_pem.encode("utf-8")
        if isinstance(signer_key_pem, str):
            signer_key_pem = signer_key_pem.encode("utf-8")

        signer_cert = x509.load_pem_x509_certificate(signer_cert_pem)
        signer_key = serialization.load_pem_private_key(signer_key_pem, password=None)

        # Build certificate records
        records_data = bytearray()
        for entry in self.certificates:
            record = self._build_certificate_record(entry)
            # Wrap record with RECORD_START tag
            record_writer = TLVWriter()
            record_writer.write_bytes(ITLRecordTag.RECORD_START, record)
            records_data.extend(record_writer.getvalue())

        records_bytes = bytes(records_data)

        # Build signer info
        signer_info = self._build_signer_info(signer_cert)

        # Build signature info
        sig_info, hash_alg, sig_alg = self._build_signature_info(signer_key)

        # Build header (without final length yet)
        header_writer = TLVWriter()
        header_writer.write_version(
            ITLHeaderTag.VERSION, ITL_VERSION_MAJOR, ITL_VERSION_MINOR
        )
        # Placeholder for length - will calculate after
        header_writer.write_bytes(ITLHeaderTag.SIGNER_INFO, signer_info)
        header_writer.write_bytes(ITLHeaderTag.SIGNATURE_INFO, sig_info)

        # Calculate what needs to be signed (header + records, before signature)
        # The length field will be updated after we know the signature size
        pre_sig_data = header_writer.getvalue() + records_bytes

        # Sign the data
        if isinstance(signer_key, rsa.RSAPrivateKey):
            signature = signer_key.sign(
                pre_sig_data,
                padding.PKCS1v15(),
                hashes.SHA512(),
            )
        elif isinstance(signer_key, ec.EllipticCurvePrivateKey):
            # Choose hash based on curve
            curve_name = signer_key.curve.name
            if curve_name == "secp384r1":
                hash_obj = hashes.SHA384()
            elif curve_name == "secp521r1":
                hash_obj = hashes.SHA512()
            else:
                hash_obj = hashes.SHA256()

            signature = signer_key.sign(
                pre_sig_data,
                ec.ECDSA(hash_obj),
            )
        else:
            raise ValueError(f"Unsupported signer key type: {type(signer_key)}")

        # Calculate final length (pre_sig_data + signature TLV)
        # Signature TLV: tag(1) + length(2) + signature
        sig_tlv_len = 1 + 2 + len(signature)
        total_length = len(pre_sig_data) + sig_tlv_len

        # Rebuild with correct length
        final_writer = TLVWriter()
        final_writer.write_version(
            ITLHeaderTag.VERSION, ITL_VERSION_MAJOR, ITL_VERSION_MINOR
        )
        final_writer.write_uint32(ITLHeaderTag.LENGTH, total_length)
        final_writer.write_bytes(ITLHeaderTag.SIGNER_INFO, signer_info)
        final_writer.write_bytes(ITLHeaderTag.SIGNATURE_INFO, sig_info)

        # Add records
        final_writer.write_raw(records_bytes)

        # Add signature
        final_writer.write_bytes(ITLHeaderTag.SIGNATURE, signature)

        return final_writer.getvalue()

    def clear(self) -> None:
        """Remove all certificates."""
        self.certificates.clear()
