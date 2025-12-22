"""TLV (Tag-Length-Value) encoding utilities for ITL files and encrypted configs.

ITL files use a specific TLV format where:
- Tag: 1 byte identifying the element type
- Length: 2 bytes (big-endian) for the value length
- Value: Variable length data

Cisco IP phones use these formats for security verification.
"""

import struct
from enum import IntEnum


class ITLHeaderTag(IntEnum):
    """ITL file header TLV tags."""

    VERSION = 0x01  # File version (2 bytes: major.minor)
    LENGTH = 0x02  # Total file length (4 bytes)
    SIGNER_INFO = 0x03  # Signer information block
    SIGNER_NAME = 0x04  # Signer common name (string)
    SERIAL_NUMBER = 0x05  # Signer certificate serial number
    ISSUER = 0x06  # Issuer name (string)
    SIGNATURE_INFO = 0x07  # Signature information block
    HASH_ALGORITHM = 0x08  # Hash algorithm (1 byte)
    SIGNATURE_ALGORITHM = 0x09  # Signature algorithm (1 byte)
    SIGNATURE_MODULUS_LEN = 0x0A  # RSA modulus length (2 bytes)
    SIGNATURE_EXPONENT_LEN = 0x0B  # RSA exponent length (2 bytes)
    SIGNATURE = 0x0C  # Actual signature bytes


class ITLRecordTag(IntEnum):
    """ITL certificate record TLV tags."""

    RECORD_START = 0x01  # Start of a certificate record
    FUNCTION = 0x02  # Function/role flags (2 bytes)
    ISSUER_NAME = 0x03  # Issuer name string
    ROLE = 0x04  # Role code (2 bytes)
    SERIAL_NUMBER = 0x05  # Certificate serial number
    SUBJECT_NAME = 0x06  # Subject name string
    PUBLIC_KEY = 0x07  # DER-encoded SubjectPublicKeyInfo
    SIGNATURE_INFO = 0x08  # Signature block info
    CERTIFICATE = 0x09  # DER-encoded X.509 certificate


class EncryptedConfigTag(IntEnum):
    """Encrypted config file TLV tags."""

    # Header tags (0x70-0x7F)
    FILE_ID = 0x70  # File type identifier (2 bytes, value 0x0002)
    FILE_LENGTH = 0x71  # Total payload length (4 bytes)
    RESERVED = 0x72  # Reserved padding (16 bytes)

    # Encryption block tags (0x01-0x0F)
    DEVICE_NAME = 0x01  # Target device identifier
    ENCRYPTED_KEY = 0x02  # RSA-encrypted AES key
    IV = 0x03  # AES-CBC initialization vector (16 bytes)
    ENCRYPTED_DATA = 0x04  # Encrypted config data

    # Signature tags
    SIGNATURE = 0x0C  # PKCS#1 v1.5 signature


class HashAlgorithm(IntEnum):
    """Hash algorithm identifiers used in signatures."""

    SHA1 = 0x01
    SHA512 = 0x02


class SignatureAlgorithm(IntEnum):
    """Signature algorithm identifiers."""

    RSA_SHA1 = 0x00
    RSA_SHA512 = 0x01
    ECDSA_SHA256 = 0x02
    ECDSA_SHA384 = 0x03
    ECDSA_SHA512 = 0x04


class RoleCode(IntEnum):
    """Certificate role codes for ITL files.

    These identify what function each certificate serves in the phone's
    trust hierarchy.
    """

    SAST = 0  # System Administrator Security Token - signs ITL updates
    CCM = 1  # Cisco Call Manager - SIP-TLS connections
    CCM_TFTP = 2  # CCM + TFTP combined role
    TFTP = 3  # TFTP server - config/firmware downloads
    CAPF = 4  # Certificate Authority Proxy Function
    APP_SERVER = 7  # Application server
    TVS = 21  # Trust Verification Service


# Map string role names to numeric codes
ROLE_NAME_TO_CODE: dict[str, RoleCode] = {
    "SAST": RoleCode.SAST,
    "CCM": RoleCode.CCM,
    "CCM+TFTP": RoleCode.CCM_TFTP,
    "TFTP": RoleCode.TFTP,
    "CAPF": RoleCode.CAPF,
    "APP-SERVER": RoleCode.APP_SERVER,
    "TVS": RoleCode.TVS,
}


class TLVWriter:
    """Builder for constructing TLV-encoded binary data.

    This class accumulates TLV elements and can output the complete
    binary representation.

    Example:
        writer = TLVWriter()
        writer.write_uint8(ITLHeaderTag.VERSION, 1, 1)
        writer.write_bytes(ITLRecordTag.CERTIFICATE, cert_der)
        data = writer.getvalue()
    """

    def __init__(self) -> None:
        """Initialize an empty TLV buffer."""
        self._buffer = bytearray()

    def write_raw(self, data: bytes) -> None:
        """Write raw bytes directly without TLV encoding."""
        self._buffer.extend(data)

    def write_tlv(self, tag: int, value: bytes) -> None:
        """Write a complete TLV element.

        Args:
            tag: 1-byte tag identifier
            value: Raw bytes for the value
        """
        length = len(value)
        # Tag (1 byte) + Length (2 bytes big-endian) + Value
        self._buffer.extend(struct.pack(">BH", tag, length))
        self._buffer.extend(value)

    def write_uint8(self, tag: int, value: int) -> None:
        """Write a TLV with a single byte value."""
        self.write_tlv(tag, struct.pack(">B", value))

    def write_uint16(self, tag: int, value: int) -> None:
        """Write a TLV with a 2-byte big-endian value."""
        self.write_tlv(tag, struct.pack(">H", value))

    def write_uint32(self, tag: int, value: int) -> None:
        """Write a TLV with a 4-byte big-endian value."""
        self.write_tlv(tag, struct.pack(">I", value))

    def write_string(self, tag: int, value: str) -> None:
        """Write a TLV with a UTF-8 encoded string value."""
        self.write_tlv(tag, value.encode("utf-8"))

    def write_bytes(self, tag: int, value: bytes) -> None:
        """Write a TLV with raw bytes value."""
        self.write_tlv(tag, value)

    def write_version(self, tag: int, major: int, minor: int) -> None:
        """Write a TLV with a 2-byte version (major.minor)."""
        self.write_tlv(tag, struct.pack(">BB", major, minor))

    def getvalue(self) -> bytes:
        """Return the accumulated TLV data as bytes."""
        return bytes(self._buffer)

    def __len__(self) -> int:
        """Return the current buffer length."""
        return len(self._buffer)

    def clear(self) -> None:
        """Clear the buffer."""
        self._buffer.clear()


def parse_tlv(data: bytes, offset: int = 0) -> tuple[int, int, bytes, int]:
    """Parse a single TLV element from binary data.

    Args:
        data: Binary data containing TLV elements
        offset: Starting position in data

    Returns:
        Tuple of (tag, length, value, next_offset)

    Raises:
        ValueError: If data is too short or malformed
    """
    if offset + 3 > len(data):
        raise ValueError("Insufficient data for TLV header")

    tag = data[offset]
    length = struct.unpack(">H", data[offset + 1 : offset + 3])[0]

    value_start = offset + 3
    value_end = value_start + length

    if value_end > len(data):
        raise ValueError(f"TLV value extends past data end (need {length} bytes)")

    value = data[value_start:value_end]
    return tag, length, value, value_end
