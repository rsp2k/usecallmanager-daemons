"""Configuration file encryption for Cisco IP phones.

Encrypted config files (.enc.sgn) use:
1. AES-128-CBC for symmetric encryption of the XML config
2. RSA-PKCS1v15 to wrap the AES key with the device's public key
3. PKCS#1 v1.5 SHA-512 signature for integrity

This ensures only the target device can decrypt its configuration.

References:
- https://usecallmanager.nz/device-security.html
- https://github.com/usecallmanagernz/certutils
"""

import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from usecallmanager_capf.security.tlv import EncryptedConfigTag, TLVWriter


# AES key and IV sizes
AES_KEY_SIZE = 16  # 128-bit AES
AES_IV_SIZE = 16  # 128-bit IV for CBC mode
AES_BLOCK_SIZE = 16


def _pad_pkcs7(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def _encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data with AES-128-CBC.

    Args:
        plaintext: Data to encrypt (will be PKCS#7 padded)
        key: 16-byte AES key
        iv: 16-byte initialization vector

    Returns:
        Encrypted ciphertext
    """
    padded = _pad_pkcs7(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _wrap_key_rsa(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt AES key with RSA public key using PKCS1v15.

    Args:
        symmetric_key: The AES key to wrap
        public_key: Device's RSA public key

    Returns:
        RSA-encrypted key
    """
    return public_key.encrypt(symmetric_key, padding.PKCS1v15())


def encrypt_config(
    config_xml: str | bytes,
    device_name: str,
    device_cert: x509.Certificate | str | bytes,
    signer_cert: x509.Certificate | str | bytes,
    signer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | str | bytes,
) -> bytes:
    """Encrypt a configuration file for a specific device.

    The encrypted file can only be decrypted by the device that holds
    the private key corresponding to device_cert.

    Args:
        config_xml: XML configuration content
        device_name: Device identifier (e.g., "SEP001122334455")
        device_cert: Device's X.509 certificate (LSC)
        signer_cert: Signer's X.509 certificate
        signer_key: Signer's private key for signing

    Returns:
        Encrypted .enc.sgn file as bytes

    Raises:
        ValueError: If device certificate doesn't have RSA public key
    """
    # Normalize inputs
    if isinstance(config_xml, str):
        config_xml = config_xml.encode("utf-8")

    if isinstance(device_cert, (str, bytes)):
        if isinstance(device_cert, str):
            device_cert = device_cert.encode("utf-8")
        device_cert = x509.load_pem_x509_certificate(device_cert)

    if isinstance(signer_cert, (str, bytes)):
        if isinstance(signer_cert, str):
            signer_cert = signer_cert.encode("utf-8")
        signer_cert = x509.load_pem_x509_certificate(signer_cert)

    if isinstance(signer_key, (str, bytes)):
        if isinstance(signer_key, str):
            signer_key = signer_key.encode("utf-8")
        signer_key = serialization.load_pem_private_key(signer_key, password=None)

    # Validate device has RSA key (phones use RSA for config decryption)
    device_public_key = device_cert.public_key()
    if not isinstance(device_public_key, rsa.RSAPublicKey):
        raise ValueError(
            f"Device certificate must have RSA public key, got {type(device_public_key)}"
        )

    # Generate random AES key and IV
    aes_key = os.urandom(AES_KEY_SIZE)
    aes_iv = os.urandom(AES_IV_SIZE)

    # Encrypt the config
    encrypted_data = _encrypt_aes_cbc(config_xml, aes_key, aes_iv)

    # Wrap the AES key with device's public key
    encrypted_key = _wrap_key_rsa(aes_key, device_public_key)

    # Build the encryption block
    enc_writer = TLVWriter()
    enc_writer.write_string(EncryptedConfigTag.DEVICE_NAME, device_name)
    enc_writer.write_bytes(EncryptedConfigTag.ENCRYPTED_KEY, encrypted_key)
    enc_writer.write_bytes(EncryptedConfigTag.IV, aes_iv)
    enc_writer.write_bytes(EncryptedConfigTag.ENCRYPTED_DATA, encrypted_data)

    encryption_block = enc_writer.getvalue()

    # Build header
    header_writer = TLVWriter()
    # File ID: 0x0002 indicates encrypted config
    header_writer.write_uint16(EncryptedConfigTag.FILE_ID, 0x0002)

    # Reserved padding (16 bytes of zeros)
    header_writer.write_bytes(EncryptedConfigTag.RESERVED, bytes(16))

    header = header_writer.getvalue()

    # Data to sign (header + encryption block)
    data_to_sign = header + encryption_block

    # Sign with signer's key
    if isinstance(signer_key, rsa.RSAPrivateKey):
        signature = signer_key.sign(
            data_to_sign,
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
            data_to_sign,
            ec.ECDSA(hash_obj),
        )
    else:
        raise ValueError(f"Unsupported signer key type: {type(signer_key)}")

    # Calculate total length and rebuild with length field
    # Length = header + encryption_block + signature TLV
    sig_tlv_len = 1 + 2 + len(signature)  # tag + length + value
    total_payload_len = len(encryption_block) + sig_tlv_len

    # Final assembly
    final_writer = TLVWriter()
    final_writer.write_uint16(EncryptedConfigTag.FILE_ID, 0x0002)
    final_writer.write_uint32(EncryptedConfigTag.FILE_LENGTH, total_payload_len)
    final_writer.write_bytes(EncryptedConfigTag.RESERVED, bytes(16))

    # Add encryption block
    final_writer.write_raw(encryption_block)

    # Add signature
    final_writer.write_bytes(EncryptedConfigTag.SIGNATURE, signature)

    return final_writer.getvalue()


def decrypt_config(
    encrypted_data: bytes,
    device_private_key: rsa.RSAPrivateKey | str | bytes,
) -> bytes:
    """Decrypt an encrypted configuration file.

    This is primarily for testing - real decryption happens on the phone.

    Args:
        encrypted_data: The .enc.sgn file contents
        device_private_key: Device's RSA private key

    Returns:
        Decrypted XML configuration

    Raises:
        ValueError: If file format is invalid or decryption fails
    """
    if isinstance(device_private_key, (str, bytes)):
        if isinstance(device_private_key, str):
            device_private_key = device_private_key.encode("utf-8")
        device_private_key = serialization.load_pem_private_key(
            device_private_key, password=None
        )

    if not isinstance(device_private_key, rsa.RSAPrivateKey):
        raise ValueError("Device private key must be RSA")

    from usecallmanager_capf.security.tlv import parse_tlv

    offset = 0
    encrypted_key = None
    iv = None
    ciphertext = None

    # Parse TLV elements
    while offset < len(encrypted_data):
        try:
            tag, length, value, next_offset = parse_tlv(encrypted_data, offset)
        except ValueError:
            break

        if tag == EncryptedConfigTag.ENCRYPTED_KEY:
            encrypted_key = value
        elif tag == EncryptedConfigTag.IV:
            iv = value
        elif tag == EncryptedConfigTag.ENCRYPTED_DATA:
            ciphertext = value

        offset = next_offset

    if not encrypted_key or not iv or not ciphertext:
        raise ValueError("Missing required encryption fields in file")

    # Decrypt the AES key
    aes_key = device_private_key.decrypt(encrypted_key, padding.PKCS1v15())

    # Decrypt the config
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    padding_len = padded[-1]
    return padded[:-padding_len]
