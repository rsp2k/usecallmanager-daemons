"""CAPF TLS server implementation.

Handles binary protocol communication with Cisco IP phones for certificate enrollment.
"""

import binascii
import logging
import os
import select
import signal
import socket
import ssl
import struct
import threading
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import oid

from usecallmanager_capf.protocol.constants import (
    AUTH_TYPE_NONE,
    CERTIFICATE_TYPE_LSC,
    COMMAND_AUTH_REQUEST,
    COMMAND_AUTH_RESPONSE,
    COMMAND_DELETE_CERTIFICATE_REQUEST,
    COMMAND_DELETE_CERTIFICATE_RESPONSE,
    COMMAND_END_SESSION,
    COMMAND_FETCH_CERTIFICATE_REQUEST,
    COMMAND_FETCH_CERTIFICATE_RESPONSE,
    COMMAND_KEY_GENERATE_REQUEST,
    COMMAND_KEY_GENERATE_RESPONSE,
    COMMAND_REQUEST_IN_PROGRESS,
    COMMAND_STORE_CERTIFICATE_REQUEST,
    COMMAND_STORE_CERTIFICATE_RESPONSE,
    CURVE_NAME_TO_BYTE,
    ELEMENT_AUTH_TYPE,
    ELEMENT_CERTIFICATE,
    ELEMENT_CERTIFICATE_TYPE,
    ELEMENT_CURVE,
    ELEMENT_DEVICE_NAME,
    ELEMENT_KEY_SIZE,
    ELEMENT_KEY_TYPE,
    ELEMENT_PASSWORD,
    ELEMENT_PUBLIC_KEY,
    ELEMENT_REASON,
    ELEMENT_REASON_INFO,
    ELEMENT_SHA2_SIGNED_DATA,
    ELEMENT_SIGNED_DATA,
    ELEMENT_SUDI_DATA,
    ELEMENT_VERSION,
    HASH_SHA512,
    KEY_TYPE_EC,
    KEY_TYPE_RSA,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    REASON_INVALID_ELEMENT,
    REASON_NO_ACTION,
    REASON_UNKNOWN_DEVICE,
    REASON_UPDATE_CERTIFICATE,
)

if TYPE_CHECKING:
    from usecallmanager_capf.db.repository import DeviceRepository

logger = logging.getLogger(__name__)


class ProtocolError(Exception):
    """Error in protocol handling."""


class CapfServer:
    """CAPF TLS server that handles certificate enrollment requests."""

    def __init__(
        self,
        port: int,
        timeout: int,
        capf_certificate_file: str,
        issuer_certificate_file: str,
        verify_certificate_files: list[str] | None = None,
        certificates_dir: str = "/var/lib/capf/certificates",
        validity_days: int = 365,
        allow_tlsv1: bool = False,
        repository: "DeviceRepository | None" = None,
        client_limit: int = 0,
    ):
        self.port = port
        self.timeout = timeout
        self.repository = repository
        self.client_limit = client_limit
        self.issuer_certificate_file = issuer_certificate_file
        self.verify_certificate_files = verify_certificate_files or []
        self.certificates_dir = Path(certificates_dir)
        self.validity_days = validity_days
        self.server_socket: socket.socket | None = None
        self._running = False

        # Ensure certificates directory exists
        self.certificates_dir.mkdir(parents=True, exist_ok=True)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.verify_mode = ssl.CERT_NONE

        if allow_tlsv1:
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1
            ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0")
            logger.warning("TLSv1.0 connections are vulnerable to CVE-2014-3566")

        try:
            ssl_context.load_cert_chain(capf_certificate_file)
        except (PermissionError, FileNotFoundError, IsADirectoryError) as error:
            raise ProtocolError(f"{error.strerror}: {error.filename}") from error

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.settimeout(timeout)
            self.server_socket = ssl_context.wrap_socket(self.server_socket, server_side=True)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(5)
        except ssl.SSLError as error:
            raise ProtocolError(error.reason) from error
        except OSError as error:
            raise ProtocolError(error.strerror) from error

        logger.info("CAPF protocol server listening on port %d", port)

    def __del__(self):
        if self.server_socket is not None:
            self.server_socket.close()

    def run(self):
        """Run the server main loop."""
        poll = select.poll()
        poll.register(self.server_socket.fileno(), select.POLLIN)

        self._running = True

        # Only register signal handlers if in main thread (for standalone use)
        # When run as part of the async service, signals are handled by the service
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
                signal.signal(signum, self._shutdown)

        try:
            while self._running:
                events = poll.poll(60)

                for fileno, event in events:
                    if fileno != self.server_socket.fileno() or not event & select.POLLIN:
                        continue

                    try:
                        client_socket, _ = self.server_socket.accept()
                        ip_address, port = client_socket.getpeername()
                    except OSError as error:
                        logger.error("Accept error: %s", error.strerror)
                        continue

                    thread = threading.Thread(
                        daemon=True,
                        name=f"{ip_address}:{port}",
                        target=self._client_connection,
                        args=(client_socket,),
                    )
                    thread.start()

        except InterruptedError:
            pass
        finally:
            self._running = False

    def stop(self):
        """Stop the server."""
        self._running = False

    def _shutdown(self, signum, frame):
        raise InterruptedError

    def _client_connection(self, client_socket: socket.socket):
        connection = CapfConnection(
            client_socket=client_socket,
            repository=self.repository,
            client_limit=self.client_limit,
            issuer_certificate_file=self.issuer_certificate_file,
            verify_certificate_files=self.verify_certificate_files,
            certificates_dir=self.certificates_dir,
            validity_days=self.validity_days,
        )
        connection.run()


class CapfConnection:
    """Handles a single CAPF client connection."""

    client_count = 0
    session_id_counter = 0
    _lock = threading.Lock()

    def __init__(
        self,
        client_socket: socket.socket,
        repository: "DeviceRepository | None" = None,
        client_limit: int = 0,
        issuer_certificate_file: str = "",
        verify_certificate_files: list[str] | None = None,
        certificates_dir: Path = Path("/var/lib/capf/certificates"),
        validity_days: int = 365,
    ):
        with CapfConnection._lock:
            CapfConnection.client_count += 1
            CapfConnection.session_id_counter += 1
            self.session_id = CapfConnection.session_id_counter

        self.client_socket = client_socket
        self.repository = repository
        self.client_limit = client_limit
        self.issuer_certificate_file = issuer_certificate_file
        self.verify_certificate_files = verify_certificate_files or []
        self.certificates_dir = certificates_dir
        self.validity_days = validity_days

    def __del__(self):
        with CapfConnection._lock:
            CapfConnection.client_count -= 1
        self.client_socket.close()

    def run(self):
        """Handle the client connection."""
        if self.client_limit and CapfConnection.client_count > self.client_limit:
            logger.info("Too many clients: %d of %d", CapfConnection.client_count, self.client_limit)
            return

        try:
            # Send initial auth request
            self._send_request(COMMAND_AUTH_REQUEST, {ELEMENT_VERSION: PROTOCOL_VERSION, ELEMENT_AUTH_TYPE: AUTH_TYPE_NONE})

            command, elements = self._receive_response()

            if command != COMMAND_AUTH_RESPONSE:
                raise ProtocolError(f"Unexpected command: {command}")

            version = elements.get(ELEMENT_VERSION)
            if version is not None and version > PROTOCOL_VERSION:
                raise ProtocolError(f"Invalid protocol version: {version}")

            device_name = elements.get(ELEMENT_DEVICE_NAME)
            if device_name is None:
                raise ProtocolError("Missing device name element")

            logger.info("Device Name: %s", device_name)

            if self.repository is None:
                logger.warning("No repository configured")
                self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_UNKNOWN_DEVICE})
                return

            device = self.repository.get_by_name(device_name)

            if device is None:
                logger.info("Unknown device: %s", device_name)
                self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_UNKNOWN_DEVICE})
                return

            logger.info("Authentication Mode: %s", device.authentication.title() if device.authentication else "None")

            # Handle authentication
            if device.authentication == "password":
                password = elements.get(ELEMENT_PASSWORD)
                if device.password != password:
                    raise ProtocolError("Incorrect password")

            elif device.authentication == "certificate":
                certificate = elements.get(ELEMENT_CERTIFICATE)
                signed_data = elements.get(ELEMENT_SIGNED_DATA)
                sha2_signed_data = elements.get(ELEMENT_SHA2_SIGNED_DATA)
                sudi_data = elements.get(ELEMENT_SUDI_DATA)

                self._verify_signed_data(device_name, certificate, signed_data, sha2_signed_data)
                self._verify_sudi_data(sudi_data)

            logger.info("Scheduled Operation: %s", device.operation.title() if device.operation else "None")

            # Execute operation
            if device.operation == "install":
                self._install_certificate(device_name, device.key_size, device.curve_name)
            elif device.operation == "fetch":
                self._fetch_certificate(device_name)
            elif device.operation == "delete":
                self._delete_certificate(device_name)
            elif device.operation == "none":
                self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_NO_ACTION})

        except ProtocolError as error:
            logger.error("Error: %s", error)
            self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_INVALID_ELEMENT})
        except Exception:
            logger.error("%s", traceback.format_exc())

    def _send_request(self, command: int, elements: dict):
        """Send a request to the client."""
        request = b""

        reason = elements.get(ELEMENT_REASON)
        if reason is not None:
            request += struct.pack("> B H B", ELEMENT_REASON, 1, reason)

        certificate_type = elements.get(ELEMENT_CERTIFICATE_TYPE)
        if certificate_type is not None:
            request += struct.pack("> B H B", ELEMENT_CERTIFICATE_TYPE, 1, certificate_type)

        certificate = elements.get(ELEMENT_CERTIFICATE)
        if certificate is not None:
            cert_wrapper = struct.pack("> B H B B", 1, len(certificate) + 2, 0, CERTIFICATE_TYPE_LSC) + certificate
            request += struct.pack("> B H", ELEMENT_CERTIFICATE, len(cert_wrapper)) + cert_wrapper

        version = elements.get(ELEMENT_VERSION)
        if version is not None:
            request += struct.pack("> B H B", ELEMENT_VERSION, 1, version)

        auth_type = elements.get(ELEMENT_AUTH_TYPE)
        if auth_type is not None:
            request += struct.pack("> B H B", ELEMENT_AUTH_TYPE, 1, auth_type)

        key_size = elements.get(ELEMENT_KEY_SIZE)
        if key_size is not None:
            request += struct.pack("> B H H", ELEMENT_KEY_SIZE, 2, key_size)

        key_type = elements.get(ELEMENT_KEY_TYPE)
        if key_type is not None:
            request += struct.pack("> B H B", ELEMENT_KEY_TYPE, 1, key_type)

        curve = elements.get(ELEMENT_CURVE)
        if curve is not None:
            request += struct.pack("> B H B", ELEMENT_CURVE, 1, curve)

        # Send header and body together to avoid phone stalling
        header = struct.pack("> B B I H", PROTOCOL_ID, command, self.session_id, len(request))
        self.client_socket.sendall(header + request)

    def _receive_response(self) -> tuple[int, dict]:
        """Receive a response from the client."""
        response = self.client_socket.recv(8)

        if not len(response):
            raise ProtocolError("Client closed socket")

        if len(response) != 8:
            raise ProtocolError("Invalid header length")

        protocol_id, command, session_id, response_length = struct.unpack("> B B I H", response)

        if protocol_id != PROTOCOL_ID:
            raise ProtocolError(f"Invalid protocol ID: {protocol_id}")

        if session_id != self.session_id:
            raise ProtocolError(f"Mismatched session ID: {session_id}")

        response = b""

        while len(response) < response_length:
            response_chunk = self.client_socket.recv(response_length - len(response))
            if not len(response_chunk):
                break
            response += response_chunk

        if len(response) != response_length:
            raise ProtocolError("Truncated response")

        elements = {}
        index = 0

        while index < len(response):
            tag, length = struct.unpack_from("> B H", response, index)
            index += 3

            if tag == ELEMENT_REASON:
                elements[ELEMENT_REASON] = response[index]
            elif tag == ELEMENT_REASON_INFO:
                elements[ELEMENT_REASON_INFO] = response[index : index + length][:-1].decode("utf-8")
            elif tag == ELEMENT_CERTIFICATE_TYPE:
                elements[ELEMENT_CERTIFICATE_TYPE] = response[index]
            elif tag == ELEMENT_CERTIFICATE:
                elements[ELEMENT_CERTIFICATE] = response[index : index + length][5:]
            elif tag == ELEMENT_SIGNED_DATA:
                elements[ELEMENT_SIGNED_DATA] = response[index : index + length]
            elif tag == ELEMENT_VERSION:
                elements[ELEMENT_VERSION] = response[index]
            elif tag == ELEMENT_PASSWORD:
                elements[ELEMENT_PASSWORD] = response[index : index + length][:-1].decode("utf-8")
            elif tag == ELEMENT_DEVICE_NAME:
                elements[ELEMENT_DEVICE_NAME] = response[index : index + length][:-1].decode("utf-8")
            elif tag == ELEMENT_PUBLIC_KEY:
                elements[ELEMENT_PUBLIC_KEY] = response[index : index + length]
            elif tag == ELEMENT_SUDI_DATA:
                elements[ELEMENT_SUDI_DATA] = response[index : index + length]
            elif tag == ELEMENT_SHA2_SIGNED_DATA:
                elements[ELEMENT_SHA2_SIGNED_DATA] = response[index : index + length]
            else:
                raise ProtocolError(f"Unknown element tag: {tag}")

            index += length

        return command, elements

    def _verify_certificate(self, certificate, cert_type: str):
        """Verify a certificate against known issuers."""
        if certificate is None:
            raise ProtocolError("No certificate")

        subject_name = ",".join([attr.rfc4514_string() for attr in certificate.subject])
        issuer_name = ",".join([attr.rfc4514_string() for attr in certificate.issuer])

        logger.info("%s Subject Name: %s", cert_type, subject_name)
        logger.info("%s Issuer Name: %s", cert_type, issuer_name)

        for verify_file in [self.issuer_certificate_file, *self.verify_certificate_files]:
            try:
                with open(verify_file, "rb") as f:
                    verify_cert_data = f.read()
            except (PermissionError, FileNotFoundError, IsADirectoryError) as error:
                raise ProtocolError(f"{error.strerror}: {error.filename}") from error

            try:
                verify_cert = x509.load_pem_x509_certificate(verify_cert_data, backends.default_backend())
            except ValueError as e:
                raise ProtocolError("Invalid verify certificate") from e

            if certificate.issuer != verify_cert.subject:
                continue

            public_key = verify_cert.public_key()

            try:
                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        certificate.signature_hash_algorithm,
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        ec.ECDSA(certificate.signature_hash_algorithm),
                    )
            except InvalidSignature:
                continue

            return

        raise ProtocolError("Unknown certificate issuer")

    def _verify_signed_data(self, device_name: str, certificate_data: bytes | None, signed_data: bytes | None, sha2_signed_data: bytes | None):
        """Verify signed authentication data."""
        if certificate_data is None:
            raise ProtocolError("No certificate")
        if signed_data is None:
            raise ProtocolError("No signed-data")
        if sha2_signed_data is None:
            raise ProtocolError("No SHA2 signed-data")

        try:
            certificate = x509.load_der_x509_certificate(certificate_data, backends.default_backend())
        except ValueError as e:
            raise ProtocolError("Invalid certificate") from e

        public_key = certificate.public_key()

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise ProtocolError("No RSA or EC public-key in certificate")

        hash_algorithm, sha2_length = struct.unpack_from("> B H", sha2_signed_data)
        sha2_signed_data = sha2_signed_data[3 : 3 + sha2_length]

        if hash_algorithm != HASH_SHA512:
            raise ProtocolError(f"Invalid SHA2 hash-algorithm: {hash_algorithm}")

        self._verify_certificate(certificate, "Authentication")

        auth_data = device_name.encode("utf-8") + b"\x00" + certificate.public_bytes(serialization.Encoding.DER)

        if isinstance(public_key, rsa.RSAPublicKey):
            try:
                self._rsa_public_decrypt(public_key, signed_data, auth_data, hashes.SHA1())
            except ValueError as e:
                raise ProtocolError("Invalid RSA signed-data") from e

            try:
                self._rsa_public_decrypt(public_key, sha2_signed_data, auth_data, hashes.SHA512())
            except ValueError as e:
                raise ProtocolError("Invalid RSA SHA2 signed-data") from e

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                public_key.verify(signed_data, auth_data, ec.ECDSA(hashes.SHA1()))
            except InvalidSignature as e:
                raise ProtocolError("Invalid EC signed-data") from e

            try:
                public_key.verify(sha2_signed_data, auth_data, ec.ECDSA(hashes.SHA512()))
            except InvalidSignature as e:
                raise ProtocolError("Invalid EC SHA2 signed-data") from e

    def _verify_sudi_data(self, sudi_data: bytes | None):
        """Verify SUDI (Secure Unique Device Identifier) data."""
        if sudi_data is None:
            return

        sudi_index = 0

        (sudi_length,) = struct.unpack_from("> x H", sudi_data, sudi_index)
        sudi_index += 3

        certificate_data = sudi_data[sudi_index : sudi_index + sudi_length]
        sudi_index += sudi_length

        (sudi_length,) = struct.unpack_from("> x H", sudi_data, sudi_index)
        sudi_index += 3

        signed_data = sudi_data[sudi_index : sudi_index + sudi_length]
        sudi_index += sudi_length

        hash_algorithm, sudi_length = struct.unpack_from("> B H", sudi_data, sudi_index)
        sudi_index += 3

        sha2_signed_data = sudi_data[sudi_index : sudi_index + sudi_length]

        if hash_algorithm != HASH_SHA512:
            raise ProtocolError(f"Invalid SHA2 hash-algorithm: {hash_algorithm}")

        try:
            certificate = x509.load_der_x509_certificate(certificate_data, backends.default_backend())
        except ValueError as e:
            raise ProtocolError("Invalid SUDI certificate") from e

        public_key = certificate.public_key()

        if not isinstance(public_key, rsa.RSAPublicKey):
            return

        self._verify_certificate(certificate, "SUDI")

        # Cisco's CAPF server uses little-endian for session ID
        auth_data = struct.pack("< I", self.session_id) + certificate.public_bytes(serialization.Encoding.DER)

        try:
            self._rsa_public_decrypt(public_key, signed_data, auth_data, hashes.SHA1())
        except ValueError as e:
            raise ProtocolError("Invalid SUDI RSA signed-data") from e

        try:
            self._rsa_public_decrypt(public_key, sha2_signed_data, auth_data, hashes.SHA512())
        except ValueError as e:
            raise ProtocolError("Invalid SUDI RSA SHA2 signed-data") from e

    def _rsa_public_decrypt(self, public_key: rsa.RSAPublicKey, signed_data: bytes, auth_data: bytes, hash_algorithm):
        """Verify RSA signature using public key decryption."""
        public_numbers = public_key.public_numbers()

        hash_obj = hashes.Hash(hash_algorithm, backends.default_backend())
        hash_obj.update(auth_data)
        auth_data_hash = hash_obj.finalize()

        signed_int = int.from_bytes(signed_data, byteorder="big")
        decrypted_int = pow(signed_int, public_numbers.e, public_numbers.n)
        decrypted = decrypted_int.to_bytes(public_key.key_size // 8, byteorder="big")

        # Remove PKCS1 type 1 padding
        decrypted = decrypted[-len(auth_data_hash) :]

        if decrypted != auth_data_hash:
            raise ValueError("Signature verification failed")

    def _install_certificate(self, device_name: str, key_size: int | None, curve_name: str | None):
        """Install a new certificate on the device."""
        if key_size:
            logger.info("Key Algorithm: RSA")
            logger.info("Key Size: %d", key_size)

            self._send_request(COMMAND_KEY_GENERATE_REQUEST, {ELEMENT_KEY_TYPE: KEY_TYPE_RSA, ELEMENT_KEY_SIZE: key_size})

        elif curve_name:
            logger.info("Key Algorithm: EC")
            logger.info("Curve: %s", curve_name)

            curve = CURVE_NAME_TO_BYTE.get(curve_name, 0)
            self._send_request(COMMAND_KEY_GENERATE_REQUEST, {ELEMENT_KEY_TYPE: KEY_TYPE_EC, ELEMENT_CURVE: curve})

        else:
            raise ProtocolError("No key size or curve specified")

        command, elements = self._receive_response()

        if command == COMMAND_REQUEST_IN_PROGRESS:
            command, elements = self._receive_response()

        if command != COMMAND_KEY_GENERATE_RESPONSE:
            raise ProtocolError(f"Unexpected command: {command}")

        public_key_data = elements.get(ELEMENT_PUBLIC_KEY)

        if public_key_data is None:
            reason = elements.get(ELEMENT_REASON, -1)
            logger.info("Error: Key generation failed (%d)", reason)
            self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_INVALID_ELEMENT})
            return

        # Load issuer certificate and key
        try:
            with open(self.issuer_certificate_file, "rb") as f:
                issuer_data = f.read()
        except (PermissionError, FileNotFoundError, IsADirectoryError) as error:
            raise ProtocolError(f"{error.strerror}: {error.filename}") from error

        try:
            issuer_certificate = x509.load_pem_x509_certificate(issuer_data, backends.default_backend())
        except ValueError as e:
            raise ProtocolError(f"No certificate in file: {self.issuer_certificate_file}") from e

        try:
            issuer_private_key = serialization.load_pem_private_key(issuer_data, None, backends.default_backend())
        except ValueError as e:
            raise ProtocolError(f"No private key in file: {self.issuer_certificate_file}") from e

        # Build certificate
        builder = x509.CertificateBuilder()

        subject_attrs = [x509.NameAttribute(oid.NameOID.COMMON_NAME, device_name)]
        for attr in issuer_certificate.subject:
            if attr.oid in (
                oid.NameOID.ORGANIZATION_NAME,
                oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
                oid.NameOID.LOCALITY_NAME,
                oid.NameOID.STATE_OR_PROVINCE_NAME,
                oid.NameOID.COUNTRY_NAME,
            ):
                subject_attrs.append(attr)

        builder = builder.subject_name(x509.Name(subject_attrs))
        builder = builder.issuer_name(issuer_certificate.issuer)

        public_key = serialization.load_der_public_key(public_key_data, backends.default_backend())
        builder = builder.public_key(public_key)

        serial_number = int.from_bytes(os.urandom(16), byteorder="big")
        builder = builder.serial_number(serial_number)

        not_valid_before = datetime.now(UTC)
        builder = builder.not_valid_before(not_valid_before)

        not_valid_after = datetime.now(UTC) + timedelta(days=self.validity_days)
        builder = builder.not_valid_after(not_valid_after)

        # Extensions
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # 1.3.6.1.5.5.7.3.5 is IPsec End System
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    oid.ObjectIdentifier("1.3.6.1.5.5.7.3.5"),
                ]
            ),
            critical=False,
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(device_name)]),
            critical=False,
        )

        certificate = builder.sign(issuer_private_key, hashes.SHA256(), backends.default_backend())

        # Update database
        serial_number_int = certificate.serial_number
        serial_number_bytes = serial_number_int.to_bytes((serial_number_int.bit_length() + 7) // 8, byteorder="big")
        serial_number_hex = binascii.hexlify(serial_number_bytes).decode("utf-8")

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        self.repository.update_after_install(
            device_name=device_name,
            serial_number=serial_number_hex,
            certificate=cert_pem,
            not_valid_before=certificate.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
            not_valid_after=certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Save to file
        cert_file = self.certificates_dir / f"{device_name}.pem"
        try:
            cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        except (PermissionError, IsADirectoryError) as error:
            raise ProtocolError(f"{error.strerror}: {error.filename}") from error

        logger.info("Result: Installed certificate")

        # Send certificate to device
        self._send_request(
            COMMAND_STORE_CERTIFICATE_REQUEST,
            {
                ELEMENT_CERTIFICATE_TYPE: CERTIFICATE_TYPE_LSC,
                ELEMENT_CERTIFICATE: certificate.public_bytes(serialization.Encoding.DER),
            },
        )

        command, elements = self._receive_response()

        if command != COMMAND_STORE_CERTIFICATE_RESPONSE:
            raise ProtocolError(f"Unexpected command: {command}")

        reason = elements.get(ELEMENT_REASON, -1)
        if reason != REASON_UPDATE_CERTIFICATE:
            logger.info("Error: Failed to store certificate (%d)", reason)

        self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_UPDATE_CERTIFICATE})

    def _fetch_certificate(self, device_name: str):
        """Fetch the current certificate from the device."""
        self._send_request(COMMAND_FETCH_CERTIFICATE_REQUEST, {})
        command, elements = self._receive_response()

        if command != COMMAND_FETCH_CERTIFICATE_RESPONSE:
            raise ProtocolError(f"Unexpected command: {command}")

        reason = elements.get(ELEMENT_REASON, -1)

        if reason != REASON_UPDATE_CERTIFICATE:
            logger.info("Error: Fetch certificate failed (%d)", reason)
        else:
            certificate_data = elements.get(ELEMENT_CERTIFICATE)

            if certificate_data is None:
                raise ProtocolError("Missing certificate element")

            try:
                certificate = x509.load_der_x509_certificate(certificate_data, backends.default_backend())
            except ValueError as e:
                raise ProtocolError("Invalid certificate") from e

            serial_number_int = certificate.serial_number
            serial_number_bytes = serial_number_int.to_bytes((serial_number_int.bit_length() + 7) // 8, byteorder="big")
            serial_number_hex = binascii.hexlify(serial_number_bytes).decode("utf-8")

            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

            self.repository.update_after_install(
                device_name=device_name,
                serial_number=serial_number_hex,
                certificate=cert_pem,
                not_valid_before=certificate.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
                not_valid_after=certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # Save to file
            cert_file = self.certificates_dir / f"{device_name}.pem"
            try:
                cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            except (PermissionError, IsADirectoryError) as error:
                raise ProtocolError(f"{error.strerror}: {error.filename}") from error

            logger.info("Result: Fetched certificate")

        self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_NO_ACTION})

    def _delete_certificate(self, device_name: str):
        """Delete the certificate from the device."""
        self._send_request(COMMAND_DELETE_CERTIFICATE_REQUEST, {})
        command, elements = self._receive_response()

        if command != COMMAND_DELETE_CERTIFICATE_RESPONSE:
            raise ProtocolError(f"Unexpected command: {command}")

        reason = elements.get(ELEMENT_REASON, -1)

        if reason != REASON_UPDATE_CERTIFICATE:
            logger.info("Error: Delete certificate failed (%d)", reason)
        else:
            self.repository.update_after_delete(device_name)

            # Remove file
            cert_file = self.certificates_dir / f"{device_name}.pem"
            if cert_file.exists():
                try:
                    cert_file.unlink()
                except (PermissionError, IsADirectoryError) as error:
                    raise ProtocolError(f"{error.strerror}: {error.filename}") from error

            logger.info("Result: Deleted certificate")

        self._send_request(COMMAND_END_SESSION, {ELEMENT_REASON: REASON_UPDATE_CERTIFICATE})
