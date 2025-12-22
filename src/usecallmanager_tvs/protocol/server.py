"""TVS TLS server implementation.

Handles binary protocol communication with Cisco IP phones for certificate verification.
"""

import binascii
import logging
import re
import select
import signal
import socket
import ssl
import struct
import threading
import traceback
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes

from usecallmanager_tvs.protocol.constants import (
    COMMAND_VERIFY_REQUEST,
    COMMAND_VERIFY_RESPONSE,
    ELEMENT_CERTIFICATE,
    ELEMENT_DEVICE_NAME,
    ELEMENT_ROLES,
    ELEMENT_STATUS,
    ELEMENT_TTL,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    ROLE_NAME_TO_BYTE,
    STATUS_INVALID,
    STATUS_VALID,
)

if TYPE_CHECKING:
    from usecallmanager_tvs.db.repository import CertificateRepository

logger = logging.getLogger(__name__)


class ProtocolError(Exception):
    """Error in protocol handling."""


class TvsServer:
    """TVS TLS server that handles certificate verification requests."""

    def __init__(
        self,
        port: int,
        timeout: int,
        tvs_certificate_file: str,
        allow_tlsv1: bool = False,
        repository: "CertificateRepository | None" = None,
        client_limit: int = 0,
    ):
        self.port = port
        self.timeout = timeout
        self.repository = repository
        self.client_limit = client_limit
        self.server_socket: socket.socket | None = None
        self._running = False

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.verify_mode = ssl.CERT_NONE

        if allow_tlsv1:
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1
            ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0")
            logger.warning("TLSv1.0 connections are vulnerable to CVE-2014-3566")

        try:
            ssl_context.load_cert_chain(tvs_certificate_file)
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

        logger.info("TVS protocol server listening on port %d", port)

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
        connection = TvsConnection(client_socket, self.repository, self.client_limit)
        connection.run()


class TvsConnection:
    """Handles a single TVS client connection."""

    client_count = 0
    _lock = threading.Lock()

    def __init__(
        self,
        client_socket: socket.socket,
        repository: "CertificateRepository | None" = None,
        client_limit: int = 0,
    ):
        with TvsConnection._lock:
            TvsConnection.client_count += 1

        self.client_socket = client_socket
        self.repository = repository
        self.client_limit = client_limit
        self.session_id: int | None = None

    def __del__(self):
        with TvsConnection._lock:
            TvsConnection.client_count -= 1
        self.client_socket.close()

    def run(self):
        """Handle the client connection."""
        if self.client_limit and TvsConnection.client_count > self.client_limit:
            logger.info("Too many clients: %d of %d", TvsConnection.client_count, self.client_limit)
            return

        try:
            command, elements = self._receive_request()

            if command != COMMAND_VERIFY_REQUEST:
                raise ProtocolError(f"Unexpected command: {command}")

            self._verify_certificate(elements)

        except ProtocolError as error:
            logger.info("Protocol error: %s", error)
        except Exception:
            logger.error("%s", traceback.format_exc())

    def _send_response(self, command: int, elements: dict):
        """Send a response to the client."""
        response = b""

        status = elements.get(ELEMENT_STATUS)
        if status is not None:
            response += struct.pack("> B H B", ELEMENT_STATUS, 1, status)

        roles = elements.get(ELEMENT_ROLES)
        if roles is not None:
            response += struct.pack("> B H", ELEMENT_ROLES, len(roles)) + roles

        ttl = elements.get(ELEMENT_TTL)
        if ttl is not None:
            response += struct.pack("> B H I", ELEMENT_TTL, 4, ttl)

        header = struct.pack(
            "> B B B B I H",
            PROTOCOL_ID,
            PROTOCOL_VERSION,
            command,
            0,
            self.session_id,
            len(response),
        )
        self.client_socket.sendall(header + response)

    def _receive_request(self) -> tuple[int, dict]:
        """Receive a request from the client."""
        request = self.client_socket.recv(10)

        if not len(request):
            raise ProtocolError("Client closed socket")

        if len(request) != 10:
            raise ProtocolError("Invalid header length")

        protocol_id, version, command, session_id, request_length = struct.unpack_from(
            "> B B B x I H", request, 0
        )

        if protocol_id != PROTOCOL_ID:
            raise ProtocolError(f"Invalid protocol ID: {protocol_id}")

        if version > PROTOCOL_VERSION:
            raise ProtocolError(f"Invalid protocol version: {version}")

        if self.session_id is None:
            self.session_id = session_id
        elif session_id != self.session_id:
            raise ProtocolError(f"Mismatched session ID: {session_id}")

        request = b""

        while len(request) < request_length:
            request_chunk = self.client_socket.recv(request_length - len(request))
            if not len(request_chunk):
                break
            request += request_chunk

        if len(request) != request_length:
            raise ProtocolError("Truncated request")

        elements = {}
        index = 0

        while index < len(request):
            tag, length = struct.unpack_from("> B H", request, index)
            index += 3

            if tag == ELEMENT_DEVICE_NAME:
                device_name = request[index : index + length]
                device_name = device_name[1:].decode("utf-8")
                elements[ELEMENT_DEVICE_NAME] = device_name
            elif tag == ELEMENT_CERTIFICATE:
                certificate = request[index : index + length]
                elements[ELEMENT_CERTIFICATE] = certificate
            else:
                raise ProtocolError(f"Unknown element tag: {tag}")

            index += length

        return command, elements

    def _verify_certificate(self, elements: dict):
        """Verify a certificate and send the response."""
        device_name = elements.get(ELEMENT_DEVICE_NAME)

        if device_name is None:
            raise ProtocolError("No device name")

        if not re.search(r"(?x) ^ CP - [0-9]{4} - SEP [0-9A-F]{12} $", device_name):
            raise ProtocolError(f"Invalid device name: {device_name}")

        logger.info("Device Name: %s", device_name)

        certificate_data = elements.get(ELEMENT_CERTIFICATE)

        if certificate_data is None:
            raise ProtocolError("Missing certificate element")

        try:
            certificate = x509.load_der_x509_certificate(certificate_data, backends.default_backend())
        except ValueError as e:
            raise ProtocolError("Invalid certificate") from e

        serial_number = certificate.serial_number
        serial_number_bytes = serial_number.to_bytes((serial_number.bit_length() + 7) // 8, byteorder="big")
        serial_number_hex = binascii.hexlify(serial_number_bytes).decode("utf-8")

        subject_name = ",".join([attr.rfc4514_string() for attr in certificate.subject])
        issuer_name = ",".join([attr.rfc4514_string() for attr in certificate.issuer])

        certificate_hash = certificate.fingerprint(hashes.SHA256())
        certificate_hash_hex = binascii.hexlify(certificate_hash).decode("utf-8")

        logger.info("Subject Name: %s", subject_name)
        logger.info("Issuer Name: %s", issuer_name)
        logger.info("Serial Number: %s", serial_number_hex)
        logger.info("Certificate Hash: %s", certificate_hash_hex)

        # Look up certificate in database
        if self.repository is None:
            logger.warning("No repository configured, rejecting certificate")
            self._send_response(COMMAND_VERIFY_RESPONSE, {ELEMENT_STATUS: STATUS_INVALID})
            return

        cert_record = self.repository.get_by_hash(certificate_hash_hex)

        if cert_record is None:
            logger.info("Status: Invalid")
            self._send_response(COMMAND_VERIFY_RESPONSE, {ELEMENT_STATUS: STATUS_INVALID})
            return

        logger.info("Status: Valid")
        logger.info("Roles: %s", cert_record.roles)
        logger.info("TTL: %d", cert_record.ttl)

        # Encode roles as bytes
        roles = b""
        for role in cert_record.roles.split(","):
            role = role.strip()
            if role in ROLE_NAME_TO_BYTE:
                roles += struct.pack("B", ROLE_NAME_TO_BYTE[role])

        self._send_response(
            COMMAND_VERIFY_RESPONSE,
            {
                ELEMENT_STATUS: STATUS_VALID,
                ELEMENT_ROLES: roles,
                ELEMENT_TTL: cert_record.ttl,
            },
        )
