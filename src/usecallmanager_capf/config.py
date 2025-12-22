"""Configuration for CAPF service."""

from pathlib import Path

from pydantic_settings import BaseSettings


class CapfConfig(BaseSettings):
    """CAPF service configuration via environment variables."""

    # Protocol settings
    protocol_port: int = 3804
    tls_cert_file: Path = Path("/certs/capf.pem")
    issuer_cert_file: Path | None = None  # Defaults to tls_cert_file
    verify_cert_files: list[Path] = []
    timeout: int = 10
    client_limit: int = 0
    allow_tlsv1: bool = False
    validity_days: int = 365

    # API settings
    api_port: int = 8082
    api_host: str = "0.0.0.0"

    # Database and storage
    database_url: str = "sqlite:////var/lib/capf/capf.sqlite3"
    certificates_dir: Path = Path("/var/lib/capf/certificates")

    # Logging
    log_level: str = "INFO"

    model_config = {"env_prefix": "CAPF_", "env_file": ".env", "extra": "ignore"}

    def get_issuer_cert_file(self) -> Path:
        """Get the issuer certificate file, defaulting to TLS cert."""
        return self.issuer_cert_file or self.tls_cert_file
