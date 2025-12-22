"""Configuration for TVS service."""

from pathlib import Path

from pydantic_settings import BaseSettings


class TvsConfig(BaseSettings):
    """TVS service configuration via environment variables."""

    # Protocol settings
    protocol_port: int = 2445
    tls_cert_file: Path = Path("/certs/tvs.pem")
    timeout: int = 10
    client_limit: int = 0
    allow_tlsv1: bool = False

    # API settings
    api_port: int = 8081
    api_host: str = "0.0.0.0"

    # Database
    database_url: str = "sqlite:////var/lib/tvs/tvs.sqlite3"

    # Logging
    log_level: str = "INFO"

    model_config = {"env_prefix": "TVS_", "env_file": ".env", "extra": "ignore"}
