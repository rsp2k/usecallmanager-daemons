"""CAPF service runner - combines binary protocol server with FastAPI."""

import asyncio
import logging
import sys
from concurrent.futures import ThreadPoolExecutor

import uvicorn

from usecallmanager_capf.api.app import create_app
from usecallmanager_capf.config import CapfConfig
from usecallmanager_capf.db.database import get_session, init_db
from usecallmanager_capf.db.repository import DeviceRepository
from usecallmanager_capf.protocol.server import CapfServer

# Global config for health check access
_config: CapfConfig | None = None

logger = logging.getLogger(__name__)


class CapfService:
    """Main service that runs both protocol and API servers."""

    def __init__(self, config: CapfConfig):
        global _config
        _config = config
        self.config = config
        self.protocol_server: CapfServer | None = None
        self.executor: ThreadPoolExecutor | None = None

    def _setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format="%(name)s %(message)s",
            stream=sys.stdout,
            force=True,
        )

    def _run_protocol_server(self):
        """Run the binary protocol server in a thread."""
        try:
            # Get thread-local session
            session = get_session(self.config.database_url)
            repository = DeviceRepository(session)

            self.protocol_server = CapfServer(
                port=self.config.protocol_port,
                timeout=self.config.timeout,
                capf_certificate_file=str(self.config.tls_cert_file),
                issuer_certificate_file=str(self.config.get_issuer_cert_file()),
                verify_certificate_files=[str(f) for f in self.config.verify_cert_files],
                certificates_dir=str(self.config.certificates_dir),
                validity_days=self.config.validity_days,
                allow_tlsv1=self.config.allow_tlsv1,
                repository=repository,
                client_limit=self.config.client_limit,
            )
            self.protocol_server.run()
        except Exception as e:
            logger.error("Protocol server error: %s", e)
            raise

    async def start(self):
        """Start both servers."""
        self._setup_logging()

        logger.info("Starting CAPF service...")
        logger.info("Protocol port: %d", self.config.protocol_port)
        logger.info("API port: %d", self.config.api_port)
        logger.info("Database: %s", self.config.database_url)
        logger.info("Certificates dir: %s", self.config.certificates_dir)

        # Initialize database
        init_db(self.config.database_url)

        # Ensure certificates directory exists
        self.config.certificates_dir.mkdir(parents=True, exist_ok=True)

        # Create repository for API
        session = get_session(self.config.database_url)
        repository = DeviceRepository(session)

        # Create FastAPI app
        app = create_app(repository)

        # Start protocol server in dedicated thread
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="capf-protocol")
        loop = asyncio.get_event_loop()
        protocol_task = loop.run_in_executor(self.executor, self._run_protocol_server)

        # Start FastAPI server
        api_config = uvicorn.Config(
            app,
            host=self.config.api_host,
            port=self.config.api_port,
            log_level=self.config.log_level.lower(),
        )
        api_server = uvicorn.Server(api_config)

        try:
            await asyncio.gather(
                protocol_task,
                api_server.serve(),
            )
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.protocol_server:
                self.protocol_server.stop()
            if self.executor:
                self.executor.shutdown(wait=False)


def main():
    """Entry point."""
    try:
        from importlib.metadata import version

        package_version = version("usecallmanager-daemons")
    except Exception:
        package_version = "4.0.0"

    print(f"CAPF (Certificate Authority Proxy Function) v{package_version}")

    config = CapfConfig()
    service = CapfService(config)
    asyncio.run(service.start())


if __name__ == "__main__":
    main()
