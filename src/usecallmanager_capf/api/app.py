"""FastAPI application factory for CAPF."""

from fastapi import FastAPI

from usecallmanager_capf.api import routes
from usecallmanager_capf.db.repository import DeviceRepository


def create_app(repository: DeviceRepository) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(
        title="CAPF API",
        description="Certificate Authority Proxy Function REST API for managing devices",
        version="4.0.0",
    )

    # Override the repository dependency
    def get_repository():
        return repository

    app.dependency_overrides[routes.get_repository] = get_repository

    # Include routes
    app.include_router(routes.router, prefix="/api/v1", tags=["devices"])

    return app
