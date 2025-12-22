"""FastAPI application factory for TVS."""

from fastapi import FastAPI

from usecallmanager_tvs.api import routes
from usecallmanager_tvs.db.repository import CertificateRepository


def create_app(repository: CertificateRepository) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(
        title="TVS API",
        description="Trust Verification Service REST API for managing certificates",
        version="4.0.0",
    )

    # Override the repository dependency
    def get_repository():
        return repository

    app.dependency_overrides[routes.get_repository] = get_repository

    # Include routes
    app.include_router(routes.router, prefix="/api/v1", tags=["certificates"])

    return app
