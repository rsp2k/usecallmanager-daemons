# TVS (Trust Verification Service) Dockerfile
FROM ghcr.io/astral-sh/uv:0.5-python3.12-bookworm-slim AS base

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Dev stage - with hot reload
FROM base AS dev
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --frozen --no-install-project || true

COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen || uv sync

EXPOSE 2445 8081

CMD ["uv", "run", "usecallmanager-tvs"]

# Prod stage - optimized
FROM base AS prod
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --frozen --no-dev --no-editable --no-install-project || true

COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable || uv sync --no-dev

# Create non-root user
RUN useradd --create-home --shell /bin/bash --uid 1000 tvs && \
    mkdir -p /var/lib/tvs && \
    chown -R tvs:tvs /var/lib/tvs /app

USER tvs

EXPOSE 2445 8081

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8081/api/v1/health || exit 1

CMD ["uv", "run", "usecallmanager-tvs"]
