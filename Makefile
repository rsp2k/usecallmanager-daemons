.PHONY: help build up down logs shell lint test clean dev prod certs frontend-dev frontend-build frontend-install

# Load .env file if it exists
-include .env
export

COMPOSE = docker compose
MODE ?= prod

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Development
dev: MODE=dev ## Start in development mode
dev: up

prod: MODE=prod ## Start in production mode
prod: up

up: ## Start services
	$(COMPOSE) up -d --build
	$(COMPOSE) logs -f

down: ## Stop services
	$(COMPOSE) down

logs: ## Show logs
	$(COMPOSE) logs -f

logs-tvs: ## Show TVS logs
	$(COMPOSE) logs -f tvs

logs-capf: ## Show CAPF logs
	$(COMPOSE) logs -f capf

logs-frontend: ## Show frontend logs
	$(COMPOSE) logs -f frontend

shell-tvs: ## Shell into TVS container
	$(COMPOSE) exec tvs bash

shell-capf: ## Shell into CAPF container
	$(COMPOSE) exec capf bash

shell-frontend: ## Shell into frontend container
	$(COMPOSE) exec frontend sh

# Build
build: ## Build containers
	$(COMPOSE) build

rebuild: ## Rebuild containers without cache
	$(COMPOSE) build --no-cache

# Linting
lint: ## Run ruff linter
	uv run ruff check src/

lint-fix: ## Run ruff linter with fixes
	uv run ruff check --fix src/

format: ## Format code with ruff
	uv run ruff format src/

# Testing
test: ## Run tests
	uv run pytest

# Certificates
certs: certs/tvs/tvs.pem certs/capf/capf.pem ## Generate self-signed certificates

certs/tvs/tvs.pem:
	@mkdir -p certs/tvs
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-keyout certs/tvs/tvs.pem -out certs/tvs/tvs.pem \
		-subj "/CN=TVS/O=UseCallManager"
	@echo "Generated TVS certificate: certs/tvs/tvs.pem"

certs/capf/capf.pem:
	@mkdir -p certs/capf
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-keyout certs/capf/capf.pem -out certs/capf/capf.pem \
		-subj "/CN=CAPF/O=UseCallManager"
	@echo "Generated CAPF certificate: certs/capf/capf.pem"

# Cleanup
clean: ## Clean up containers and volumes
	$(COMPOSE) down -v --remove-orphans

clean-all: clean ## Clean everything including images
	$(COMPOSE) down -v --rmi all --remove-orphans

# Local development (without Docker)
run-tvs: ## Run TVS locally
	uv run usecallmanager-tvs

run-capf: ## Run CAPF locally
	uv run usecallmanager-capf

# Frontend
frontend-install: ## Install frontend dependencies
	cd frontend && npm ci

frontend-dev: ## Run frontend in dev mode (local)
	cd frontend && npm run dev

frontend-build: ## Build frontend
	cd frontend && npm run build

# Utilities
sync: ## Sync dependencies
	uv sync

lock: ## Update lock file
	uv lock

# Database inspection
db-tvs: ## Open TVS database
	sqlite3 /var/lib/tvs/tvs.sqlite3

db-capf: ## Open CAPF database
	sqlite3 /var/lib/capf/capf.sqlite3
