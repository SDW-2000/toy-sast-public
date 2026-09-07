.PHONY: doctor install up down logs migrate bootstrap-admin lint typecheck test test-frontend test-backend verify-analyzer compose-check smoke

doctor:
	./scripts/doctor.sh

install:
	pnpm install --frozen-lockfile
	cd backend && uv sync --frozen --group dev --no-group analyzer

up:
	docker compose up --build --detach

down:
	docker compose down

logs:
	docker compose logs --follow

migrate:
	docker compose run --rm --build migration

bootstrap-admin:
	@test -n "$(ADMIN_EMAIL)" || (echo "Usage: make bootstrap-admin ADMIN_EMAIL=admin@example.com" && exit 1)
	docker compose run --rm api python -m app.bootstrap_admin --email "$(ADMIN_EMAIL)"

lint:
	pnpm lint
	cd backend && uv run ruff check .

typecheck:
	pnpm typecheck
	cd backend && uv run mypy app tests

test: test-frontend test-backend

test-frontend:
	pnpm test

test-backend:
	cd backend && uv run pytest

verify-analyzer:
	docker compose run --rm worker-analyzer /analyzer/scripts/verify-languages.sh

compose-check:
	docker compose config --quiet

smoke:
	./scripts/smoke.sh
