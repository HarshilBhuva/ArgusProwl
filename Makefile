.PHONY: test lint frontend-install frontend-test frontend-lint frontend-build deploy stop clean

test:
	uv run pytest

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

frontend-install:
	cd frontend && npm ci

frontend-test:
	cd frontend && npx vitest run

frontend-lint:
	cd frontend && npm run lint

frontend-build:
	cd frontend && npm run build

deploy:
	docker compose up -d --build

stop:
	docker compose down

# Stop services without deleting persisted volumes or application data.
clean: stop
