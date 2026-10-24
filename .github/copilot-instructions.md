# Copilot instructions for ArgusProwl

## Environment and dependencies

- Use the repository-managed Python environment: `uv run ...`.
- Run `uv sync --group dev` when dependencies need to be installed or updated.
- Keep `pyproject.toml` and `uv.lock` in sync; do not add a parallel `requirements.txt`.
- Use Node.js 22 and `npm ci` for frontend work.

## Validation

- Backend tests: `uv run pytest -q`.
- Backend lint: `uv run ruff check src tests`.
- Python formatting: `uv run ruff format --check src tests`.
- Frontend tests: `cd frontend && npx vitest run`.
- Frontend lint and build: `cd frontend && npm run lint && npm run build`.
- Configuration validation: `uv run python -m argusprowl validate-config`.

## Repository boundaries

- Keep changes scoped to the community product and its verified capabilities.
- Do not add generated runtime state, local databases, logs, secrets, or downloaded ATT&CK datasets to commits.
- Prefer updating maintained user/developer documentation over adding planning notes or placeholder reports.
- Do not claim checks passed unless they were run and their results were observed.
