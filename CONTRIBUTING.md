# Contributing Guidelines – argusprowl

Thank you for contributing to **argusprowl**! Please follow these guidelines to maintain high code quality and architectural integrity.

## Development Standards

### 1. Code Quality & Formatting
- **Python Version**: Python 3.13+
- **Code Style**: PEP8 compliant.
- **Linter**: **Ruff** (configured in `pyproject.toml`). Run `uv run ruff check src/ tests/` before committing.
- **Type Annotations**: Mandatory explicit type hints on all function parameters and return values.

### 2. Design Principles
- **SOLID**: Maintain Single Responsibility for every class.
- **Clean Architecture**: Never import outer framework dependencies directly into core model or interface files.
- **No Global Mutables**: Avoid global variables or unconstrained shared state.
- **No Circular Imports**: Keep module dependencies unidirectional.

### 3. Testing Requirements
- Every new feature or module must include comprehensive `pytest` tests under `tests/`.
- Ensure all tests pass before submitting a Pull Request:
  ```bash
  uv run pytest
  ```

### 4. Dependencies
- Runtime dependencies live in `pyproject.toml` (`[project] dependencies`) and are
  resolved through the committed `uv.lock`. Dev-only tooling lives in
  `[dependency-groups] dev`. Do not add a parallel `requirements.txt`.

### 5. Git & Commit Guidelines
- Commit messages should be descriptive and concise:
  - `feat(config): add environment variable override support`
  - `fix(events): prevent subscriber exception from blocking dispatch`
  - `docs(arch): update Clean Architecture layer diagram`
