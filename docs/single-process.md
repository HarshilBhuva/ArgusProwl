# Single-Process Local Product Architecture

## Overview

argusprowl runs as a single Python process on `127.0.0.1:8080` that serves both the
FastAPI backend and the React production frontend from `frontend/dist/`. No separate Vite
dev server, no npm, no process-group management — one port, one process, one shutdown.

## Route Map

| Pattern | Handler | Behaviour |
|---------|---------|-----------|
| `/api/v1/*` | FastAPI route table | JSON API responses |
| `/docs`, `/redoc`, `/openapi.json` | FastAPI built-in | Swagger / ReDoc / OpenAPI JSON |
| `/assets/{path:path}` | `serve_frontend_file()` | Static asset from `frontend/dist/assets/` |
| `/{path:path}` (catch-all) | `serve_spa()` | `index.html` for unknown UI routes |

## Frontend Serving

`src/argusprowl/api/frontend_serving.py` provides:

- **`serve_frontend_file(path: str)`** — resolves the request against `frontend/dist/`,
  checks for path traversal (`..` components, dotfiles), returns
  `(content: bytes | None, content_type: str | None, status: int)`.
- **`validate_frontend_build()`** — raises `RuntimeError` when `frontend/dist/` does not
  exist, used as a hard gate at startup.

The SPA catch-all never intercepts `/api/`, `/docs`, `/redoc`, or `/openapi.json` paths;
these always route to the FastAPI machinery.

## Application Lifecycle

```
scripts/start
  └── python -m argusprowl start
        └── Application.startup(start_api=False)
              ├── Load config
              ├── Wire DI container
              ├── Start processing loop + collectors
              └── create_api_app() → validates frontend/dist
                    └── Application.run_foreground(host, port)
                          └── uvicorn.run(api_app)  # blocks
```

`create_api_app()` validates the frontend build at factory time, so a missing build
produces a clear startup error instead of a silent 404.

## Configuration

- `scripts/start` sets `BACKEND_HOST=127.0.0.1` and `BACKEND_PORT=8080` (from env
  `BACKEND_PORT`).
- `ApiConfig` defaults: `enabled=True, host="127.0.0.1", port=8080`.
- `--config` arg is passed through to the `argusprowl` CLI.

## Startup Gate

`scripts/start` checks port availability before launching. If 8080 is occupied, it
prints an error and exits without starting anything. A `trap` on SIGINT/SIGTERM exits
the process cleanly.

## Missing Build Fallback

If `frontend/dist/` is absent:
- `validate_frontend_build()` raises `RuntimeError` at `create_api_app()` call time.
- The error propagates through `Application.startup()` as a `LifecycleError`.
- `argusprowl` CLI prints the error and exits with a non-zero code.

The launcher never starts an empty server or falls back to a placeholder.

## Related Documents

- [[Architecture]]
