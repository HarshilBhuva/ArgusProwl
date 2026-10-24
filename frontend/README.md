# ArgusProwl frontend

The frontend is a React + TypeScript application built with Vite. The production build is served by the FastAPI application from `frontend/dist/`.

## Development

From this directory:

```bash
npm ci
npm run dev
```

## Validation

```bash
npx vitest run
npm run lint
npm run build
```

The repository also contains Playwright configuration and end-to-end tests. Run `npx playwright test` when the required browser dependencies and application test environment are available.
