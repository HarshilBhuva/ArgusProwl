# Copilot instructions for ArgusProwl

## Python environment rule

Use the repository-managed environment for Python work:
- Prefer `uv run python ...`, `uv run pytest ...`, and `uv run ruff ...`.
- Run `uv sync` first when dependencies are not installed.
- Do not bypass the project dependency lockfile by installing arbitrary packages into the system interpreter.

## Report output preference

When the user asks for a report, prefer returning a copyable text block directly in chat rather than creating a markdown file on disk unless the user explicitly asks for a file or a specific path.

Default behavior:
- Provide the report inline in the chat response as plain copyable text.
- Keep it concise, structured, and easy to paste into issues, docs, or notes.
- Use markdown headings and bullets when helpful, but keep it copy-friendly.

Only create a `.md` file when:
- the user specifically requests a file location,
- the task explicitly says to save the report to a path, or
- the user asks for a durable artifact in the workspace.

## Scope

This instruction applies to all Python-based development, validation, and test commands in this repository, and to report-generation requests made in this project.
