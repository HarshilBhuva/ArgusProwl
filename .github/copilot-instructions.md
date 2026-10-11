# Copilot instructions for Threat Hunter

## Python environment rule

Before running any Python command in this workspace, always check whether a project-local virtual environment exists at `.venv`.

Use the project environment for Python work:
- Prefer `.venv/bin/python`
- Prefer `.venv/bin/pytest`
- Prefer `.venv/bin/python -m ...` for module execution

Do not run bare `python`, `pytest`, or other Python entrypoints against the system interpreter when a workspace virtual environment is available.

If `.venv` is missing, stop and inform the user rather than running Python commands with the global environment. If appropriate, suggest creating the environment before continuing.

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
