# Threat_Hunter → argusprowl-community Consolidation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the single-commit `Threat_Hunter/main` into the actively-developed `argusprowl-community/main` preserving both histories, keep Apache-2.0 license and runtime ATT&CK download, clean up stale artifacts, and leave a clean working tree ready for a new GitHub repo named `ArgusProwl`.

**Architecture:** `argusprowl-community` is the canonical repo (46 commits, current). `Threat_Hunter/main` is a historical snapshot pushed separately; it adds two docs (`productization.md`, `single-process.md`) and an outdated README but no code newer than what's already in local. A merge commit preserves provenance. All merge conflicts resolve to the local version.

**Tech Stack:** Python 3.13, FastAPI, React/TypeScript, pytest, ruff, Docker, GitHub Actions.

**Spec:** `docs/superpowers/plans/YYYY-MM-DD-threat-hunter-merge.md` — this document.

## Global Constraints

- Canonical history on `main` is never rewritten or force-pushed.
- Work is done on a dedicated branch; `main` remains untouched until the user approves the final result.
- License stays Apache-2.0; no MIT badge change.
- ATT&CK snapshot stays out of the repo (runtime download only); do not add `assets/attck/enterprise-attack-18.1.json` from Threat_Hunter.
- `.orig` files and orphaned symlinks are removed from git tracking.
- Runtime databases (`data/*.db`), logs, `.venv`, `node_modules`, `frontend/dist`, and `frontend/node_modules` stay out of version control.
- Pre-merge test/lint baseline passes before any merge touch.

---

### Task 1: Establish pre-merge baseline

**Files:** none (read-only verification)

- [ ] **Step 1: Verify local baseline is clean and tests pass**

Run these commands and record results before touching anything:
```bash
git status --short
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q --tb=short
npx --prefix frontend tsc --noEmit -p frontend/tsconfig.app.json
npx --prefix frontend vitest run
```

All must pass with zero failures. If any fail, fix them first on this branch before merging (report failures back to the user; do not proceed until the baseline is green).

- [ ] **Step 2: Record baseline hashes for audit trail**

```bash
git rev-parse HEAD > /tmp/baseline-local-head.txt
git log --oneline | head -1 >> /tmp/baseline-local-head.txt
echo "Baseline HEAD: $(cat /tmp/baseline-local-head.txt)"
```

---

### Task 2: Add Threat_Hunter as remote and inspect

**Files:** git metadata only

- [ ] **Step 1: Add remote and fetch**

```bash
git remote add threat-hunter https://github.com/HarshilBhuva/Threat_Hunter.git
git fetch threat-hunter
git branch -r | grep threat-hunter
```

Expected: `threat-hunter/main` at commit `9eb6b78`.

- [ ] **Step 2: Dry-run the merge to confirm conflict list**

```bash
git merge --no-commit --no-ff threat-hunter/main
git diff --name-only --diff-filter=U
```

Record the conflicted files. Expected conflict set: `README.md`, `.gitignore`, `Dockerfile`, `.github/workflows/backend-ci.yml`, `.github/workflows/docker-build.yml`, `.github/workflows/frontend-ci.yml`, `frontend/vite.config.ts`, `src/argusprowl/core/application.py`, `tests/integration/test_application.py`, `tests/integration/test_docker_product.py`, `pyproject.toml` (license field), `assets/attck/enterprise-attack-18.1.json` (new file, handled below), plus any new-from-remote files.

- [ ] **Step 3: Abort the dry-run**

```bash
git merge --abort
```

Verify clean state is restored: `git status` shows no changes.

---

### Task 3: Execute the merge with conflict resolution strategy

**Files:** ~12 conflict targets + ~15 new files from Threat_Hunter

Strategy per file type:
- **Code files** (`src/**`, `tests/**`, `scripts/**`): always take **ours** (local) — these are newer and tested.
- **CI workflows** (`.github/workflows/*.yml`): always take **ours**.
- **Config files** (`Dockerfile`, `pyproject.toml`, `frontend/vite.config.ts`): always take **ours**.
- **`.gitignore`**: always take **ours** (remote contains garbage lines like `h path` and `h`).
- **`README.md`**: take **ours** (more accurate current description).
- **`assets/attck/enterprise-attack-18.1.json`**: **delete** — user chose runtime download. Stage as deleted even though local doesn't have it (the merge will try to add the 46 MB file; we reject it).
- **`docs/productization.md`** and **`docs/single-process.md`**: **accept** — new docs from Threat_Hunter not in local.
- **All other new files from Threat_Hunter** (frontend pages, tests, scripts): **accept** — they supplement local.

- [ ] **Step 1: Start the real merge**

```bash
git merge --no-edit threat-hunter/main
```

- [ ] **Step 2: Resolve all conflicts by keeping local (ours)**

For each conflicted file, run:
```bash
git checkout --ours <filepath>
git add <filepath>
```

Apply to this exact list:
```
README.md
.gitignore
Dockerfile
.github/workflows/backend-ci.yml
.github/workflows/docker-build.yml
.github/workflows/frontend-ci.yml
frontend/vite.config.ts
src/argusprowl/core/application.py
tests/integration/test_application.py
tests/integration/test_docker_product.py
pyproject.toml
```

- [ ] **Step 3: Reject the bundled ATT&CK snapshot**

```bash
git rm assets/attck/enterprise-attack-18.1.json 2>/dev/null || true
rm -f assets/attck/enterprise-attack-18.1.json
# Ensure the directory stays (may be empty) but is tracked if it has a .gitkeep
ls assets/attck/
```

If `assets/attck/` is now empty and has no `.gitkeep`, remove the empty dir:
```bash
rmdir assets/attck 2>/dev/null || true
```

- [ ] **Step 4: Accept new docs from Threat_Hunter**

```bash
git add docs/productization.md docs/single-process.md
```

Verify they exist:
```bash
ls -la docs/productization.md docs/single-process.md
head -3 docs/productization.md
head -3 docs/single-process.md
```

- [ ] **Step 5: Accept all other new files from Threat_Hunter**

The merge should have auto-added most files. Verify no unmerged files remain:
```bash
git diff --name-only --diff-filter=U
```

If the output is empty, all conflicts are resolved. If not, resolve any remaining with `git checkout --ours <file>` and `git add <file>`.

- [ ] **Step 6: Commit the merge**

```bash
git commit --no-edit 2>/dev/null || git status
```

If the merge auto-committed (no commit needed because no conflicts remained — unlikely but possible), verify with:
```bash
git log --oneline -3
```

Expected: top commit is a merge commit with both parents.

---

### Task 4: Clean up stale artifacts

**Files:** gitworking tree (delete only)

- [ ] **Step 1: Remove `.orig` backup files from git tracking**

These files are leftover development artifacts with no references in code:
```bash
git rm --cached frontend/src/lib/api.ts.orig frontend/src/types/api.ts.orig 2>/dev/null || true
rm -f frontend/src/lib/api.ts.orig frontend/src/types/api.ts.orig
```

Verify they're gone:
```bash
find frontend/src -name "*.orig" -type f
git ls-files | grep "\.orig"
```

Both must be empty.

- [ ] **Step 2: Remove the orphaned `rules` symlink**

No code in `src/`, `tests/`, `config/`, or `scripts/` references the `rules/` path — all use `config/rules`. The symlink is redundant.

```bash
git rm rules
rm rules
```

Verify nothing broke:
```bash
grep -rn '"rules"' src/ tests/ config/ scripts/ 2>/dev/null
ls config/rules/
```

The grep must return nothing. `config/rules/` must still list all YAML rule files.

- [ ] **Step 3: Verify .gitignore catches the right things**

Confirm these are all ignored (not staged):
```bash
git status --short
```

Expected: no `node_modules/`, `__pycache__/`, `.venv/`, `frontend/node_modules/`, `frontend/dist/`, `*.db`, `*.log`, `.pytest_cache/`, `.ruff_cache/`, `.vite/`, `frontend/.vite/` in the output. If any leak through, add them to `.gitignore` (take the existing local version which is correct).

---

### Task 5: Validate the merged repository

**Files:** none (read-only verification)

- [ ] **Step 1: Full test suite**

```bash
uv run pytest -q --tb=short
```

All tests must pass. If any fail, diagnose and fix before proceeding — do not ship a broken merge.

- [ ] **Step 2: Linting**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
```

Zero violations expected.

- [ ] **Step 3: TypeScript check**

```bash
npx --prefix frontend tsc --noEmit -p frontend/tsconfig.app.json
```

Zero errors.

- [ ] **Step 4: Frontend unit tests**

```bash
npx --prefix frontend vitest run
```

All pass.

- [ ] **Step 5: Docker build smoke test**

```bash
docker compose build --no-cache 2>&1 | tail -20
```

Build must succeed. Do not run `docker compose up` — just verify the image builds.

- [ ] **Step 6: Final git status**

```bash
git status --short
git log --oneline -5
```

Working tree must be clean (no uncommitted changes). Log must show the merge commit at the top.

---

### Task 6: Deliverables summary for user review

- [ ] **Step 1: Print the final state**

```bash
echo "=== Branch ===" && git branch --show-current
echo "=== Top 5 commits ===" && git log --oneline -5
echo "=== Conflict count ===" && git rev-list --merges --count HEAD
echo "=== Total commits ===" && git rev-list --count HEAD
echo "=== Added docs ===" && ls docs/productization.md docs/single-process.md
echo "=== Removed: orig files ===" && find frontend/src -name "*.orig"
echo "=== Removed: rules symlink ===" && test -L rules && echo "SYMLINK STILL EXISTS" || echo "CLEAN"
echo "=== Assets ATT&CK ===" && ls -la assets/attck/ 2>/dev/null || echo "DIR EMPTY OR REMOVED"
echo "=== License ===" && head -3 LICENSE
echo "=== Remote list ===" && git remote -v
echo "=== Working tree ===" && git status --short
```

Copy this output to the user and ask for approval before any push or new-remote creation.

---

### What NOT to do (guardrails)

- Do **not** force-push `main` or rewrite any existing commit history.
- Do **not** create the new GitHub repo — the user will do that after review.
- Do **not** change the license from Apache-2.0.
- Do **not** bundle `assets/attck/enterprise-attack-18.1.json` into the merged tree.
- Do **not** add `.orig` files back or restore the `rules` symlink.
- Do **not** push until the user explicitly approves the final state.
