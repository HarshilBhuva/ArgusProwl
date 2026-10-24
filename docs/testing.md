# TESTING GUIDELINES — argusprowl

## Core Principles

### 1. Preparation Before Code Changes
Before modifying code or adding features:
1. **Locate Production Implementation**: Trace the active class/function in `src/argusprowl/`.
2. **Locate Existing Tests**: Search `tests/` for existing test coverage of the component.
3. **Trace Runtime Path**: Understand how data flows through the component in production.
4. **Inspect Fixtures**: Check existing fixtures in `tests/conftest.py` or local test files.
5. **Identify Invariants**: Understand the invariants being asserted.
6. **Reuse Test Infrastructure**: Reuse `mock_config`, `sample_event`, and established fixtures before creating new ones.

### 2. Test Design & Scoping
- **Unit Tests**: Test individual functions, math models, and isolated logic (e.g., periodicity calculations, severity mapping).
- **Integration Tests**: Test interaction across boundaries (e.g., `Parser` -> `NormalizedEvent`, `Detector` -> `DetectionResult`).
- **E2E Tests**: Use sparingly—only when verifying end-to-end pipeline processing across all stages.
- **Rule**: Do not write E2E tests for logic that can be deterministically validated via unit/integration tests.

### 3. Deterministic Synchronization
- **No Arbitrary Delays**: Never use `time.sleep(...)` as a synchronization primitive.
- **Synchronization Mechanics**: Use `threading.Event`, bounded polling with explicit timeouts, or direct mock clock manipulation (`time.monotonic` patching).
- **No Infinite Waits**: Every lock, wait, or queue read in tests must specify an explicit timeout.

### 4. Comprehensive Test Coverage (Positive & Negative)
Every detector, parser, or analytical model must include test cases for:
- **Positive Detection**: Expected malicious/anomalous condition triggers alert.
- **Near-Miss / Threshold Boundary**: Behavior just below detection threshold does not trigger.
- **Benign Suppression**: Common benign patterns (e.g., HTTP/HTTPS polling on port 80/443, NTP on port 123) are explicitly suppressed.
- **Insufficient Evidence**: Insufficient observations or duration yield no detection.
- **Malformed Input**: Missing fields, corrupt JSON/log lines, unexpected types handle gracefully.
- **Duplicate & Out-of-Order Delivery**: Re-delivering identical `source_record_id` does not corrupt metrics or inflate counts.

### 5. Critical Integrity Rules
- **NEVER Modify Tests to Pass Broken Code**: Never change test assertions or lower production detection thresholds simply because a test failed.
- **Diagnose Root Cause**: Determine if failure is due to implementation error, invalid fixture, environmental issue, or wrong test assumption.
- **Maintain Production Thresholds**: Production parameters (e.g., beaconing periodicity threshold `0.70`, min observations `10`) must not be weakened in tests to force pass state.

### 6. Live vs Replay Equivalence
Features operating on temporal or stateful logic must verify:
- **Semantic Equivalence**: `ReplayEngine` output must match `DetectionManager` live output for identical input logs.
- **Real Parsers**: Replay tests must use production log parsers, not mock log dictionaries.
- **State Isolation**: Independent replay runs must maintain separate, non-leaking temporal state.

### 7. Execution & Verification Workflow
1. **Targeted Run**: Run tests for the specific module under edit:
   ```bash
   uv run pytest -q tests/unit/test_<module>.py  # or tests/integration/test_<module>.py when applicable
   ```
2. **Full Regression Suite**: Verify no regressions across the codebase:
   ```bash
   uv run pytest -q
   ```
3. **Project Diagnostics & Hygiene**:
   ```bash
   uv run python -m compileall -q src tests scripts
   uv run python -m argusprowl validate-config
   uv run python -m argusprowl health
   git diff --check
   ```
