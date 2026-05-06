# AISA InvestigationWorkdirService Implementation Plan

Date: 2026-04-25
Lane: `agent-workflow` crossing `web-surface`, daemon/runtime, and case-memory only as needed
Status: planned

## 1. Purpose

Add a AISA-native `InvestigationWorkdirService` that gives each agent investigation a safe, local-first workspace for structured artifacts, intermediate evidence, logs, and resumable investigation state.

The design is inspired by Vigil `WorkdirManager`, but must be adapted to AISA's runtime boundaries:

- AISA is local-first by default.
- Deterministic analyzers, scoring, and evidence paths remain authoritative for verdicts and scores.
- Agent workflows may organize, summarize, and persist investigation context, but must not silently become the source of final verdict truth.
- Missing optional wiring must degrade honestly without breaking IOC, file, email, chat, or case workflows.

## 2. Goals

- Create a dedicated service in `CABTA/src/agent/investigation_workdir.py` for managing per-investigation working directories.
- Provide deterministic filesystem contracts for creation, safe reads/writes, JSON helpers, append-only event logs, artifact manifests, and archival.
- Integrate with `CABTA/src/agent/agent_loop.py` so sessions can create and use a workdir without forcing all agent runs to depend on it.
- Support case-memory linkage by recording workdir references and artifact summaries in existing case/session metadata where appropriate.
- Support optional web dependency injection in `CABTA/src/web/app.py` only if needed for route/runtime reuse.
- Keep artifact layout stable enough for future daemon/headless runs without introducing a daemon requirement in this phase.
- Add focused tests under `CABTA/tests/` that validate service behavior, security guardrails, and agent-loop integration seams.

## 3. Non-goals

- Do not implement analyzer, scoring, or verdict changes.
- Do not make LLM-generated files authoritative for final threat verdicts.
- Do not introduce cloud storage, external object stores, or mandatory network dependencies.
- Do not add a new database table unless later implementation discovers that existing stores cannot hold minimal references.
- Do not build a full UI for browsing workdirs in the initial service implementation.
- Do not execute files, malware, scripts, or generated commands from the workdir.
- Do not copy Vigil runtime architecture wholesale; use only the useful workdir-management concept.

## 4. Existing reference and adaptation

Vigil reference: `vigil/daemon/workdir.py` contains `WorkdirManager`, which provides:

- per-investigation directory creation
- required default files
- evidence subdirectories
- safe path resolution
- text and JSON read/write helpers
- append-only `log.jsonl`
- disk usage and archive helpers

AISA adaptation:

- Rename and scope the concept as `InvestigationWorkdirService` under CABTA agent code.
- Use AISA naming and metadata keys, not Vigil keys.
- Prefer `CABTA/.cabta-runtime/investigations/` or existing runtime-data config conventions if already centralized during implementation.
- Make the service injectable and optional, not globally required.
- Add stricter artifact schema and path guardrails because CABTA may handle malware samples, email attachments, logs, and analyst-provided evidence.
- Keep all persisted workdir data local to the AISA host.

## 5. Architecture

### 5.1 Service responsibility

`InvestigationWorkdirService` owns filesystem lifecycle and artifact metadata for investigation workdirs. It should not own investigation reasoning, case selection, final verdict decisions, tool execution, or web route logic.

Primary responsibilities:

- Normalize and validate investigation identifiers.
- Create or hydrate a per-investigation directory.
- Create required files and subdirectories.
- Safely resolve paths under the investigation directory.
- Read and write text and JSON files with bounded behavior.
- Append structured event records to `events.jsonl`.
- Register artifacts in `artifacts/index.json`.
- Summarize workspace state for case-memory checkpoints.
- Archive or close a workdir when an investigation session ends.

### 5.2 Proposed directory layout

Default root:

```text
.cabta-runtime/investigations/
  {investigation_id}/
    manifest.json
    state.json
    plan.md
    context.md
    events.jsonl
    review.md
    artifacts/
      index.json
      evidence/
      enrichments/
      query-results/
      uploads/
      reports/
      scratch/
    exports/
    _archive/
```

Notes:

- The implementation should avoid committing generated runtime workdirs.
- If AISA already has a runtime-root helper or config key, use that instead of hardcoding.
- `scratch/` is non-authoritative temporary workspace material and must be labeled as such in metadata.
- `evidence/`, `enrichments/`, and `query-results/` may contain artifacts from deterministic tools and external integrations, but the workdir itself does not decide verdicts.

### 5.3 Required files

- `manifest.json`: stable metadata about the workdir and schema version.
- `state.json`: mutable service-owned state for resumability.
- `plan.md`: agent-readable investigation plan or analyst task framing.
- `context.md`: case/session context snapshot intended for agent prompts or review.
- `events.jsonl`: append-only operational event log for workdir actions.
- `review.md`: analyst-facing notes, caveats, and manual review placeholders.
- `artifacts/index.json`: artifact registry and summaries.

### 5.4 Service API sketch

Implementation should keep the public API small and testable:

```python
class InvestigationWorkdirService:
    def __init__(self, base_dir: str | Path | None = None, *, max_file_bytes: int | None = None): ...
    def create_or_get(self, investigation_id: str, *, case_id: str | None = None, session_id: str | None = None, thread_id: str | None = None) -> Path: ...
    def exists(self, investigation_id: str) -> bool: ...
    def get_path(self, investigation_id: str) -> Path: ...
    def read_text(self, investigation_id: str, relative_path: str) -> str: ...
    def write_text(self, investigation_id: str, relative_path: str, content: str, *, artifact_kind: str | None = None) -> dict: ...
    def append_text(self, investigation_id: str, relative_path: str, content: str) -> dict: ...
    def read_json(self, investigation_id: str, relative_path: str, default: object | None = None) -> object: ...
    def write_json(self, investigation_id: str, relative_path: str, payload: object, *, artifact_kind: str | None = None) -> dict: ...
    def register_artifact(self, investigation_id: str, *, relative_path: str, artifact_type: str, source: str, authoritative: bool = False, metadata: dict | None = None) -> dict: ...
    def append_event(self, investigation_id: str, event_type: str, payload: dict | None = None) -> None: ...
    def summarize(self, investigation_id: str) -> dict: ...
    def archive(self, investigation_id: str) -> Path | None: ...
```

The exact method names can be refined during implementation, but the service should remain filesystem-focused and not absorb agent-loop control flow.

## 6. Artifact schema

### 6.1 `manifest.json`

Required fields:

```json
{
  "schema_version": "1.0",
  "product": "AISA",
  "investigation_id": "string",
  "case_id": "string|null",
  "session_id": "string|null",
  "thread_id": "string|null",
  "created_at": "iso-8601",
  "updated_at": "iso-8601",
  "status": "active|closed|archived",
  "runtime": {
    "local_first": true,
    "verdict_authority": "deterministic_aisa_scoring"
  }
}
```

### 6.2 `state.json`

Recommended fields:

```json
{
  "schema_version": "1.0",
  "phase": "initialized|running|waiting_human|completed|failed",
  "last_step": 0,
  "latest_tool": null,
  "active_focus": null,
  "deterministic_decision_refs": [],
  "agentic_notes_refs": [],
  "open_questions": []
}
```

### 6.3 `artifacts/index.json`

Recommended fields:

```json
{
  "schema_version": "1.0",
  "artifacts": [
    {
      "id": "artifact-local-id",
      "relative_path": "artifacts/evidence/example.json",
      "artifact_type": "tool_result|query_result|enrichment|upload|report|scratch|agent_note",
      "source": "investigate_ioc|analyze_malware|agent_loop|analyst_upload|mcp_tool",
      "created_at": "iso-8601",
      "updated_at": "iso-8601",
      "size_bytes": 0,
      "sha256": "optional-for-file-content",
      "mime_type": "application/json",
      "authoritative": false,
      "verdict_boundary": "non_authoritative|deterministic_evidence_ref|deterministic_decision_ref",
      "metadata": {}
    }
  ]
}
```

### 6.4 `events.jsonl`

Each line should be valid JSON:

```json
{
  "ts": "iso-8601",
  "product": "AISA",
  "investigation_id": "string",
  "case_id": "string|null",
  "session_id": "string|null",
  "event_type": "workdir_created|artifact_registered|state_updated|workdir_archived",
  "payload": {}
}
```

## 7. Security guardrails

- Block path traversal with resolved-path containment checks.
- Validate `investigation_id` against a conservative allowlist such as alphanumeric, underscore, dash, and dot, or map unsafe external IDs to safe slugs.
- Reject absolute paths for workdir-relative operations.
- Reject symlink escapes; do not follow symlinks outside the workdir.
- Bound read/write sizes through configurable `max_file_bytes` for text and JSON helpers.
- Use UTF-8 for text and JSON; binary artifacts should be registered by path and handled cautiously.
- Never execute any file in the workdir.
- Treat uploaded or extracted files as untrusted, especially malware samples and email attachments.
- Avoid storing secrets, raw API keys, bearer tokens, or provider credentials in `context.md`, `events.jsonl`, or artifact metadata.
- Redact obvious secrets in event payloads if the service receives raw tool parameters.
- Ensure archive operations stay inside the configured base directory.
- Use append-only events for auditability; avoid destructive deletion helpers in the initial implementation.

## 8. Deterministic verdict boundary

The service must preserve AISA's verdict boundary:

- Deterministic analyzers and scoring remain the authoritative source for final verdicts and numeric scores.
- Workdir artifacts may reference deterministic tool outputs and scoring payloads, but they do not create authoritative verdicts on their own.
- Agent notes, `plan.md`, `context.md`, `review.md`, and scratch artifacts are interpretive or operational unless explicitly referencing deterministic result IDs.
- Artifact metadata should include `authoritative` and `verdict_boundary` fields so downstream readers can distinguish deterministic evidence from agentic explanation.
- `AgentLoop` may use workdir context to improve continuity, but final answers must continue to respect existing deterministic-decision resolution paths.

## 9. Integration points

### 9.1 `CABTA/src/agent/investigation_workdir.py`

Create the new service here. Keep it dependency-light and suitable for unit tests.

Implementation guidance:

- Use `pathlib.Path`.
- Use atomic-ish write patterns where practical for JSON files, such as writing to a sibling temporary file then replacing.
- Keep corrupt JSON handling explicit and non-silent; return defaults with warning metadata or raise a narrow service exception depending on method semantics.
- Add a small exception hierarchy only if needed, such as `InvestigationWorkdirError` and `UnsafeWorkdirPathError`.

### 9.2 `CABTA/src/agent/agent_loop.py`

Integrate as an optional dependency:

- Add an optional constructor parameter such as `investigation_workdir_service=None`.
- Store it as `self.investigation_workdir_service`.
- When a session/investigation starts, derive an investigation ID from existing session ID, case ID, or thread ID in a stable way.
- Create or hydrate a workdir only when the service is available.
- Record minimal checkpoint artifacts after tool observations or final summaries only if that does not change existing control flow.
- Do not make workdir failures fail the agent loop; log and continue with degraded behavior unless a caller explicitly opts into strict mode.

### 9.3 `CABTA/src/web/app.py`

Only modify if dependency injection is needed:

- Initialize `InvestigationWorkdirService` during app creation alongside other agent services.
- Store it on `app.state.investigation_workdir_service`.
- Pass it into `AgentLoop` construction where the app currently wires agent dependencies.
- Preserve graceful startup if service initialization fails; log a warning and keep the app usable.

### 9.4 Case memory integration

Prefer minimal, additive integration:

- Store workdir summary references in existing session/case metadata or checkpoint payloads.
- Suggested shape:

```json
{
  "investigation_workdir": {
    "investigation_id": "string",
    "relative_root": ".cabta-runtime/investigations/string",
    "manifest_ref": "manifest.json",
    "artifact_count": 0,
    "last_event_type": "state_updated",
    "verdict_boundary": "deterministic_scoring_remains_authoritative"
  }
}
```

- Avoid copying large artifact contents into case memory.
- Case memory should link to workdir summaries, not replace artifact storage.

### 9.5 Daemon/headless runtime

This plan does not require a daemon implementation. However, the service should be safe for future daemon use:

- No FastAPI dependency in the service.
- No global event loop assumptions.
- No mandatory web app state.
- Configurable base directory.
- Stable archive and summarize methods.

## 10. Phased implementation

### Phase 1 — Service foundation

- Add `CABTA/src/agent/investigation_workdir.py`.
- Implement initialization, ID validation, safe path resolution, workdir creation, required files, required subdirectories, and basic read/write helpers.
- Add focused unit tests for creation, required layout, safe path blocking, JSON read/write, and corrupt JSON behavior.

### Phase 2 — Artifact and event contracts

- Add `register_artifact`, `append_event`, `summarize`, disk usage, and archive behavior.
- Ensure artifact metadata includes authority and verdict-boundary fields.
- Add tests for artifact index creation, append-only events, summary shape, size accounting, and archive containment.

### Phase 3 — Agent-loop optional integration

- Add optional service injection to `CABTA/src/agent/agent_loop.py`.
- Create or hydrate workdirs for agent sessions only when available.
- Persist lightweight context/state checkpoints without changing final verdict resolution.
- Add tests proving the agent loop runs when the service is absent and records summaries when present.

### Phase 4 — Web dependency injection if needed

- If the web runtime constructs `AgentLoop`, initialize the service in `CABTA/src/web/app.py` and pass it through.
- Preserve graceful degradation if initialization fails.
- Add focused app-factory or route-level tests only if web wiring is touched.

### Phase 5 — Case-memory linkage

- Add minimal workdir summary references to existing checkpoint/session metadata if useful for analyst continuity.
- Avoid large payload duplication.
- Add tests under `CABTA/tests/` for case-memory reference shape if `CaseMemoryService` or checkpoint payloads are touched.

### Phase 6 — Documentation and validation

- Update CABTA docs only if the implementation changes runtime configuration, startup behavior, or analyst workflow.
- Run focused tests for all touched files.
- Document any intentionally deferred UI or daemon features in the implementation notes.

## 11. Test plan

Add or update focused tests under `CABTA/tests/`.

Suggested files:

- `CABTA/tests/test_investigation_workdir_service.py`
- `CABTA/tests/test_agent_loop_investigation_workdir.py` if agent-loop integration is non-trivial
- Existing app-factory tests if `CABTA/src/web/app.py` is modified
- Existing case-memory tests if checkpoint metadata changes

Required test coverage:

- Creates expected directory layout and required files.
- Reuses an existing workdir without clobbering analyst or agent content.
- Blocks `../` path traversal.
- Blocks absolute paths.
- Blocks or safely handles symlink escapes.
- Writes and reads JSON deterministically.
- Handles corrupt JSON explicitly.
- Appends JSONL events with AISA metadata.
- Registers artifacts with `authoritative` and `verdict_boundary` fields.
- Summarizes artifact count, disk usage, last event, and manifest metadata.
- Archives inside the configured base directory.
- Agent loop still works when the workdir service is `None`.
- Agent loop records workdir state when service is injected.
- Web app starts when service initialization succeeds.
- Web app degrades honestly if service initialization fails, if web wiring is added.

Focused command examples for implementation phase:

```bash
python -m pytest CABTA/tests/test_investigation_workdir_service.py
python -m pytest CABTA/tests/test_agent_loop_investigation_workdir.py
python -m pytest CABTA/tests/test_case_memory_service.py
python -m pytest CABTA/tests/test_agent_loop_prompt_plumbing.py
```

## 12. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Workdir content becomes mistaken for authoritative verdict output | Add explicit `authoritative` and `verdict_boundary` metadata; keep deterministic decision references separate |
| Path traversal or unsafe artifact access | Centralize path resolution and test traversal, absolute path, and symlink escape cases |
| Runtime bloat from large artifacts | Add configurable file size limits and summary-only case-memory references |
| Corrupt JSON breaks future sessions | Use explicit corrupt JSON handling and preserve raw files for manual review where possible |
| Web startup becomes fragile | Keep service optional and fail soft during app initialization |
| Sensitive data leaks into logs | Redact likely secrets and avoid recording raw credentials or provider headers |
| Implementation drifts into a new persistence layer | Keep the service filesystem-only and link summaries to existing case/session stores |

## 13. Rollout plan

- Land the service with unit tests first and no mandatory runtime wiring.
- Add optional agent-loop injection after the service contract is stable.
- Add web DI only if required by the existing agent construction path.
- Add case-memory references only after workdir summaries are stable.
- Keep the feature local-only and disabled-by-absence: if the service is not configured or fails to initialize, AISA continues existing behavior.
- Monitor generated `.cabta-runtime/investigations/` size during local use and add retention policy later if needed.

## 14. Acceptance criteria

- `CABTA/src/agent/investigation_workdir.py` exists with a tested `InvestigationWorkdirService`.
- Workdir creation produces the agreed local-first layout and schema files.
- Path safety tests prove traversal and absolute-path attempts are blocked.
- Artifact metadata distinguishes deterministic evidence references from agentic notes.
- `CABTA/src/agent/agent_loop.py` can use the service optionally without changing existing verdict authority.
- `CABTA/src/web/app.py` is touched only if DI is required and remains gracefully degradable.
- Case-memory integration is additive, summary-only, and does not duplicate large artifacts.
- Focused tests under `CABTA/tests/` pass for all touched surfaces.

## 15. Implementation checklist

- [ ] Implement `CABTA/src/agent/investigation_workdir.py`.
- [ ] Add service unit tests under `CABTA/tests/`.
- [ ] Add artifact index and event-log tests.
- [ ] Add optional injection into `CABTA/src/agent/agent_loop.py`.
- [ ] Add agent-loop integration tests.
- [ ] Add `CABTA/src/web/app.py` DI only if needed by runtime construction.
- [ ] Add web app-factory tests if web DI is touched.
- [ ] Add case-memory summary reference tests if case-memory payloads are touched.
- [ ] Run focused tests and document any known deferred behavior.
