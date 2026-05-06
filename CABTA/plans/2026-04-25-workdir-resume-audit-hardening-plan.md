# Workdir resume/audit hardening plan

## Scope

Feature area: 2.2 Workdir resume/audit hardening.

Lanes: agent-workflow + web-surface.

## Invariants

- Workdir content is an audit/export/resume context mirror only.
- Deterministic AISA analyzers and scoring remain authoritative for verdicts and scores.
- Historical deterministic decisions from workdir must be marked contextual/non-authoritative until fresh tools re-validate.
- Missing or corrupt workdir data must degrade safely and not break normal investigations.

## Implementation steps

1. Extend `InvestigationWorkdirService` with:
   - artifact/index integrity refresh using SHA-256, size, and updated timestamps;
   - manifest validation over required layout, JSON readability, artifact existence, hashes, and corrupt JSON;
   - persisted `review_state.json` analyst review model;
   - structured resume payload with lineage, artifact hashes, warning markers, and state payload for safe hydration.
2. Extend `AgentLoop` with a safe resume entrypoint that creates a new session and hydrates context as non-authoritative workdir mirror state.
3. Add API routes for validation, review get/update, resume payload inspection, and starting a resumed session.
4. Add lightweight UI affordances in existing agent templates for validation/review/resume links.
5. Add focused service, route, and agent-loop tests with isolated temp dirs.

## Acceptance criteria

- Hash mismatch is detected by validation.
- Resume payload carries lineage, source hashes, non-authoritative warning, and deterministic verdict boundary.
- Resume-start route creates a new session with lineage metadata when `AgentLoop` is available.
- Review state can be read and updated without mutating canonical evidence/verdict files.
- Archive includes validation/integrity summary and excludes prior archives/temp files.
