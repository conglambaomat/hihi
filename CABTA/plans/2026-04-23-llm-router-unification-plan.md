# AISA LLM Router Unification Plan

Date: 2026-04-23
Lane: `integration-control` with `agent-workflow` and `web-surface`
Status: in progress

## Goal

Refactor CABTA so all runtime LLM traffic uses a single OpenAI-compatible router contract centered on:

- `llm.provider`
- `llm.base_url`
- `llm.model`
- unified API key

Target router runtime:

- base URL: `http://localhost:20128/v1`
- provider identity normalized to one canonical router path
- no active parallel provider runtime semantics for `openrouter`, `ollama`, `groq`, `gemini`, `anthropic`, or `nvidia`

## Invariants

- Deterministic AISA analyzers and scoring remain authoritative for verdicts and numeric outcomes.
- LLM output remains interpretive, assistive, and degradable.
- Missing or unreachable router must surface honest degraded state in agent and web health surfaces.
- Legacy config keys may be normalized on load for compatibility, but must not preserve old runtime call paths.

## Scope

Primary files expected:

- `src/utils/config.py`
- `src/integrations/llm_analyzer.py`
- `src/agent/agent_loop.py`
- `src/agent/provider_gateway.py`
- `src/agent/provider_health_service.py`
- `src/agent/provider_chat_gateway.py`
- `src/agent/session_response_builder.py`
- `src/web/app.py`
- `src/web/runtime_refresh.py`
- `src/web/data_provider.py`
- `src/web/routes/config_api.py`
- `src/detection/llm_rule_generator.py`
- config examples and focused tests

## Phases

### Phase 1 — Canonical config and normalization

- Replace OpenRouter-only normalization with router-only normalization.
- Introduce canonical defaults for router base URL and model.
- Normalize legacy provider/model fields into canonical `llm.base_url`, `llm.model`, unified API key.
- Remove old provider-specific defaults from active runtime config.

### Phase 2 — Shared transport and runtime collapse

- Collapse analyzer runtime dispatch to one OpenAI-compatible chat-completions transport.
- Collapse agent runtime dispatch to one router transport for both tool-calling and text generation.
- Remove failover semantics and old provider branches from active execution paths.
- Preserve runtime status tracking with honest router availability/error metadata.

### Phase 3 — Web/settings/health surfaces

- Update settings and health endpoints to expose canonical router config.
- Keep any legacy endpoint names only as compatibility aliases where necessary.
- Ensure UI/runtime messaging refers to the router, not deprecated parallel providers.

### Phase 4 — Tests/docs/config examples

- Update focused tests to assert router-only normalization and runtime behavior.
- Update example config and essential docs to reflect canonical router wiring.

### Phase 5 — Focused validation

- Run focused pytest coverage for config, provider/health, analyzer, web API, and agent prompt plumbing surfaces touched by the migration.
- Restart running web app only if required after persisted config/runtime changes.

## Acceptance criteria

- AISA runtime uses a single router transport at `http://localhost:20128/v1`.
- Canonical config is `llm.provider`, `llm.base_url`, `llm.model`, and a unified API key field.
- Old provider branches are removed or clearly dead-ended into normalization only.
- Web health/settings surfaces report router status honestly.
- Focused tests covering touched surfaces pass or any residual failures are documented precisely.
