# TEST-MANIFEST.md

## Purpose

This file helps choose the right test scope while developing CABTA.

## Current Test Surface

At the current snapshot, CABTA contains broad pytest coverage under `tests/`, including analysis-core, web/API, agent workflow, router runtime, and investigation workdir hardening modules.

Major test areas:

- web API and stores
- analyzers
- scoring
- caching
- rate limiting
- email forensics
- agent workflows

## Important Note

Use focused tests for touched lanes first, then expand to adjacent contract tests. State exactly what was run and any skipped slow/live dependency coverage.

## Baseline Commands

### Environment and setup smoke test

```bash
python test_setup.py
```

### Full test suite

```bash
python -m pytest -q
```

### Verbose test suite

```bash
python -m pytest -q -rA
```

## Focused Test Lanes

### Web and API changes

Files likely touched:

- `src/web/app.py`
- `src/web/routes/*`
- `src/web/analysis_manager.py`
- `src/web/case_store.py`
- `templates/*`

Run:

```bash
python -m pytest tests/test_web_api.py -q
```

### IOC and enrichment changes

Files likely touched:

- `src/tools/ioc_investigator.py`
- `src/integrations/threat_intel*.py`
- `src/utils/dga_detector.py`
- `src/utils/domain_age_checker.py`
- `src/scoring/intelligent_scoring.py`

Run:

```bash
python -m pytest tests/test_scoring.py tests/test_adaptive_scoring.py -q
```

Add targeted IOC tests if behavior changes are deeper than scoring.

### Malware and file-analysis changes

Files likely touched:

- `src/tools/malware_analyzer.py`
- `src/analyzers/*`
- `src/utils/yara_scanner.py`
- `src/scoring/tool_based_scoring.py`

Common focused runs:

```bash
python -m pytest tests/test_file_type_router.py tests/test_yara_scanner.py tests/test_packer_detection.py -q
python -m pytest tests/test_shellcode_detector.py tests/test_fuzzy_hash.py -q
```

### Email-analysis changes

Files likely touched:

- `src/tools/email_analyzer.py`
- `src/analyzers/email_*`
- `src/analyzers/bec_detector.py`

Run:

```bash
python -m pytest tests/test_email_forensics.py -q
```

### Caching and rate limiting

Run:

```bash
python -m pytest tests/test_cache.py tests/test_rate_limiter.py -q
```

### Agent and MCP workflow changes

Files likely touched:

- `src/agent/*`
- `src/server.py`
- `src/web/routes/agent.py`
- `src/web/routes/chat.py`

Run:

```bash
python -m pytest tests/test_agent.py tests/test_web_api.py tests/test_agent_loop_investigation_workdir.py tests/test_investigation_workdir_service.py -q
```

For vibe SOC query, coverage, retry, and dynamic hypothesis reasoning changes, run:

```bash
python -m pytest tests/test_query_coverage_retry.py -q
python -m pytest tests/test_agent.py -k "log_query_planner or search_logs or reasoning_guided_next_action" -q
python -m pytest tests/test_agentic_reasoning.py -q
python -m pytest tests/test_prompt_composer.py tests/test_agent_loop_prompt_plumbing.py tests/test_reasoning_mirror_ui.py -q
python -m pytest tests/test_agent_loop_investigation_workdir.py -q
```

For Vibe SOC universal orchestration changes, run:

```bash
python -m pytest tests/test_vibe_soc_universal_orchestration_phase12.py tests/test_vibe_soc_universal_orchestration_phase3.py tests/test_vibe_soc_universal_orchestration_phase4.py tests/test_vibe_soc_universal_orchestration_phase5.py -q
python -m pytest tests/test_capability_catalog_contracts.py tests/test_agent_loop_prompt_plumbing.py tests/test_agentic_reasoning.py tests/test_query_coverage_retry.py tests/test_playbook_log_demo.py tests/test_agent_chat_reasoning_ui.py tests/test_web_api.py -q
```

For LLM-first SOC request interpretation, schema constraints, mocked provider behavior, repair/fallback, and additive provider-envelope checks, run:

```bash
python -m pytest tests/test_soc_interpretation_schema.py tests/test_llm_request_interpreter.py tests/test_provider_chat_gateway.py -q
```

For Vibe SOC natural-chat reliability contracts and audit scenarios, run:

```bash
python -m pytest tests/test_soc_task_state.py tests/test_parameter_binder.py tests/test_preflight_validator.py tests/test_runtime_contract_schemas.py tests/test_vibe_soc_natural_chat_scenarios.py -q
python -m pytest tests/test_vibe_soc_natural_chat_scenarios.py tests/test_vibe_soc_universal_orchestration_phase12.py tests/test_vibe_soc_universal_orchestration_phase3.py tests/test_vibe_soc_universal_orchestration_phase4.py tests/test_vibe_soc_universal_orchestration_phase5.py -q
```

## Suggested Change-to-Test Mapping

### If you change result schemas

Run:

```bash
python -m pytest tests/test_web_api.py tests/test_models.py -q
```

### If you change scoring thresholds or verdict logic

Run:

```bash
python -m pytest tests/test_scoring.py tests/test_adaptive_scoring.py -q
```

### If you change routing or analyzer dispatch

Run:

```bash
python -m pytest tests/test_file_type_router.py tests/test_web_api.py -q
```

### If you change LLM router/provider runtime

Run:

```bash
python -m pytest tests/test_router_config_normalization.py tests/test_provider_chat_gateway.py tests/test_provider_gateway.py tests/test_provider_health_service.py tests/test_llm_analyzer_failover.py tests/test_web_data_provider.py -q
```

### If you change investigation workdir behavior

Run:

```bash
python -m pytest tests/test_investigation_workdir_service.py tests/test_agent_loop_investigation_workdir.py tests/test_investigation_workdir_web_runtime.py -q
```

## Pre-Completion Checklist

- run the narrowest relevant tests first
- expand to cross-layer tests if result shapes or APIs changed
- state clearly if tests were not run
- update this manifest if the test surface changes materially

## Unresolved Questions

- None.
