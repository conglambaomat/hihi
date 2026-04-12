# TEST-MANIFEST.md

## Purpose

This file helps choose the right test scope while developing CABTA.

## Current Test Surface

At the current snapshot, CABTA contains `21` test modules under `tests/`.

Major test areas:

- web API and stores
- analyzers
- scoring
- caching
- rate limiting
- email forensics
- agent workflows

## Important Note

The current local environment used for repo analysis did not have `pytest` available on PATH, so this manifest documents the intended test commands even when execution is not possible in every session.

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
python -m pytest tests/test_agent.py tests/test_web_api.py -q
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

## Pre-Completion Checklist

- run the narrowest relevant tests first
- expand to cross-layer tests if result shapes or APIs changed
- state clearly if tests were not run
- update this manifest if the test surface changes materially

## Unresolved Questions

- None.
