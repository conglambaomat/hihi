# CABTA Analysis Core

Use this rule for verdict-bearing CABTA work.

## Scope

Primary areas:

- `CABTA/src/tools/ioc_investigator.py`
- `CABTA/src/tools/malware_analyzer.py`
- `CABTA/src/tools/email_analyzer.py`
- `CABTA/src/analyzers/`
- `CABTA/src/scoring/`
- `CABTA/src/detection/`
- `CABTA/src/reporting/`
- related web routes, templates, and tests when contracts surface in the UI

## Core rule

For IOC, file, and email flows:

- analyzers extract evidence
- integrations enrich
- scoring decides
- reporting explains
- LLM output interprets but does not replace deterministic verdict logic

If a proposed change weakens that boundary, redesign it.

## Entry points

### IOC work

Start with:

- `CABTA/src/tools/ioc_investigator.py`
- `CABTA/src/integrations/threat_intel.py`
- `CABTA/src/integrations/threat_intel_extended.py`
- `CABTA/src/scoring/intelligent_scoring.py`

### File and malware work

Start with:

- `CABTA/src/tools/malware_analyzer.py`
- `CABTA/src/analyzers/file_type_router.py`
- the relevant analyzer in `CABTA/src/analyzers/`
- `CABTA/src/scoring/tool_based_scoring.py`

### Email work

Start with:

- `CABTA/src/tools/email_analyzer.py`
- `CABTA/src/analyzers/email_forensics.py`
- `CABTA/src/analyzers/email_threat_indicators.py`
- `CABTA/src/analyzers/bec_detector.py`
- `CABTA/src/scoring/intelligent_scoring.py`

## Plan triggers

Create or update a plan when the change:

- alters scoring or verdict semantics
- changes result contracts used by web, reports, cases, or MCP tools
- crosses tool, analyzer, scoring, and reporting layers
- adds a new analyzer, enrichment source, or output format

## Delivery checklist

- read the orchestrator before editing a lower-level analyzer
- preserve additive contracts where possible
- keep degraded behavior explicit when APIs or tools are unavailable
- run focused tests for the touched lane
- update docs when architecture, scoring, outputs, or setup change
