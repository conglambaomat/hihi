# CABTA Project Overview

## Product Name

- Canonical: `CABTA`
- Expanded: `Cyan Agent Blue Team Assistant`

## Product Purpose

CABTA is a local-first analyst platform for SOC and DFIR workflows. It helps defenders investigate IOCs, analyze suspicious files, inspect emails, generate detection content, and work through investigations from a web dashboard, CLI, or MCP interface.

## Primary Users

- SOC analysts
- incident responders
- threat hunters
- malware analysts
- email security analysts
- defenders building MCP-assisted security workflows

## Core User Problems

### 1. IOC triage is fragmented

Analysts often pivot across many TI sources manually. CABTA centralizes multi-source lookup, enrichment, scoring, and rule generation.

### 2. File and email analysis are slow to operationalize

Analysts need more than raw findings. They need verdicts, evidence, MITRE context, and deployable rules.

### 3. AI tooling often breaks privacy boundaries

CABTA prefers local-first workflows and optional local LLM usage through Ollama so sensitive artifacts do not need to leave the environment.

### 4. Defensive teams need actionable outputs

CABTA produces:

- verdicts
- evidence
- MITRE mappings
- detection rules
- STIX exports
- analyst-ready reports

## Product Pillars

### Local-First Security

- local execution first
- optional enrichment from external sources
- local LLM support
- no mandatory cloud dependency for core flows

### Analyst-Grade Explainability

- evidence must stay visible
- verdicts should be traceable to findings
- outputs should help analysts explain "why"

### Modular Security Pipelines

- tools orchestrate analysis
- analyzers specialize by artifact type
- integrations enrich data
- scoring converts findings into consistent verdicts
- reporting makes results operational

### Graceful Degradation

- missing API keys reduce enrichment only
- optional integrations should fail soft
- unsupported file types should still return a useful baseline result

## Core Capabilities

### IOC Investigation

- IP, domain, URL, hash, email, and CVE lookup
- multi-source TI
- domain age and DGA enrichment
- rule generation
- optional LLM interpretation

### Malware and File Analysis

- type routing via `FileTypeRouter`
- specialized analyzers for PE, ELF, Mach-O, Office, PDF, scripts, APK, archives, memory, and text
- YARA, strings, entropy, sandbox, MITRE mapping
- ransomware and beacon-specific analysis

### Email Forensics

- SPF, DKIM, DMARC checks
- advanced header and relay analysis
- phishing and BEC detection
- IOC extraction
- attachment escalation into file analysis

### Analyst Interfaces

- FastAPI dashboard
- REST API
- CLI
- MCP server
- agent chat and playbook workflow

## System Constraints

- must preserve local-first operating model
- must avoid turning LLM into the sole verdict engine
- must preserve backwards compatibility where reasonable
- must remain usable with partial configuration
- should stay understandable to human analysts, not only automation

## Engineering Priorities

1. correctness of analysis and scoring
2. clear evidence and explainability
3. stable analyst workflows
4. safe extensibility for new analyzers and TI sources
5. better project memory for long-running development

## Current Repo Reality

The main prompt surface for this product now routes cleanly to `CABTA`, but older names still remain in some code paths, generated output text, and historical materials. New work should treat `CABTA` as the source-of-truth name and avoid reintroducing legacy identities into touched surfaces.

## What Vibe Coding Needs in This Repo

To develop CABTA effectively with AI assistance, the repo needs:

- stable project memory docs
- explicit development standards
- test-surface visibility
- reusable plan templates
- a repo-specific operating model for long tasks and multi-session work

Those supporting files are now part of the repo.

## Unresolved Questions

- None.
