# Research Notes: Vigil to AISA Mapping

## Core Decision

Use the asymmetric model:

- CABTA/AISA = analysis core + verdict governance
- Vigil-inspired features = orchestration plane

## Why This Is The Right Split

### CABTA/AISA already has the stronger analysis core

- web/API/CLI/MCP share one core
- IOC, file, and email tool orchestrators already exist
- analyzer and integration layers already exist
- scoring already owns verdicts
- reporting and cases already exist

### Vigil is stronger where AISA is currently thinner

- specialist agents
- readable workflow definitions
- workflow execution structure
- approval workflow
- graph and timeline ideas
- AI decision logging
- headless daemon direction

## Guardrails

1. workflow must call tools for evidence
2. scoring remains source of truth for verdicts
3. orchestration must not silently replace analysis core
4. local-first core use must remain simple

## Immediate Best Bets

1. specialist agent foundation
2. workflow definition engine
3. capability catalog
4. case-linked workflow state
5. approval and decision governance

## Deferred Until Later

- full custom integration builder
- mandatory queueing stack
- mandatory background daemon
- heavier storage/runtime assumptions for all users

## Unresolved Questions

- none yet
