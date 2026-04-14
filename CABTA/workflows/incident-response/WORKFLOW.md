---
id: incident-response
name: Incident Response
description: "Coordinate triage, investigation, containment planning, and reporting while CABTA scoring keeps verdict authority."
execution-backend: playbook
playbook-id: incident_response
default-agent-profile: responder
agents:
  - triage
  - investigator
  - responder
  - reporter
tools-used:
  - extract_iocs
  - investigate_ioc
  - correlate_findings
  - generate_rules
capabilities:
  - triage
  - investigation
  - response
  - case-management
required-tools:
  - extract_iocs
  - correlate_findings
optional-tools:
  - investigate_ioc
  - generate_rules
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - threat-intel-free
  - osint-tools
approval-mode: analyst-gated
headless-ready: true
use-case: "Escalate a confirmed or high-risk alert into a structured response workflow."
trigger-examples:
  - "Respond to a phishing incident with multiple affected users"
  - "Handle an active malware infection on a workstation"
---

# Incident Response

This workflow keeps CABTA as the evidence and verdict core while using an
orchestration layer to structure the response phases.

## Operating Model

- Playbook-backed execution for deterministic evidence gathering.
- Analyst approval remains mandatory for high-impact containment actions.
- Final verdict stays tied to CABTA scoring and correlated findings.

## Phases

1. Triage the incoming signal and extract the primary observables.
2. Gather corroborating evidence with CABTA analyzers and threat-intel tools.
3. Prepare response or containment actions and pause where approval is required.
4. Produce a case-ready summary and follow-up plan.
