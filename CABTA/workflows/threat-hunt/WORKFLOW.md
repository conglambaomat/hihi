---
id: threat-hunt
name: Threat Hunt
description: "Hypothesis-driven hunting workflow with generated queries, live Splunk pivots when available, and explicit manual boundaries when no SIEM backend is connected."
execution-backend: playbook
playbook-id: threat_hunt
default-agent-profile: threat_hunter
agents:
  - threat_hunter
  - network_analyst
  - detection_engineer
  - reporter
tools-used:
  - extract_iocs
  - generate_rules
  - search_threat_intel
  - correlate_findings
capabilities:
  - hypothesis-generation
  - hunt-query-creation
  - timeline-reconstruction
required-tools:
  - extract_iocs
  - generate_rules
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - splunk
  - threat-intel-free
  - network-analysis
approval-mode: inherited
headless-ready: true
use-case: "Drive a structured threat hunt from a hypothesis and a small set of known indicators."
trigger-examples:
  - "Threat hunt for possible post-phishing beaconing"
  - "Hunt for similar behavior across finance endpoints"
---

# Threat Hunt

This workflow keeps the hunt grounded in tools, hunt queries, and evidence
artifacts instead of letting the model improvise unsupported conclusions.

## Operating Model

- Convert the hypothesis into explicit pivots and generated hunt queries.
- Run hunt queries through the read-only Splunk MCP backend when it is connected and policy allows automatic execution.
- Mark manual lookup requirements clearly when the environment lacks a live log backend.
- Feed confirmed evidence back through CABTA correlation before summarizing.
