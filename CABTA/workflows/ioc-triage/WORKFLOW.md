---
id: ioc-triage
name: IOC Triage
description: "Structured IOC enrichment and analyst-ready prioritization backed by CABTA scoring."
execution-backend: playbook
playbook-id: ioc_triage
default-agent-profile: threat_intel_analyst
agents:
  - triage
  - threat_intel_analyst
  - reporter
tools-used:
  - investigate_ioc
  - search_threat_intel
  - correlate_findings
capabilities:
  - ioc-enrichment
  - priority-ranking
  - analyst-summary
required-tools:
  - investigate_ioc
  - correlate_findings
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - threat-intel-free
  - free-osint
approval-mode: inherited
headless-ready: true
use-case: "Rapidly validate and prioritize a suspicious IP, domain, URL, hash, email address, or CVE."
trigger-examples:
  - "Triage the suspicious domain from this alert"
  - "Investigate whether this IP is malicious"
---

# IOC Triage

This workflow is designed for the fastest path from raw indicator to
evidence-backed verdict.

## Operating Model

- Prefer CABTA IOC investigation and scoring first.
- Use enrichment tools to explain or strengthen the evidence chain.
- Treat single-source hits as supporting context, not as final proof.
