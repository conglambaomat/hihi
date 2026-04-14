---
id: phishing-investigation
name: Phishing Investigation
description: "Email-centric orchestration for header/auth analysis, link pivots, attachment review, and case-ready findings."
execution-backend: playbook
playbook-id: phishing_investigation
default-agent-profile: phishing_analyst
agents:
  - triage
  - phishing_analyst
  - threat_intel_analyst
  - reporter
tools-used:
  - analyze_email
  - extract_iocs
  - investigate_ioc
  - correlate_findings
capabilities:
  - email-forensics
  - phishing-analysis
  - case-management
required-tools:
  - analyze_email
  - extract_iocs
  - correlate_findings
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - free-osint
  - osint-tools
approval-mode: inherited
headless-ready: true
use-case: "Investigate a suspicious email with links, attachments, impersonation risk, or BEC indicators."
trigger-examples:
  - "Run phishing investigation on this suspicious email"
  - "Investigate a possible BEC message targeting finance"
---

# Phishing Investigation

This workflow uses the existing CABTA email analysis path as the operational
core and layers orchestration on top for cleaner execution and reporting.

## Operating Model

- Parse and score the email through CABTA first.
- Use IOC pivots and attachments as follow-on evidence, not as isolated facts.
- Keep sender identity, auth results, URLs, and attachments explicit in the output.
