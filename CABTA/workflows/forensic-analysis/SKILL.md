---
id: forensic-analysis
name: Forensic Analysis
description: "Evidence-preserving forensic skill focused on artifact review, timeline reconstruction, network pivots, ATT&CK mapping, and case-ready documentation."
execution-backend: agent
default-agent-profile: network_forensics
agents:
  - investigator
  - network_forensics
  - malware_analyst
  - mitre_analyst
  - compliance_mapping
  - reporter
  - case_coordinator
tools-used:
  - extract_iocs
  - correlate_findings
  - search_logs
  - analyze_malware
  - analyze_detection_coverage
  - create_attack_layer
  - get_case_context
  - add_case_note
capabilities:
  - evidence-collection
  - timeline-reconstruction
  - attack-path-analysis
  - audit-trail
  - compliance-reporting
required-tools:
  - correlate_findings
  - analyze_detection_coverage
  - add_case_note
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - forensics-tools
  - network-analysis
  - splunk
  - remnux
approval-mode: analyst-gated
headless-ready: true
use-case: "Drive a structured forensic review with preserved evidence, timelines, ATT&CK context, and case documentation."
trigger-examples:
  - "Run forensic analysis on this host compromise"
  - "Build a forensic timeline and evidence pack for this breach"
  - "Perform artifact and log-focused investigation with case documentation"
---

# Forensic Analysis Skill

This skill brings Vigil's forensic workflow idea into AISA without moving verdict authority away from CABTA.

It emphasizes:

- evidence preservation
- timeline and entity reconstruction
- artifact-backed reasoning
- case-ready notes and milestones
- compliance and reporting context after the facts are established

## Operating Model

- Work from real artifacts, timelines, logs, and analyzer outputs.
- Keep chain-of-evidence details inside structured case notes and events.
- Use ATT&CK and coverage mapping to explain what happened, not to replace evidence.
- If a live log backend is unavailable, return the hunt/query gap honestly and continue with artifact-backed work.

## Phase Sequence

1. Gather and preserve the core evidence set.
2. Reconstruct timelines and communications.
3. Deep-dive suspicious artifacts and malware indicators.
4. Map the observed behavior to ATT&CK and coverage.
5. Update the case with forensics-oriented notes and final reporting.
