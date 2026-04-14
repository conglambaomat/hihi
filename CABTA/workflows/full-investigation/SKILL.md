---
id: full-investigation
name: Full Investigation
description: "Deep multi-agent investigation skill that correlates alerts, artifacts, timelines, hunt pivots, and reporting into one end-to-end flow."
execution-backend: agent
default-agent-profile: investigator
agents:
  - triage
  - investigator
  - correlator
  - enrichment_specialist
  - network_forensics
  - malware_analyst
  - mitre_analyst
  - detection_engineer
  - reporter
  - case_coordinator
tools-used:
  - extract_iocs
  - correlate_findings
  - recall_ioc
  - search_logs
  - search_threat_intel
  - analyze_detection_coverage
  - create_attack_layer
  - create_case
  - add_case_note
capabilities:
  - multi-agent-coordination
  - cross-source-correlation
  - timeline-reconstruction
  - case-management
  - detection-engineering
required-tools:
  - extract_iocs
  - correlate_findings
  - analyze_detection_coverage
  - create_case
required-features:
  - agent
  - workflow_engine
optional-mcp-servers:
  - splunk
  - threat-intel-free
  - free-osint
  - network-analysis
  - forensics-tools
approval-mode: inherited
headless-ready: true
use-case: "Run a deep investigation when a signal is high-value, ambiguous, or likely to require multiple analyst disciplines."
trigger-examples:
  - "Run a full investigation on this suspicious host"
  - "Deep dive this multi-stage intrusion and build the case context"
  - "Investigate this incident across IOC, network, malware, and ATT&CK views"
---

# Full Investigation Skill

This skill is the closest AISA equivalent to a Vigil-style end-to-end investigation workflow.

It does not let the model improvise unsupported findings.
It forces the investigation through real CABTA tools, analysis outputs, timelines, and case artifacts.

## Operating Model

- Start with triage and evidence extraction.
- Correlate across prior results, related indicators, and case context.
- Pull in log-hunting and enrichment only through available backends and tool truth.
- Treat ATT&CK mapping and coverage analysis as downstream evidence packaging, not verdict authority.
- Keep case updates, notes, and milestones as structured artifacts instead of ephemeral chat only.

## Phase Sequence

1. Triage and normalize the incoming signal.
2. Build the evidence chain across IOC, file, email, hunt, and prior memory.
3. Correlate entities, repeated infrastructure, and case overlap.
4. Expand into network, malware, and ATT&CK coverage where justified.
5. Update the case record and produce analyst-ready reporting.
