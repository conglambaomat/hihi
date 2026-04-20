# Root Workspace Technique Assessment for CABTA

## Purpose

This document records which techniques from the root workspace are worth adapting into CABTA, and which ones should remain developer tooling only.

Legacy naming note: older strategic material may still refer to this product direction as `AISA` / `AI Security Assistant`. For implementation, architecture, UI, and new docs, treat `CABTA` as the canonical product name.

The root repository is not a second product runtime. It is a mixed workspace containing:

- the `CABTA/` product
- agent workflow scaffolding
- hook-based policy tooling
- release and documentation automation

That distinction matters. The goal is not to copy the root repo into CABTA. The goal is to selectively adopt the highest-value techniques.

## Repos Reviewed

Reviewed root workspace areas:

- `README.md`
- `.claude/settings.json`
- `.claude/hooks/*`
- `.claude/scripts/*`
- `guide/*`
- `docs/agent-teams-guide.md`
- `docs/gitnexus-workflow.md`
- `scripts/*`

Reviewed CABTA context to map compatibility:

- `CABTA/README.md`
- `CABTA/AGENTS.md`
- `CABTA/docs/system-design.md`
- `CABTA/docs/codebase-summary.md`
- `CABTA/docs/feature-truth-matrix.md`

## Executive Conclusion

Yes. The root workspace contains several techniques that can improve CABTA without forcing a large rewrite.

The strongest reusable techniques are:

1. hook-style guardrails for agent and tool execution
2. prompt-injection defenses implemented as architecture, not prompt wording
3. centralized environment and secret resolution
4. machine-readable capability catalogs

These fit CABTA well because CABTA already has:

- agent execution
- MCP expansion
- untrusted content ingestion
- many optional providers
- growing config complexity

## High-Value Techniques to Integrate Now

### 1. Agent Guardrail and Policy Hooks

Root evidence:

- `.claude/settings.json`
- `.claude/hooks/privacy-block.cjs`
- `.claude/hooks/scout-block.cjs`
- `.claude/hooks/dev-rules-reminder.cjs`

What the root workspace does well:

- intercepts risky actions before execution
- blocks sensitive paths unless explicitly allowed
- distinguishes safe exploration from noisy or dangerous scanning
- turns policy into runtime behavior instead of documentation only

Why this matters for CABTA:

CABTA already runs agent tools, MCP tools, playbooks, and user-triggered automation over untrusted inputs. It should protect:

- uploaded samples
- case data
- config secrets
- analyst notes
- sandbox submission paths
- future log-query tools

Best AISA adaptation:

- add a lightweight policy layer around `agent_loop`, `tool_registry`, and MCP tool calls
- support rules like:
  - read-only vs write-like tool classes
  - approval-required tools
  - restricted path access
  - sensitive artifact redaction
  - max-scope limits for future Splunk or Elastic query tools

Expected benefit:

- safer autonomous behavior
- clearer analyst trust
- easier enterprise hardening later

Priority:

- `P1`

### 2. Prompt-Injection Defense by Architecture

Root evidence (patterns described in archived upstream research; local copies were removed to reduce doc duplication):

- Architectural separation of untrusted content vs privileged tool selection
- Skills and hooks as policy surfaces

What the root workspace does well:

- treats prompt injection as a systems problem
- recommends separating untrusted-content handling from privileged action selection
- favors structured reduction before agent decision-making

Why this matters for AISA:

AISA consumes hostile or semi-hostile content by design:

- phishing email bodies
- HTML
- malware strings
- URLs
- OSINT pages
- external TI summaries
- MCP tool output

This is one of the most important fit areas because AISA already states:

- evidence first
- deterministic verdict path
- LLM is additive, not verdict authority

Best AISA adaptation:

- separate `extract/summarize untrusted content` from `decide privileged next action`
- reduce tool results into typed structured evidence before agent reuse
- do not pass raw hostile text directly into tool-selection prompts
- add trust labels to tool outputs such as:
  - `trusted_local`
  - `external_untrusted`
  - `user_supplied`
  - `transformed_summary`

Expected benefit:

- lower prompt-injection risk
- better agent reliability
- cleaner future SOC log-hunting design

Priority:

- `P1`

### 3. Centralized Environment and Secret Resolution

Root evidence:

- `.claude/scripts/resolve_env.py`
- `guide/ENVIRONMENT_RESOLVER.md`

What the root workspace does well:

- defines clear precedence for env sources
- supports fallback chains
- avoids scattered secret resolution logic

Why this matters for AISA:

AISA currently mixes:

- `config.yaml`
- web-saved settings
- runtime refresh
- provider-specific env expectations
- MCP server env injection

That works, but the model is getting complex.

Best AISA adaptation:

- define one canonical precedence model for:
  - `config.yaml`
  - runtime-updated settings
  - environment variables
  - MCP server `env`
  - derived aliases like `hybrid_analysis/hybridanalysis`
- use it in:
  - LLM provider config
  - threat-intel API keys
  - sandbox provider keys
  - MCP server token/env bridging

Expected benefit:

- fewer config drift bugs
- easier settings UX
- cleaner troubleshooting

Priority:

- `P1`

### 4. Machine-Readable Capability Catalogs

Root evidence:

- `.claude/scripts/generate_catalogs.py`
- `guide/SKILLS.yaml`
- `guide/COMMANDS.yaml`

What the root workspace does well:

- stores capabilities in structured catalogs
- generates human-readable docs from machine-readable sources
- makes orchestration aware of real, current capabilities

Why this matters for AISA:

AISA already has many moving parts:

- local tools
- MCP tools
- analyzers
- integrations
- playbooks
- optional providers

Best AISA adaptation:

- create a generated capability catalog for:
  - agent tools
  - MCP servers and tools
  - analyzers
  - integrations
  - playbooks
- use the catalog to support:
  - settings UI
  - health UI
  - playbook validation
  - agent tool awareness
  - docs sync

Expected benefit:

- less stale documentation
- fewer mismatches between UI and backend
- easier future auto-planning for agents

Priority:

- `P1`

## Good Candidates for Later Phases

### 5. Workflow Hydration and Persistent State Patterns

Root evidence:

- `guide/SKILLS.md` / `guide/SKILLS.yaml` (curated skill catalog)
- `.claude/hooks/session-init.cjs`

Why it is useful:

- the root workspace treats long-running work as resumable state, not chat memory only

Possible AISA adaptation:

- resumable investigation plans
- hunt plans linked to cases
- analyst handoff state between sessions

Priority:

- `P2`

### 6. Release and Packaging Automation

Root evidence:

- `scripts/prepare-release-assets.cjs`
- `scripts/generate-opencode.py`
- root `package.json`

Why it is useful:

- AISA will eventually benefit from cleaner packaging, asset prep, and release metadata

Priority:

- `P2`

### 7. Multi-Agent Team Orchestration

Root evidence:

- `docs/agent-teams-guide.md`
- `.claude/settings.json`

Why it is useful:

- future AISA may want specialist agents for triage, malware, email, or threat hunting

Why it is not first priority:

- high complexity
- bigger validation burden
- less immediate value than hardening current single-agent flows

Priority:

- `P3`

## Techniques That Should Not Be Copied Directly

These are useful references, but should not be imported into AISA runtime as-is:

- terminal-specific statusline UX
- Claude/OpenCode-specific workflow hooks with no product value
- root branding and project scaffolding conventions
- skill-marketplace assumptions
- developer-only orchestration docs as runtime product logic

## Recommended Integration Roadmap for CABTA

### Phase 1. Guardrails and trust boundaries

- add agent execution policy layer
- classify tool actions by risk
- add trust labels for tool outputs and user-provided content
- reduce raw untrusted text before privileged tool-selection prompts

### Phase 2. Config and capability truth model

- standardize config/env precedence
- generate a live capability catalog
- use catalog to improve settings, health, and MCP visibility

### Phase 3. Investigation-state upgrades

- persistent hunt plans
- resumable case-linked agent workflows
- clearer human/agent handoff artifacts

### Phase 4. Advanced orchestration

- selective multi-agent workflows
- specialist investigation roles
- packaged release automation

## Best Immediate Engineering Targets

If only a small amount of work can be done next, the best targets are:

1. policy guardrails around agent and MCP tool execution
2. prompt-injection-safe separation between extraction and privileged action planning
3. a generated AISA capability catalog
4. a single canonical secret/config precedence model

These four give the best ratio of:

- security
- correctness
- maintainability
- user trust
- future extensibility

## Final Assessment

The root workspace does contain techniques worth integrating into AISA.

The most valuable insight is this:

The reusable value is not the boilerplate itself. The reusable value is the operational discipline behind it:

- policy as code
- trust-boundary-aware agent design
- capability truth catalogs
- explicit environment resolution

That is exactly the kind of infrastructure AISA needs as it grows from a strong localhost analysis platform into a more autonomous investigation assistant.

## Unresolved Questions

- None.
