# CABTA Queue-Backed Runtime Design

## Purpose

This document defines the intended queue-backed runtime model for CABTA background and headless workflow execution.

It exists to make the runtime migration path explicit and safe while preserving CABTA's current local-first, evidence-first behavior.

This design does **not** replace CABTA's deterministic verdict authority.
It describes orchestration semantics only.

## Current Compatibility Path

Current background execution remains compatibility-oriented:

- headless scheduling is optional
- runtime mode remains effectively **thread-per-session**
- queue state is used to coordinate dispatch and retries
- worker-runtime migration is incremental, not a rewrite

The current runtime already exposes these operational semantics:

- durable queue entries
- lease ownership
- lease expiry
- stale lease release
- retry scheduling with backoff
- terminal failure state
- cancellation
- resume from failed/cancelled queue state
- bounded cycle limit in daemon execution
- explicit runtime status in daemon inspection

## Core Runtime Goals

The queue-backed runtime must provide:

1. resumable job semantics
2. bounded concurrency
3. explicit lease / cancel / retry behavior
4. compatibility with current session-based execution
5. graceful degradation when optional integrations are unavailable
6. observability that explains what the daemon is doing and why

## Runtime Model

### 1. Queue Job

A queue job represents one scheduled workflow dispatch attempt.

Minimum queue identity:

- `id`
- `schedule_id`
- `workflow_id`

Current persisted runtime fields include:

- `status`
- `attempts`
- `max_attempts`
- `next_run_at`
- `leased_at`
- `lease_owner`
- `lease_expires_at`
- `session_id`
- `last_error`
- `last_transition`
- `resume_token`

### 2. Runtime Status Model

Queue jobs may move through these states:

- `queued`
- `leased`
- `retry_scheduled`
- `completed`
- `failed`
- `cancelled`

Intended interpretation:

- `queued`: ready for dispatch when due
- `leased`: currently owned by a worker/daemon cycle
- `retry_scheduled`: previously attempted, retry planned later
- `completed`: dispatch produced a valid running session or terminal completion
- `failed`: no more retry path remains or error is terminal
- `cancelled`: explicitly cancelled by operator/runtime control

### 3. Lease Model

A lease is the runtime claim that a worker currently owns a job.

Lease fields:

- `lease_owner`
- `leased_at`
- `lease_expires_at`

Rules:

- only due jobs in `queued` or `retry_scheduled` may be leased
- leasing increments `attempts`
- lease expiry must be explicit
- stale leases are released into `retry_scheduled`
- lease metadata must be cleared on:
  - completion
  - retry scheduling
  - failure
  - cancellation
  - resume reset

### 4. Resume Model

Resume support currently exists at queue-state level, not full session replay.

Current semantics:

- a job in `failed` or `cancelled` can be moved back to `queued`
- `resume_token` gives the runtime a stable resume-oriented identifier
- resumed jobs should be treated as re-dispatchable units, not as proof that in-memory execution state was restored

Future expansion may include:

- session-aware resume checkpoints
- step-level workflow resume
- richer persisted execution cursor

## Retry Model

Retry is intended for temporary/runtime-blocking failures, not unsupported configurations.

Current behavior:

- retryable blocked outcomes transition to `retry_scheduled`
- backoff is based on daemon-configured base delay
- terminal failures become `failed`

Recommended policy interpretation:

- retry:
  - dependency temporarily unavailable
  - optional service disconnected but expected to recover
  - transient runtime issue
- fail terminally:
  - invalid workflow
  - missing required playbook for playbook-backed execution
  - unrecoverable configuration problem
  - explicitly non-retryable dispatch error

## Cancellation Model

Cancellation is an explicit runtime control.

Current queue semantics:

- any non-completed, non-cancelled job may move to `cancelled`
- cancellation clears lease ownership
- cancellation records `last_error` with operator/runtime reason
- cancellation updates `last_transition`

Future UI/API behavior should surface:

- who cancelled
- why cancellation happened
- whether the job can be resumed safely

## Bounded Concurrency Policy

CABTA should remain local-first and predictable.
Background execution must not silently overrun host resources.

Current bounded execution controls:

- daemon `cycle_limit`
- daemon `max_workers` status exposure
- lease timeout
- retry backoff policy

Intended policy:

- cycle execution must respect configured maximum per polling pass
- worker count must be explicit and inspectable
- when future multi-worker execution is enabled, queue leasing remains the arbitration mechanism
- bounded concurrency must prefer fewer stable jobs over uncontrolled parallelism

## Runtime Inspection Contract

Daemon/runtime inspection should answer:

- is daemon mode enabled?
- what is the runtime mode?
- is this still compatibility mode?
- how many jobs are queued / leased / retrying / failed / cancelled?
- what lease and retry policy applies?
- what is the migration target?

Current daemon status now exposes:

- `runtime_mode`
- `queue_enabled`
- `resumable_jobs`
- `approval_aware`
- `bounded_concurrency`
- `lease_policy`
- `worker_supervision`
  - worker inventory
  - active worker count
  - last cycle summary
  - per-worker last error / heartbeat / cycle metadata
- `migration_path`
- queue state counts

## Compatibility Rules

The queue-backed runtime must preserve the following:

- CABTA remains usable without daemon mode
- local interactive investigations keep working
- queue-backed execution does not replace deterministic analyzer authority
- missing optional services degrade enrichment/orchestration, not core product viability
- thread-per-session remains the compatibility path until worker runtime is proven

## Worker Migration Path

### Current
- optional headless daemon
- queue-backed dispatch metadata
- thread-per-session execution compatibility

### Near-term target
- queue-backed worker runtime
- explicit worker ownership semantics
- richer runtime inspection
- clearer operational cancellation/resume controls

Partially implemented now in compatibility mode:

- daemon cycle execution records per-worker status
- runtime inspection exposes worker supervision metadata
- last-cycle success/error state is visible without inspecting raw queue rows

### Later target
- resumable execution cursor beyond queue state
- multi-worker bounded scheduling
- richer operational metrics and admin controls

## Open Questions

The following remain intentionally open:

- whether full session resume should be supported at workflow-step granularity
- whether resume tokens should map to persisted execution cursor state
- whether cancellation should cascade into active agent/playbook session termination
- whether worker pools should remain in-process or become a separate runtime boundary

## Guardrails

At every runtime phase:

- queue/runtime orchestration must not become verdict authority
- deterministic CABTA analysis remains authoritative for verdict-bearing output
- runtime hardening must improve reliability, not blur evidence ownership