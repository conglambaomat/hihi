# CABTA Live Verification Log

Date: 2026-04-01

This log captures the hybrid verification pass used during the current correctness/stabilization cycle.

## Runtime Verification

### Startup Path

- `run-web.ps1` successfully launched CABTA on Windows localhost
- `http://127.0.0.1:3003/api/config/info` returned `200`
- `http://127.0.0.1:3003/api/config/health` returned `200`

### Web Route Smoke

Verified `200 OK` for:

- `/`
- `/settings`
- `/api/config/info`
- `/api/config/health`
- `/api/dashboard/sources`
- `/api/agent/sandbox/status`

## Automated Verification

- Full suite: `704 passed`
- Targeted regression after current fixes: `214 passed`

## Source / Integration Verification

Probe IOC used for TI checks: `8.8.8.8`

### Live-Verified

- `Groq`
  - live call succeeded
  - CABTA received a valid structured response
- `VirusTotal`
  - live lookup succeeded
  - no transport/config error observed
- `AbuseIPDB`
  - live lookup succeeded
  - no transport/config error observed
- `Shodan`
  - live lookup succeeded
  - no transport/config error observed
- `AlienVault OTX`
  - live lookup succeeded
  - no transport/config error observed
- `GreyNoise`
  - live lookup succeeded
  - no transport/config error observed

### Configured But Not Auto-Wired

- `URLScan`
  - key may be configured
  - CABTA does not currently use URLScan in the live IOC enrichment path
  - surfaced as `manual` in web source health

## Sandbox Verification

### Verified Current Host State

- `Docker Isolation`
  - status: `not_available`
  - reason: Docker not available on PATH
- `VM Staging`
  - status: `not_configured`
  - reason: no `sandbox.vm.staging_dir` configured
- `Local Static Analysis`
  - status: `available`
  - static-only file handling is available
- `Cloud Sandbox Adapters`
  - status: `not_configured`
  - no adapters registered in current runtime

### Interpretation

Current CABTA localhost runtime is honest and usable, but dynamic sandbox detonation is not active on this machine.

The file-analysis lane remains valid for:

- hash reputation
- static analyzers
- YARA/static pivots
- non-executing local artifact analysis

It is not currently a full dynamic detonation workstation on this host.

## UI / Contract Verification

- Dashboard source health now separates `configured` from `available`
- URLScan now appears as `manual` instead of being implied to be live
- Sandbox status now reflects actual local capability instead of returning an empty surface
- Settings sandbox options now map to backend-supported values

## Unresolved Questions

- None.
