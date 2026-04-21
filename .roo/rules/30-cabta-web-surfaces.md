# CABTA Web Surfaces

Use this rule for CABTA's localhost web app and API-facing behavior.

## Scope

Primary areas:

- `CABTA/src/web/app.py`
- `CABTA/src/web/routes/`
- `CABTA/src/web/analysis_manager.py`
- `CABTA/src/web/case_store.py`
- `CABTA/templates/`
- `CABTA/static/`

## Web-specific rules

- Treat `CABTA/src/web/app.py` as the application wiring center.
- Preserve graceful startup when optional services are unavailable.
- Keep route-layer changes thin; business logic should stay in tools, agent services, workflow services, or dedicated web helpers.
- Do not let the UI imply capabilities that the runtime cannot actually provide.
- When changing result rendering, preserve the split between deterministic decision output and agentic explanation output.

## Typical change path

1. identify the affected route or page
2. trace the backing state or service
3. confirm the contract shape from the source module
4. update template and static assets only as needed
5. run focused API or web tests

## Common entry points

- `CABTA/src/web/routes/analysis.py`
- `CABTA/src/web/routes/chat.py`
- `CABTA/src/web/routes/cases.py`
- `CABTA/src/web/routes/workflows.py`
- `CABTA/templates/dashboard.html`
- `CABTA/templates/agent_chat.html`
- `CABTA/templates/workflows.html`

## Plan triggers

Create or update a plan when the change combines:

- backend plus template plus static asset work
- web plus agent or workflow changes
- new pages or multi-route features
- contract changes that affect existing templates or JavaScript

## Delivery checklist

- verify the page still matches live runtime capability
- keep error and degraded states explicit
- run the most relevant route or web tests
- update docs when behavior, setup, or visible workflows change
