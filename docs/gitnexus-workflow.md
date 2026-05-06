# GitNexus - optional code intelligence workflow

Use this when the **GitNexus MCP server** (or CLI) is available in your environment. If GitNexus is not connected, use normal search, tests, and code reading instead - do not block small edits on missing GitNexus.

This project may be indexed as **claudekit-engi** in GitNexus. Use GitNexus tools to understand code, assess impact, and navigate safely when the integration is active.

> Before serious code tasks, check GitNexus index freshness with repo context or a safe read tool. If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in the terminal before relying on GitNexus output.

## Recommended when GitNexus is available

- **Before larger refactors:** consider `gitnexus_impact` on the symbol you change to see blast radius (callers, processes, risk).
- **Before commits (optional):** `gitnexus_detect_changes()` can help verify scope of symbol/flow impact.
- **Exploration:** `gitnexus_query` / `gitnexus_context` can complement grep for execution-flow-oriented navigation.
- **HIGH or CRITICAL risk:** warn the user and proceed carefully.

## Avoid when GitNexus is unavailable

- Do not block small, local edits on GitNexus.
- Use find-references, tests, and careful search — do not treat missing MCP as an error.

## Resources (when indexed)

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/claudekit-engi/context` | Codebase overview, index freshness |
| `gitnexus://repo/claudekit-engi/clusters` | Functional areas |
| `gitnexus://repo/claudekit-engi/processes` | Execution flows |
| `gitnexus://repo/claudekit-engi/process/{name}` | Step-by-step trace |

## CLI / skills

| Task | Skill file |
|------|------------|
| Explore architecture | `.cursor/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Impact / blast radius | `.cursor/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Debug / trace failures | `.cursor/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Refactor / rename safely | `.cursor/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, schema | `.cursor/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index / wiki CLI | `.cursor/skills/gitnexus/gitnexus-cli/SKILL.md` |
