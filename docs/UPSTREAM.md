# Relationship to upstream

This repository is a fork of [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp),
maintained independently since upstream activity stopped after v3.0.3
(last upstream commit `799239f`, 2026-06-28).

The fork keeps upstream as the `upstream` remote and preserves contributor
authorship: upstream pull requests are adopted by merging the contributor's
original commits (never squashed) with `--no-ff`, adding any fixes as
separate commits on top. Each upstream PR head is also kept unmodified as a
read-only snapshot branch under `upstream/` so the work survives even if the
contributor's branch or the upstream PR disappears.

## Base

| Item | Value |
|---|---|
| Fork point | upstream `main` @ `799239f` (v3.0.3 line) |
| Forked on | 2026-09-03 |
| Protocol / SDK generation | MCP 2025-11-25 era: `mcp` 1.x, `fastmcp` 3.x (MCP 2026-07-28 / SDK 2.0 / fastmcp 4 not adopted) |

## Upstream pull requests

| Upstream PR | Author | Snapshot branch | Status in fork | Tracking |
|---|---|---|---|---|
| [#47](https://github.com/jtsylve/re-mcp/pull/47) Bump cryptography 49.0.0 → 50.0.0 | dependabot | `upstream/pr-47-cryptography-50` | **Merged** into `main` (`--no-ff`, commit `de66a55`) | — |
| [#46](https://github.com/jtsylve/re-mcp/pull/46) Add `analyze_database`, make `wait_for_analysis` run analysis on demand | [@shaiku](https://github.com/shaiku) | `upstream/pr-46-analyze-database` | **Merged** into `main` via `adopt/pr-46` with two fix commits (metadata refresh, error latch) and doc updates | [#4](https://github.com/offense360/eo-re-mcp/issues/4) adoption, [#5](https://github.com/offense360/eo-re-mcp/issues/5) follow-ups |
| [#48](https://github.com/jtsylve/re-mcp/pull/48) Expose Hex-Rays features (7 new IDA tools) | [@Absolucy](https://github.com/Absolucy) | `upstream/pr-48-hexrays-tools` | **Not adopted.** `set_call_type` and `set_stack_delta` do not match the Hex-Rays SDK contract; needs fixes and IDA runtime verification | [#6](https://github.com/offense360/eo-re-mcp/issues/6) |

### Verification performed before adoption

Every upstream PR was reviewed, then independently re-verified before merge:
static review, unit reproduction of each claimed defect under the existing
test stubs, and runtime experiments on the Ghidra backend (Ghidra 12.1.2)
where applicable. IDA Pro was not available, so IDA-only changes were checked
against the public IDA SDK headers, IDAPython SWIG sources and Hex-Rays
documentation. Details are in the tracking issues linked above.

## Defects found on upstream `main` (not from any PR)

| Issue | Summary |
|---|---|
| [#1](https://github.com/offense360/eo-re-mcp/issues/1) | Ghidra: `close_database` after `save_database` fails inside the worker (`Unable to lock due to active transaction`) but the supervisor reports `closed` |
| [#2](https://github.com/offense360/eo-re-mcp/issues/2) | `tests/test_tool_brief_budget.py` reads source with the locale codec; fails on non-UTF-8 Windows |
| [#3](https://github.com/offense360/eo-re-mcp/issues/3) | Documented `<PREFIX>LOG_DIR` is ignored; only `RE_MCP_LOG_DIR` / `IDA_MCP_LOG_DIR` are read |

## Syncing with upstream

If upstream resumes, `git fetch upstream && git merge upstream/main` on `main`.
Because adopted contributor commits are the same objects upstream would merge,
they de-duplicate cleanly; only the fork's own fix commits remain as
divergence and can be offered upstream as follow-up PRs.
