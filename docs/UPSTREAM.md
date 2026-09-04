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

## Fork issue log

Issues are the unit of work in this fork. Each fix lands as a `--no-ff` merge of
a branch whose commits were written test-first and, where a backend is
available, verified at runtime; the issue's closing comment holds the runtime
evidence. Status as of 2026-09-04.

| Issue | Area | Summary | Status |
|---|---|---|---|
| [#1](https://github.com/offense360/eo-re-mcp/issues/1) | Ghidra | Second save inside `close_database` failed with `Unable to lock due to active transaction`. Root cause: `GhidraProject` holds a permanent batch transaction that only `GhidraProject.save` ends; `session.save()` bypassed it. Also split `close_error` into message + `close_error_type`. | Fixed (d89a96d) |
| [#2](https://github.com/offense360/eo-re-mcp/issues/2) | tests | `test_tool_brief_budget` read source with the locale codec | Fixed (ce11725) |
| [#3](https://github.com/offense360/eo-re-mcp/issues/3) | core | `GHIDRA_MCP_*` logging variables ignored (`LOG_DIR` everywhere; `LOG_RUN`, `LABEL`, `LOG_LEVEL` in workers); process-wide env prefix added | Fixed (cca50e3) |
| [#4](https://github.com/offense360/eo-re-mcp/issues/4) | upstream | Adopt upstream PR #46 with fixes for explicit-call metadata and error latch | Done (6a4ce8c) |
| [#5](https://github.com/offense360/eo-re-mcp/issues/5) | core | Analysis state tracked as one task for all start paths: no double analysis, spawn window closed, on-demand notifications | Fixed (e3471d5) |
| [#6](https://github.com/offense360/eo-re-mcp/issues/6) | upstream | Track upstream PR #48; not adopted pending `set_call_type` / `set_stack_delta` fixes and IDA verification | Open, needs IDA |
| [#7](https://github.com/offense360/eo-re-mcp/issues/7) | core | Supervisor reported `closed` even when the worker's close/save failed; response now carries `close_error` | Fixed (4e60011) |
| [#8](https://github.com/offense360/eo-re-mcp/issues/8) | all | Already-analyzed databases were re-analyzed on first `wait_for_analysis`; backends now report `analyzed`, core seeds the flag. Also replaced the nonexistent `setAnalyzedFlag` call. | Fixed (3c3d755); IDA path unverified, see #12 |
| [#9](https://github.com/offense360/eo-re-mcp/issues/9) | Ghidra | Reopening a project whose program was never saved raised `FileNotFoundException`; now re-imports | Fixed (fbfcf51) |
| [#10](https://github.com/offense360/eo-re-mcp/issues/10) | Ghidra | `undo` / `redo` can never succeed under `GhidraProject`'s batch transaction | Open |
| [#11](https://github.com/offense360/eo-re-mcp/issues/11) | Ghidra | Confirmed at runtime: an aborted nested tool transaction marked `GhidraProject`'s batch transaction ABORTED and `save` rolled back every change since the last save. All mutations now go through `helpers.transaction()`, which never aborts; validation moved ahead of mutation in six tools. | Fixed (c6d6b91) |
| [#12](https://github.com/offense360/eo-re-mcp/issues/12) | IDA | Verify #8's `analyzed` signal (`sidecar_exists and auto_is_ok()`) on a machine with IDA | Open, needs IDA |
| [#13](https://github.com/offense360/eo-re-mcp/issues/13) | Ghidra | Three tools can still leave a partial change when they fail after their first mutation (residual from #11) | Open |
| [#14](https://github.com/offense360/eo-re-mcp/issues/14) | Ghidra | `transaction()` WARNING fires on pure validation failures; move validation ahead of the `with` block | Open |
| [#15](https://github.com/offense360/eo-re-mcp/issues/15) | scripts | `lint_ida_threading.py` reads sources without an encoding | Open |
| [#16](https://github.com/offense360/eo-re-mcp/issues/16) | tooling | pre-commit chain cannot pass on Windows (15 platform-specific pytest failures, `reuse` not installed) | Open |
| [#17](https://github.com/offense360/eo-re-mcp/issues/17) | Ghidra | Warn when a configured Ghidra install dir does not exist instead of failing with `SpawnFailed` | Open |

### Known constraints of this environment

- Only the Ghidra backend (12.1.2) can be exercised at runtime here; IDA-only
  changes are reviewed statically against the IDA SDK headers and IDAPython
  sources. Issues #6 and #12 wait on an IDA installation.
- The Windows test baseline has 15 platform-specific failures (POSIX signals,
  symlinks, `chmod`, macOS/Linux state directories). Any other failure is a
  regression.

## Syncing with upstream

If upstream resumes, `git fetch upstream && git merge upstream/main` on `main`.
Because adopted contributor commits are the same objects upstream would merge,
they de-duplicate cleanly; only the fork's own fix commits remain as
divergence and can be offered upstream as follow-up PRs.
