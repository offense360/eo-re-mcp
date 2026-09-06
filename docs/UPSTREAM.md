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
| [#48](https://github.com/jtsylve/re-mcp/pull/48) Expose Hex-Rays features (7 new IDA tools) | [@Absolucy](https://github.com/Absolucy) | `upstream/pr-48-hexrays-tools` | **Merged** into `main` via `adopt/pr-48` (`--no-ff`, commit `5a017cb`, contributor commit `2fe5990` preserved) with five fix commits verified on IDA 9.4: `set_call_type` uses the call-site operand type (`set_op_tinfo`) and gained `clear_call_type`; stack deltas are recorded at the instruction end and only user points are deleted; `call_flags` kept on zero-argument calls; `_obj_string` guarded with `is_strlit`; `refresh_decompilation.was_cached` read via `has_cached_cfunc` | [#6](https://github.com/offense360/eo-re-mcp/issues/6) |

### Verification performed before adoption

Every upstream PR was reviewed, then independently re-verified before merge:
static review, unit reproduction of each claimed defect under the existing
test stubs, and runtime experiments on the Ghidra backend (Ghidra 12.1.2)
where applicable. For PR #46/#47 IDA Pro was not available, so IDA-only changes were checked
against the public IDA SDK headers, IDAPython SWIG sources and Hex-Rays
documentation. PR #48 was verified at runtime on an IDA Professional 9.4 machine
(idalib probes and MCP scenarios). Details are in the tracking issues linked above.

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
| [#6](https://github.com/offense360/eo-re-mcp/issues/6) | upstream | Adopt upstream PR #48 (Hex-Rays tools). Stage 1 confirmed all five review findings at runtime on IDA 9.4 (plus a sixth: `mark_cfunc_dirty` always returns true); stage 2 merged the contributor commit with the fixes and verified 12 MCP scenarios on the VM. | Done (5a017cb) |
| [#7](https://github.com/offense360/eo-re-mcp/issues/7) | core | Supervisor reported `closed` even when the worker's close/save failed; response now carries `close_error` | Fixed (4e60011) |
| [#8](https://github.com/offense360/eo-re-mcp/issues/8) | all | Already-analyzed databases were re-analyzed on first `wait_for_analysis`; backends now report `analyzed`, core seeds the flag. Also replaced the nonexistent `setAnalyzedFlag` call. | Fixed (3c3d755); IDA path unverified, see #12 |
| [#9](https://github.com/offense360/eo-re-mcp/issues/9) | Ghidra | Reopening a project whose program was never saved raised `FileNotFoundException`; now re-imports | Fixed (fbfcf51) |
| [#10](https://github.com/offense360/eo-re-mcp/issues/10) | Ghidra | `undo` / `redo` can never succeed under `GhidraProject`'s batch transaction (re-verified: `canUndo()` needs no open transaction; `program.undo()` raises). Tools removed on Ghidra, `capabilities.undo` added (`false` Ghidra, `true` IDA). | Fixed (dc9a90a) |
| [#18](https://github.com/offense360/eo-re-mcp/issues/18) | Ghidra | `Session` moved off `GhidraProject` (whose `importProgram*` are `@Deprecated(forRemoval)` since Ghidra 12.0) to pyghidra 3.x `open_project` / `consume_program` / `program_loader`. No standing transaction: `helpers.transaction()` aborts on error, saves go through `DomainFile.save`, `undo`/`redo` are back on Ghidra (`capabilities.undo` true), auto-analysis runs inline in one transaction and clears the undo history. Spike then implementation, 5 commits. | Fixed (49544c6) |
| [#11](https://github.com/offense360/eo-re-mcp/issues/11) | Ghidra | Confirmed at runtime: an aborted nested tool transaction marked `GhidraProject`'s batch transaction ABORTED and `save` rolled back every change since the last save. All mutations now go through `helpers.transaction()`, which never aborts; validation moved ahead of mutation in six tools. | Fixed (c6d6b91) |
| [#12](https://github.com/offense360/eo-re-mcp/issues/12) | IDA | Verify #8's `analyzed` signal on IDA. Verified on IDA 9.4 (steps 1, 2, 4 and `force_new` passed); step 3 exposed #23 and passes since its fix. | Fixed (a7e87d9) |
| [#13](https://github.com/offense360/eo-re-mcp/issues/13) | Ghidra | Three tools could leave a partial change when they failed after their first mutation (residual from #11). Resolved by #18: tool transactions are outermost and roll back on failure; verified at runtime for `make_string`, `parse_type_declaration`, `set_function_type`. | Fixed (49544c6) |
| [#14](https://github.com/offense360/eo-re-mcp/issues/14) | Ghidra | `transaction()` WARNING fired on pure validation failures. Validation moved ahead of the `with` block in four tools, warning now names the exception, and an AST test (`tests/test_ghidra_transaction_hygiene.py`) guards the pattern with an explicit allow-list for the #13 sites. | Fixed (32e9490) |
| [#15](https://github.com/offense360/eo-re-mcp/issues/15) | scripts | Source/config files read with the locale codec in `lint_ida_threading.py`, both backends' config loaders and `daemon.py`; now UTF-8 | Fixed (32e9490) |
| [#16](https://github.com/offense360/eo-re-mcp/issues/16) | tooling | pre-commit chain cannot pass on Windows. The 7 genuinely POSIX-only tests are skipped via the `posix_only` marker (abbb268); the other 8 Windows failures were real defects fixed in #19 and #20. `reuse` hook works via its pre-commit mirror. Windows: 0 failures, `pre-commit run --all-files` green. | Fixed (afe39de) |
| [#17](https://github.com/offense360/eo-re-mcp/issues/17) | Ghidra | Install-dir discovery skipped stale sources silently and never saw pyghidra's `lastrun` fallback (the real source of the #11 "does not exist"); `bootstrap()` used `setdefault`, so a stale `GHIDRA_INSTALL_DIR` beat a valid config. `locate_ghidra()` now reports every source (lastrun added as the last one), warns on stale ones, exports the found dir unconditionally, and the supervisor fails fast with `NotFound` listing the locations checked. | Fixed (4a35129) |
| [#19](https://github.com/offense360/eo-re-mcp/issues/19) | IDA | Error messages embed paths with `!r`, doubling backslashes on Windows; also fails 6 `test_exceptions.py` tests. Fix the code, keep the tests. | Fixed (afe39de) |
| [#20](https://github.com/offense360/eo-re-mcp/issues/20) | tests | Two proxy tests are Windows-hostile (`signal.SIGKILL` in a Windows-targeted test, unescaped path regex) | Fixed (afe39de) |
| [#21](https://github.com/offense360/eo-re-mcp/issues/21) | Ghidra | Stale install-dir WARNING repeated on every `locate_ghidra()` call (residual from #17); now once per process per (source, path), DEBUG afterwards. `describe()` unchanged. | Fixed (b133ab1) |
| [#22](https://github.com/offense360/eo-re-mcp/issues/22) | Ghidra | Headless analysis logged a `GhidraScriptUtil.bundleHost` NPE and silently skipped script-based analyzers (pre-existing since upstream). The worker now acquires the script bundle host once before its first analysis pass and keeps it. | Fixed (67eb7df) |
| [#23](https://github.com/offense360/eo-re-mcp/issues/23) | IDA | `Session.close()` emptied every auto-analysis queue before saving, so an unanalyzed `.i64` reported `auto_is_ok()` true on reopen, the #8 seed skipped analysis and even `analyze_database` was a no-op. The queue is now kept on close and `Session.analyze()` re-plans the whole program when nothing is queued. | Fixed (a7e87d9) |
| [#24](https://github.com/offense360/eo-re-mcp/issues/24) | core | Design question: `open_database(run_auto_analysis=True)` on an already-analyzed database forces one full re-analysis (IDA since #23, Ghidra always); decide whether to skip when the worker reports `analyzed`. Not a double pass (first wording corrected). | Closed, keep current behaviour (decision 2026-09-06) |
| [#25](https://github.com/offense360/eo-re-mcp/issues/25) | IDA | IDA 9.4 deprecates the `func_t *`-based `ida_funcs`/`ida_frame` API (~30 call sites); replacements are 9.4-only. Decision 2026-09-06: keep the current API; migrate and raise the floor to 9.4 when Hex-Rays announces removal or a 9.4-only API is needed. | Deferred, trigger: removal notice or 9.4-only feature |
| [#26](https://github.com/offense360/eo-re-mcp/issues/26) | IDA | IDA: undo/redo report 'Nothing to undo' after rename/comment/type changes; only patch_bytes/patch_asm create undo points, and undo then reverts every change since that point (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#27](https://github.com/offense360/eo-re-mcp/issues/27) | Ghidra | Ghidra: get_database_info.max_address is the raw offset of the highest address in any address space (ELF reports 0x77F below min_address 0x100000) (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#28](https://github.com/offense360/eo-re-mcp/issues/28) | Ghidra | Ghidra: an address above 2^63-1 leaks 'int too big to convert' (OverflowError) with no error_type (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#29](https://github.com/offense360/eo-re-mcp/issues/29) | Ghidra | Ghidra: get_database_info.function_count (2006) disagrees with list_functions.total (1775) because external functions are counted only by the former (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#30](https://github.com/offense360/eo-re-mcp/issues/30) | Ghidra | Ghidra: get_xrefs_from renders stack/register references as absolute addresses (to_address "0x8", ref_type WRITE) (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#31](https://github.com/offense360/eo-re-mcp/issues/31) | Ghidra | Ghidra: get_database_info.file_path is Ghidra's '/C:/...' executable path while open_database/list_databases return the OS path (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#32](https://github.com/offense360/eo-re-mcp/issues/32) | IDA | IDA: parse_type_declaration failures say only 'Failed to parse declaration' (Ghidra returns the parser's message) (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#33](https://github.com/offense360/eo-re-mcp/issues/33) | IDA | IDA: rename_function and set_comment failures do not say why ('Failed to rename function to ...', 'Failed to set comment at 0x1') (bug; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#34](https://github.com/offense360/eo-re-mcp/issues/34) | core | core: batch with a failing operation returns the whole BatchResult as a JSON string inside the error (triple-encoded), even with stop_on_error=False (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#35](https://github.com/offense360/eo-re-mcp/issues/35) | IDA | IDA: list_local_types has no filter_pattern (Ghidra's does) — pinned tool with different parameters (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#36](https://github.com/offense360/eo-re-mcp/issues/36) | all | set_type on a function address: IDA applies the prototype, Ghidra rejects it with "Unknown data type: '<whole prototype>'" and does not point at set_function_type (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#37](https://github.com/offense360/eo-re-mcp/issues/37) | all | find_code_by_string returns different shapes per backend (Ghidra: paginated items with code_address; IDA: total_strings_scanned/unique_functions, no code_address) (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#38](https://github.com/offense360/eo-re-mcp/issues/38) | all | get_database_info: IDA exposes entry_point, Ghidra does not (client must search_tools → call get_entry_points); other fields differ too (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#39](https://github.com/offense360/eo-re-mcp/issues/39) | Ghidra | Ghidra: undo/redo responses do not say what was undone; reverting one rename after a normal session took 6 blind undo calls (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#40](https://github.com/offense360/eo-re-mcp/issues/40) | IDA | IDA: get_pseudocode_line_map is 3-4x slower than decompile_function on a 1412-line function (4.9-9.8 s vs 1.7-2.3 s) (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#41](https://github.com/offense360/eo-re-mcp/issues/41) | all | disassemble_function / decompile_function have no pagination or size cap: 478 KB and 123 KB responses for the largest ELF function (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |
| [#42](https://github.com/offense360/eo-re-mcp/issues/42) | Ghidra | Ghidra: decompiled_code uses CR LF line endings on Windows while IDA pseudocode uses LF (enhancement; found in the 2026-09-06 real-usage run on `curl.exe` / WSL `curl`) | Open |

### Continuous integration on the fork

The upstream `ci.yml` (reuse, lint, test, build on `ubuntu-latest`) is kept
as-is, with `workflow_dispatch` added so a Linux run can be requested for any
branch:

```
gh workflow run CI -R offense360/eo-re-mcp --ref <branch>
```

Linux is the reference for the full test suite: as of 9e364b6 the `test` job
reports 792 passed, 0 skipped. Windows is the development platform; its
baseline is documented below.

### Known constraints of this environment

- Only the Ghidra backend (12.1.2) can be exercised at runtime here; IDA-only
  changes are reviewed statically against the IDA SDK headers and IDAPython
  sources. Issues #6 and #12 wait on an IDA installation.
- Windows test baseline: 0 failures on Windows; 7 POSIX-only tests skipped
  with named reasons (`posix_only` marker / `skipif(sys.platform == "win32")`
  in `tests/conftest.py`), all run on Linux CI. Any failure on Windows is a
  regression.

## Syncing with upstream

If upstream resumes, `git fetch upstream && git merge upstream/main` on `main`.
Because adopted contributor commits are the same objects upstream would merge,
they de-duplicate cleanly; only the fork's own fix commits remain as
divergence and can be offered upstream as follow-up PRs.
