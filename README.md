# eo-re-mcp

eo-re-mcp is a multi-backend reverse-engineering [MCP](https://modelcontextprotocol.io/) server, maintained as a fork of [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp). It exposes binary analysis capabilities from [IDA Pro](https://hex-rays.com/ida-pro/) and [Ghidra](https://ghidra-sre.org/) over the Model Context Protocol, letting LLMs drive reverse-engineering tools directly. Supports multiple simultaneous databases through a supervisor/worker architecture.

Both backends are standalone servers, not plugins. They use headless APIs ([idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) for IDA, [pyghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) for Ghidra) to run analysis engines without a GUI.

## About this fork

**eo-re-mcp** is a maintained fork of [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp), forked from upstream `main` at `799239f` (the v3.0.3 line, upstream's last commit on 2026-06-28 UTC). Upstream has been inactive since then. The relationship is documented in detail in [docs/UPSTREAM.md](docs/UPSTREAM.md).

- **Distribution names and versions.** The packages are published as `eo-re-mcp-core`, `eo-re-mcp-ida`, `eo-re-mcp-ghidra` and `eo-re-mcp`, versioned from 1.0.0, so they never collide with upstream's `re-mcp-*` numbers. Import names (`re_mcp`, `re_mcp_ida`, `re_mcp_ghidra`), CLI names (`re-mcp`, `re-mcp-ida`, `re-mcp-ghidra`) and MCP client configurations are unchanged. The fork is **not on PyPI**: `pip install re-mcp-ida` installs upstream's last release, not this fork. Install from the wheels attached to a [GitHub release](https://github.com/offense360/eo-re-mcp/releases) or from source (see Installation).
- **Upstream pull requests.** All three pull requests open on upstream are merged here with their authors' commits preserved: [#46](https://github.com/jtsylve/re-mcp/pull/46) `analyze_database` / on-demand analysis in `wait_for_analysis` (@shaiku), [#47](https://github.com/jtsylve/re-mcp/pull/47) cryptography 50 (dependabot), and [#48](https://github.com/jtsylve/re-mcp/pull/48) seven Hex-Rays tools for IDA (@Absolucy), each with follow-up fixes verified on IDA 9.4 / Ghidra 12.1.2.
- **Upstream bugs fixed.** Real-usage verification of both backends on IDA Pro 9.4 and Ghidra 12.1.2 found and fixed more than thirty defects inherited from upstream, among them: Ghidra saves and undo/redo broken by `GhidraProject`'s permanent transaction, IDA's auto-analysis queue discarded on close, imported symbols rendered as slot offsets, `batch` errors triple-encoded, unpaginated 478 KB disassembly responses, and error messages that did not say why a rename, comment or type declaration failed. The complete list with the fix commits is the issue table in [docs/UPSTREAM.md](docs/UPSTREAM.md); each release's notes list what changed.

## Backends

| Backend | Package | Requirements |
|---------|---------|--------------|
| **IDA Pro** | [`eo-re-mcp-ida`](packages/re-mcp-ida/) | IDA Pro 9+ with a valid license |
| **Ghidra** | [`eo-re-mcp-ghidra`](packages/re-mcp-ghidra/) | Ghidra 12+, JDK 21+ |

Both backends share a common tool interface — core analysis tools use the same names, parameters, and response shapes — so LLM workflows are portable across backends. Each backend also has tools for platform-specific features (e.g. IDA: file region mapping, executable rebuilding, IDC evaluation, IDAPython scripting; Ghidra: Function ID analysis, data type archives).

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip
- macOS, Windows, or Linux
- At least one supported backend installed on the same machine

## Installation

eo-re-mcp is not on PyPI (`pip install re-mcp-ida` installs upstream's last release). Install the backend packages you need from the wheels attached to a [GitHub release](https://github.com/offense360/eo-re-mcp/releases), or from source. Every backend needs `eo-re-mcp-core` alongside it; the core package also provides the unified `re-mcp` CLI, which selects a backend with `--backend`.

### From a GitHub release

Download the wheels from the [releases page](https://github.com/offense360/eo-re-mcp/releases) into the current directory, then:

```bash
# Individual backend packages (each provides its own CLI)
uv tool install ./eo_re_mcp_ida-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl
uv tool install ./eo_re_mcp_ghidra-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl

# Or install the core package and use --backend to select
uv tool install ./eo_re_mcp_core-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ida-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ghidra-1.0.0-py3-none-any.whl
```

With pip:

```bash
pip install eo_re_mcp_core-1.0.0-py3-none-any.whl eo_re_mcp_ida-1.0.0-py3-none-any.whl     # IDA only
pip install eo_re_mcp_core-1.0.0-py3-none-any.whl eo_re_mcp_ghidra-1.0.0-py3-none-any.whl  # Ghidra only
pip install eo_re_mcp_core-1.0.0-py3-none-any.whl eo_re_mcp_ida-1.0.0-py3-none-any.whl eo_re_mcp_ghidra-1.0.0-py3-none-any.whl  # Both backends and the unified CLI
```

### From source

```bash
git clone https://github.com/offense360/eo-re-mcp && cd eo-re-mcp
uv sync
```

Or with pip:

```bash
git clone https://github.com/offense360/eo-re-mcp && cd eo-re-mcp
pip install -e packages/re-mcp-core -e packages/re-mcp-ida -e packages/re-mcp-ghidra
```

### Finding IDA Pro

The IDA backend looks for your IDA Pro installation in the following order:

1. **`IDADIR` environment variable** — checked first; set this if IDA is in a non-standard location.
2. **IDA's own config file** — `Paths.ida-install-dir` in `~/.idapro/ida-config.json` (macOS/Linux) or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows). If the `IDAUSR` environment variable is set, it is used as the config directory instead.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/IDA Professional *.app/Contents/MacOS` |
| Windows  | `C:\Program Files\IDA Professional 9.3`, `C:\Program Files\IDA Pro 9.3`, and `Program Files (x86)` equivalents |
| Linux    | `/opt/ida-pro-9.3`, `/opt/idapro-9.3`, `/opt/ida-9.3`, `~/ida-pro-9.3`, `~/idapro-9.3` |

The `idapro` package is loaded at runtime directly from your local IDA Pro installation — no extra setup steps or environment variables are needed if IDA is installed in a standard location.

### Finding Ghidra

The Ghidra backend looks for your Ghidra installation in the following order:

1. **`GHIDRA_INSTALL_DIR` environment variable** — checked first; set this if Ghidra is in a non-standard location.
2. **Config file** — `ghidra-install-dir` in `~/.ghidra/ghidra-config.json`.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/ghidra_*`, `~/ghidra_*` |
| Windows  | `C:\ghidra_*`, `~/ghidra_*` |
| Linux    | `/opt/ghidra_*`, `/usr/local/ghidra_*`, `~/ghidra_*` |

4. **pyghidra's `lastrun` file** — the directory Ghidra itself last ran from, read from `$XDG_CONFIG_HOME/ghidra/lastrun` if `XDG_CONFIG_HOME` is set, otherwise `%APPDATA%\ghidra\lastrun` (Windows), `~/Library/ghidra/lastrun` (macOS) or `~/.config/ghidra/lastrun` (Linux).

A configured location that does not exist is logged as a WARNING and skipped; if nothing is found, `open_database` and `list_targets` fail immediately with the list of locations checked.

## Usage

### Running the server

Each backend has its own CLI, or use the unified `re-mcp` command with `--backend`:

```bash
# Individual backend CLIs
re-mcp-ida
re-mcp-ghidra

# Unified CLI (requires backend package installed alongside)
re-mcp --backend ida
re-mcp --backend ghidra
```

Both CLIs support the same subcommands:

| Command | Description |
|---------|-------------|
| `<backend>` (or `<backend> stdio`) | Direct stdio mode — single-session, workers die on disconnect (default) |
| `<backend> proxy` | Stdio proxy that auto-spawns a persistent HTTP daemon |
| `<backend> serve` | Start the HTTP daemon directly (for manual daemon management) |
| `<backend> stop` | Gracefully shut down a running daemon |
| `<backend> backends` | List installed backends (most useful with the unified `re-mcp` CLI) |

The default mode runs a direct stdio server — the simplest transport, widely supported across MCP clients. Workers die when the client disconnects.

For persistent state across reconnections, use `<backend> proxy`. This mode auto-spawns a persistent HTTP daemon behind the scenes, handling port allocation and authentication transparently. Workers and database state survive client reconnections. The daemon shuts down automatically after 5 minutes of inactivity (configurable via `<PREFIX>IDLE_TIMEOUT`).

### Running without installing

`uvx` can run the release wheels directly (`--from` names the wheel that provides the command, `--with` adds the core package):

```bash
# Individual backend packages
IDADIR=/path/to/ida uvx --from ./eo_re_mcp_ida-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl re-mcp-ida
GHIDRA_INSTALL_DIR=/path/to/ghidra uvx --from ./eo_re_mcp_ghidra-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl re-mcp-ghidra

# Unified package
IDADIR=/path/to/ida uvx --from ./eo_re_mcp_core-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ida-1.0.0-py3-none-any.whl re-mcp --backend ida
GHIDRA_INSTALL_DIR=/path/to/ghidra uvx --from ./eo_re_mcp_core-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ghidra-1.0.0-py3-none-any.whl re-mcp --backend ghidra
```

```powershell
# Individual backend packages
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx --from ./eo_re_mcp_ida-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl re-mcp-ida

$env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.0.3_PUBLIC"
uvx --from ./eo_re_mcp_ghidra-1.0.0-py3-none-any.whl --with ./eo_re_mcp_core-1.0.0-py3-none-any.whl re-mcp-ghidra

# Unified package
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx --from ./eo_re_mcp_core-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ida-1.0.0-py3-none-any.whl re-mcp --backend ida
```

### MCP client configuration

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`). The examples use the installed command names (`uv tool install` and `pip install` both put them on your `PATH`):

**IDA backend:**

```json
{
  "mcpServers": {
    "ida": {
      "command": "re-mcp-ida"
    }
  }
}
```

**Ghidra backend:**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "re-mcp-ghidra"
    }
  }
}
```

**Both backends simultaneously:**

```json
{
  "mcpServers": {
    "ida": {
      "command": "re-mcp-ida"
    },
    "ghidra": {
      "command": "re-mcp-ghidra"
    }
  }
}
```

**Using the unified `re-mcp` CLI (when installed via `uv tool install ./eo_re_mcp_core-1.0.0-py3-none-any.whl --with ./eo_re_mcp_ida-1.0.0-py3-none-any.whl`):**

```json
{
  "mcpServers": {
    "ida": {
      "command": "re-mcp",
      "args": ["--backend", "ida"]
    }
  }
}
```

If the command isn't on your `PATH`, use the full path to the executable:

```json
{
  "mcpServers": {
    "ida": {
      "command": "/home/user/.pyenv/versions/<version>/bin/re-mcp-ida"
    }
  }
}
```

If the backend (IDA or Ghidra) isn't in a default location, add the install directory via the `env` key:

```json
{
  "mcpServers": {
    "ida": {
      "command": "re-mcp-ida",
      "env": {
        "IDADIR": "/path/to/ida"
      }
    },
    "ghidra": {
      "command": "re-mcp-ghidra",
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra"
      }
    }
  }
}
```

**Connecting to a running daemon directly:**

If you started the daemon manually with `<backend> serve`, the connection details (host, port, bearer token) are in the state file. Clients that support streamable HTTP can connect directly.

State file locations:
- **macOS:** `~/Library/Application Support/<backend>/daemon.json`
- **Linux:** `$XDG_STATE_HOME/<backend>/daemon.json` (defaults to `~/.local/state/<backend>/daemon.json`)
- **Windows:** `%LOCALAPPDATA%\<backend>\daemon.json`

Where `<backend>` is `re-mcp-ida` or `re-mcp-ghidra`.

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:<port>/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

### Basic workflow

1. **Open a binary** — call `open_database` with the path to a binary (or existing database file), then `wait_for_analysis` to block until it is ready
2. **Analyze** — use the available tools (list functions, decompile, search strings, read bytes, etc.)
3. **Close** — call `close_database` when done (auto-saves by default)

Raw binaries must be in a writable directory since both backends create database files alongside them. When opening an existing database, the original binary does not need to be present.

### Multi-database mode

Multiple databases can be open at the same time. By default, `open_database` keeps previously opened databases open. Pass `keep_open=False` to save and close databases owned by the current session before opening the new one. All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) require the `database` parameter (the stem ID returned by `open_database` or `list_databases`).

```
open_database("first.bin")                              # spawns worker (returns immediately)
wait_for_analysis(database="first")                     # blocks until ready
open_database("second.bin")                             # spawns second worker
wait_for_analysis(database="second")                    # blocks until ready
decompile_function(address="main", database="first")    # targets first
close_database(database="second")                       # closes second
```

### Environment variables

Each backend uses its own environment variable prefix (`IDA_MCP_` or `GHIDRA_MCP_`). The table below uses `<PREFIX>` as a placeholder. For the logging settings (`LOG_LEVEL`, `LOG_DIR`, `LOG_RUN`, `LABEL`), the backend-neutral `RE_MCP_*` name is accepted as an alias and `IDA_MCP_*` as a legacy fallback; when several are set, the backend prefix wins, then `RE_MCP_*`, then `IDA_MCP_*`.

**Backend installation:**

| Variable | Backend | Default | Description |
|----------|---------|---------|-------------|
| `IDADIR` | IDA | *(auto-detected)* | Path to IDA Pro installation directory |
| `GHIDRA_INSTALL_DIR` | Ghidra | *(auto-detected)* | Path to Ghidra installation directory |

**Shared settings** (replace `<PREFIX>` with `IDA_MCP_` or `GHIDRA_MCP_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `<PREFIX>MAX_WORKERS` | *(unlimited)* | Maximum simultaneous databases (clamped to 1-8 when set) |
| `<PREFIX>LOG_LEVEL` | `WARNING` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) — output goes to stderr |
| `<PREFIX>LOG_DIR` | *(unset)* | Directory for per-run log files. Each component logs to `<dir>/<run_id>-<label>.log`, each worker to `<dir>/<run_id>-worker-<db>.log`, and each worker's raw stderr to `<dir>/<run_id>-worker-<db>.stderr`. When unset, logs go only to stderr. |
| `<PREFIX>IDLE_TIMEOUT` | `300` | Idle auto-shutdown timeout in seconds for auto-spawned daemons. Set to `0` to disable. `<backend> serve` defaults to `0` (use `--idle-timeout=N` to override). |
| `<PREFIX>DISABLE_EXECUTE` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `execute` meta-tool (sandboxed Python code mode) |
| `<PREFIX>DISABLE_BATCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `batch` meta-tool |
| `<PREFIX>DISABLE_TOOL_SEARCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to disable server-side progressive tool disclosure — all tools become directly visible and callable, and the `search_tools` and `get_schema` meta-tools are removed. Useful with clients that provide their own tool deferral (e.g. Claude Code). |

**IDA-only settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable the `run_script` tool for arbitrary IDAPython execution |

## Tools

To keep token usage manageable, only common analysis tools and management tools are directly visible to clients. The rest are discoverable and callable through meta-tools:

- **`search_tools`** — regex search over non-pinned tool names, descriptions, and tags (pinned tools are already visible).
- **`get_schema`** — parameter schemas and return shapes for tools by name.
- **`call`** — lightweight proxy for calling any tool by name, including hidden tools not in the client tool list.
- **`execute`** — sandboxed Python that chains multiple `await invoke(name, params)` calls in a single round trip. Supports `asyncio.gather` for parallel queries, loops, and conditional logic between calls.
- **`batch`** — sequential multi-tool execution with per-item error collection and progress reporting (up to 50 operations per call).

Management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) are always visible. Most must be called directly — `save_database` and `list_databases` are the exceptions, also callable through `call`, `execute`, and `batch` for use in multi-step workflows.

The full tool catalog spans these areas:

- **Database** — open/close/save/list databases, file region mapping, metadata
- **Functions** — list, query, decompile, disassemble, rename, prototypes, chunks, stack frames
- **Decompiler** — pseudocode variable renaming/retyping, decompiler comments, microcode
- **Ctree** — AST exploration and pattern matching
- **Cross-References** — xref queries, call graphs, xref creation/deletion
- **Imports & Exports** — imported functions, exported symbols, entry point listing and manipulation
- **Search** — string extraction, byte patterns, text in disassembly, immediate values, string-to-code references, string list rebuilding
- **Types & Structures** — local types, structs, enums, type parsing and application, source declarations
- **Instructions & Operands** — decode instructions, resolve operand values, change operand display format
- **Control Flow** — basic blocks, CFG edges, switch/jump tables
- **Data** — raw byte reading, hex dumps, segment listing, pointer tables
- **Patching** — byte patching, instruction assembly, function/code creation, data loading
- **Data Definition** — define bytes, words, dwords, qwords, floats, doubles, strings, and arrays
- **Segments** — create, modify, and rebase segments
- **Names & Comments** — rename addresses, manage comments (get, set, and append)
- **Demangling** — C++ symbol name demangling
- **Analysis** — auto-analysis, fixups, exception handlers, segment registers
- **Address Metadata** — source line numbers, analysis flags, library item marking
- **Register Tracking** — register and stack pointer value tracking
- **Register Variables** — register-to-name mappings within functions
- **Signatures** — FLIRT signatures/type libraries (IDA), Function ID/data type archives (Ghidra)
- **Export** — batch decompilation/disassembly, output file generation
- **Snapshots** — take, list, and restore database snapshots
- **Processor** — architecture info, register names, instruction classification
- **Bookmarks** — marked-position management
- **Colors** — address/function coloring
- **Undo** — undo/redo operations
- **Directory Tree** — folder organization
- **Utility** — number conversion, expression evaluation, scripting

All tools include MCP [annotations](https://modelcontextprotocol.io/docs/concepts/tools#annotations) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can distinguish safe reads from mutations and prompt for confirmation on destructive operations. Mutation tools return old values alongside new values for change tracking.

See [docs/tools.md](docs/tools.md) for the complete tools reference.

## Resources

The server exposes [MCP resources](https://modelcontextprotocol.io/docs/concepts/resources) — read-only, cacheable endpoints for structured database context:

- **Static binary data** — imports, exports, entry points (with regex search variants)
- **Aggregate snapshot** — statistics (function/segment/entry point/string/name counts, code coverage)
- **Supervisor** — `<scheme>://databases` lists all open databases with worker state

The URI scheme is `ida://` for the IDA backend and `ghidra://` for the Ghidra backend.

## Prompts

The server provides [MCP prompts](https://modelcontextprotocol.io/docs/concepts/prompts) — guided workflow templates that instruct the LLM to use tools in a structured sequence. Prompts are currently available for the IDA backend only.

- **`survey_binary`** — binary triage producing an executive summary
- **`analyze_function`** — full single-function analysis with decompilation, data flow, and behavior summary
- **`diff_before_after`** — preview the effect of renaming/retyping on decompiler output
- **`classify_functions`** — categorize functions by behavioral pattern
- **`find_crypto_constants`** — scan for known cryptographic constants
- **`auto_rename_strings`** — suggest function renames based on string references
- **`apply_abi`** — apply known ABI type information to identified functions
- **`export_idc_script`** — generate a script that reproduces user annotations

## Architecture

The project is a monorepo with three packages:

- [`eo-re-mcp-core`](packages/re-mcp-core/) — shared supervisor infrastructure, transport, and common utilities
- [`eo-re-mcp-ida`](packages/re-mcp-ida/) — IDA Pro backend
- [`eo-re-mcp-ghidra`](packages/re-mcp-ghidra/) — Ghidra backend

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Development

```bash
# With uv (recommended)
uv sync                              # Install dependencies
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix

# With pip
pip install -e packages/re-mcp-core -e packages/re-mcp-ida -e packages/re-mcp-ghidra
pip install pre-commit pytest pytest-asyncio ruff jsonschema
ruff check packages/
ruff format packages/
ruff check --fix packages/
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint, and pytest on every commit.

## License

This project is dual-licensed under the [MIT License](LICENSES/MIT.txt) and [Apache License 2.0](LICENSES/Apache-2.0.txt).

© 2026 Joe T. Sylve, Ph.D.

This project is [REUSE compliant](https://reuse.software/).

---

*IDA Pro and Hex-Rays are trademarks of Hex-Rays SA. Ghidra is developed by the NSA. eo-re-mcp is an independent project and is not affiliated with or endorsed by Hex-Rays or the NSA.*
