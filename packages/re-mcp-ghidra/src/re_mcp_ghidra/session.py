# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database session manager for Ghidra via pyghidra.

Tracks whether a program is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import os
import shutil
import signal

from re_mcp_ghidra.exceptions import GhidraError

log = logging.getLogger(__name__)

_PROJECT_SUBDIR = "ghidra_projects"


class Session:
    """Singleton managing the Ghidra program session."""

    def __init__(self):
        self._program = None
        self._project = None
        self._project_location = None
        self._current_path: str | None = None
        self._flat_api = None
        # The Java object that "consumes" the open program.  Ghidra disposes a
        # DomainObject only once every consumer has released it, so the session
        # holds exactly one and releases it in close() *before* the project is
        # closed; otherwise DefaultProjectData defers dispose and the project
        # .lock file survives.
        self._consumer = None
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self._current_path is not None and self._program is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    @property
    def program(self):
        return self._program

    @property
    def flat_api(self):
        return self._flat_api

    def open(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
    ) -> dict:
        """Open a binary for analysis.

        Uses the pyghidra 3.x project API (``open_project`` /
        ``consume_program`` / ``program_loader``) rather than
        ``ghidra.base.project.GhidraProject``.  The difference that matters is
        that no "Batch Processing" transaction is left open for the life of the
        program, so tool transactions are outermost, ``DomainFile.save`` works
        and undo/redo are usable (#18).

        Returns a status dict on success.  Raises :class:`GhidraError` on failure.
        """
        import pyghidra  # noqa: PLC0415
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: PLC0415
        from ghidra.program.model.lang import (  # noqa: PLC0415
            CompilerSpecID,
            LanguageID,
        )
        from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415
        from java.io import File  # noqa: PLC0415
        from java.lang import Object as JavaObject  # noqa: PLC0415

        from re_mcp_ghidra.helpers import transaction  # noqa: PLC0415

        path = os.path.realpath(os.path.expanduser(file_path))

        if not os.path.isfile(path):
            raise GhidraError(f"File not found: {path}", error_type="FileNotFoundError")

        if self.is_open():
            self.close(save=True)

        # Create project directory alongside the binary
        binary_dir = os.path.dirname(path)
        binary_name = os.path.basename(path)
        project_dir = os.path.join(binary_dir, _PROJECT_SUBDIR)
        project_name = binary_name

        os.makedirs(project_dir, exist_ok=True)
        project_location = project_dir
        project_file = os.path.join(project_dir, project_name + ".gpr")

        warnings: list[str] = []
        project = None
        program = None
        consumer = JavaObject()
        # True only for a program restored from the project whose stored
        # "analyzed" option is set; anything imported is unanalyzed.
        analyzed = False

        try:
            if force_new and os.path.exists(project_file):
                gpr_path = project_file
                rep_path = os.path.join(project_dir, project_name + ".rep")
                if os.path.isfile(gpr_path):
                    os.remove(gpr_path)
                if os.path.isdir(rep_path):
                    shutil.rmtree(rep_path)
                log.info("force_new: removed existing project files")

            project_exists = os.path.exists(project_file)
            project = pyghidra.open_project(
                project_location, project_name, create=not project_exists
            )

            if project_exists:
                try:
                    program, _ = pyghidra.consume_program(project, "/" + binary_name, consumer)
                except FileNotFoundError:
                    # The project exists but the program was never saved into it
                    # (e.g. the previous session closed with save=False).
                    log.info(
                        "Project %s exists but has no program %s; re-importing",
                        project_name,
                        binary_name,
                    )
                    program = None
                except pyghidra.ProgramTypeError as exc:
                    project.close()
                    raise GhidraError(
                        f"/{binary_name} exists in project {project_name} "
                        f"but is not a Program: {exc}",
                        error_type="ImportFailed",
                    ) from exc
                if program is not None:
                    analyzed = bool(GhidraProgramUtilities.isAnalyzed(program))

            if program is None:
                lang = None
                cspec = None

                if language:
                    lang_svc = _get_language_service()
                    try:
                        lang = lang_svc.getLanguage(LanguageID(language))
                    except Exception as e:
                        project.close()
                        raise GhidraError(
                            f"Unknown language: {language!r}. Use list_targets to see available languages.",
                            error_type="InvalidArgument",
                        ) from e

                    if compiler_spec:
                        try:
                            cspec = lang.getCompilerSpecByID(CompilerSpecID(compiler_spec))
                        except Exception as e:
                            project.close()
                            raise GhidraError(
                                f"Unknown compiler spec: {compiler_spec!r} for language {language!r}",
                                error_type="InvalidArgument",
                            ) from e

                # name(binary_name) pins the program name so the reopen path
                # above finds it as "/<binary name>"; the loader would
                # otherwise use its own preferred name for the source.
                builder = (
                    pyghidra.program_loader()
                    .project(project)
                    .source(File(path))
                    .name(binary_name)
                    .monitor(TaskMonitor.DUMMY)
                )
                if lang is not None:
                    builder = builder.language(lang)
                    if cspec is not None:
                        builder = builder.compiler(cspec)

                try:
                    with builder.load() as load_results:
                        program = load_results.getPrimaryDomainObject(consumer)
                except Exception as exc:
                    project.close()
                    raise GhidraError(
                        f"Failed to import binary: {path}: {exc}",
                        error_type="ImportFailed",
                    ) from exc

                if program is None:
                    project.close()
                    raise GhidraError(
                        f"Failed to import binary: {path}",
                        error_type="ImportFailed",
                    )

                loaded_name = str(program.getName())
                if loaded_name != binary_name:
                    warnings.append(
                        f"Loader named the program {loaded_name!r}, expected {binary_name!r}"
                    )
                    log.warning("Loaded program name %r differs from %r", loaded_name, binary_name)

                # GhidraProject.initializeProgram() did this while importing;
                # ProgramLoader does not.  It needs a transaction of its own now
                # that nothing holds one open.
                with transaction(program, "Initialize analysis options"):
                    AutoAnalysisManager.getAnalysisManager(program).initializeOptions()

            if run_auto_analysis:
                # Ghidra 12.x has no setAnalyzedFlag(); reset the flags so a
                # forced pass starts clean.  The session fields are not set
                # yet, so run the analysis on the local program; the undo
                # history is cleared once below, after everything is done.
                GhidraProgramUtilities.resetAnalysisFlags(program)
                _run_analysis(program, mark_analyzed=True)
                analyzed = True

        except GhidraError:
            raise
        except Exception as exc:
            log.exception("Failed to open database: %s", path)
            if project is not None:
                with contextlib.suppress(Exception):
                    project.close()
            raise GhidraError(f"Failed to open database: {exc}", error_type="RuntimeError") from exc

        self._program = program
        self._project = project
        self._project_location = project_location
        self._consumer = consumer
        self._current_path = path
        self._flat_api = FlatProgramAPI(program, TaskMonitor.DUMMY)
        self.capabilities = self._probe_capabilities()
        # The loader, "Initialize analysis options" and a run_auto_analysis
        # pass all leave undo entries; a bare undo right after open would
        # roll back the analysis and then the program image (#18 U5).
        # Undo means "undo my tool calls", so the history starts empty.
        self._clear_undo_history()
        log.info(
            "Opened database: %s (analyzed=%s, capabilities: %s)", path, analyzed, self.capabilities
        )
        log.debug("open: after open %s", self._tx_state())
        return {"status": "ok", "path": path, "warnings": warnings, "analyzed": analyzed}

    def analyze(self, *, mark_analyzed: bool = True) -> None:
        """Run Ghidra auto-analysis to completion inside one transaction.

        Same calls as GhidraProject.analyze() (Ghidra 12.1.2), wrapped in a
        transaction because nothing holds one open any more (#18).  Not
        ``pyghidra.analyze``: that also collects the analysis log on every
        callback, which we discard and which cost ~20% in the #18 spike.
        Analysis passes are not undo steps (matches IDA): the undo history is
        cleared afterwards.

        Args:
            mark_analyzed: persist the "analyzed" flag afterwards (see
                :meth:`mark_program_analyzed`).  ``reanalyze_range`` passes
                False so a partial pass does not claim the whole program is
                analyzed (#8).
        """
        if self._program is None:
            raise GhidraError("No database is open.", error_type="NoDatabase")
        _run_analysis(self._program, mark_analyzed=mark_analyzed)
        self._clear_undo_history()

    def _clear_undo_history(self) -> None:
        """Drop the program's undo/redo history.

        ``DomainObject.clearUndo()`` (Ghidra 12.1.2 ``DomainObject.java:569``,
        implemented by ``DomainObjectAdapterDB.java:488``).  Called at the end
        of :meth:`open` and after every analysis pass so that ``undo`` only
        ever reverts a tool call the user made.
        """
        self._program.clearUndo()

    def mark_program_analyzed(self) -> None:
        """Persist the "analyzed" program option after a completed analysis pass.

        Stored in the program's PROGRAM_INFO options, so it survives ``save()``
        and makes ``GhidraProgramUtilities.isAnalyzed`` true when the project
        is reopened (see ``open()``).  Idempotent — :meth:`analyze` already
        does it for the passes it runs.
        """
        from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415

        if self._program is None:
            raise GhidraError("No database is open.", error_type="NoDatabase")
        GhidraProgramUtilities.markProgramAnalyzed(self._program)

    def _probe_capabilities(self) -> dict[str, bool]:
        """Detect which optional features are available."""
        return {
            "decompiler": True,
            # The pyghidra project API leaves no transaction open between tool
            # calls, so canUndo()/canRedo() work and each tool transaction is
            # one undo step (#18).  Under GhidraProject this had to be False
            # because the batch transaction blocked undo entirely (#10).
            "undo": True,
        }

    def _tx_state(self) -> str:
        """Describe the current transaction and save-related flags (for DEBUG logs).

        Under the pyghidra project API ``tx=None`` between tool calls is the
        expected state; anything else means a transaction leaked.
        """
        program = self._program
        if program is None:
            return "program=None"
        try:
            tx = program.getCurrentTransactionInfo()
            if tx is None:
                tx_desc = "tx=None"
            else:
                tx_desc = (
                    f"tx(id={tx.getID()} status={tx.getStatus()} desc={tx.getDescription()!r} "
                    f"open_sub={list(tx.getOpenSubTransactions())})"
                )
            df = program.getDomainFile()
            df_desc = "df=None" if df is None else f"canSave={df.canSave()} isBusy={df.isBusy()}"
            return (
                f"{tx_desc} {df_desc} isChanged={program.isChanged()} isLocked={program.isLocked()}"
            )
        except Exception as exc:  # pragma: no cover - diagnostics only
            return f"<state unavailable: {exc}>"

    def save(self) -> None:
        """Persist the current program to disk.

        With no standing transaction (the pyghidra project API leaves none
        open) ``DomainFile.save()`` succeeds directly.  The "Unable to lock due
        to active transaction" failure that forced ``GhidraProject.save`` in #1
        cannot happen here, because every tool transaction is closed before the
        call returns.

        A freshly imported program has no project file yet (``canSave()``
        false), so the first save mirrors what ``GhidraProject.saveAs`` did:
        delete any stale file of the same name in the root folder, then create
        it.  ``Loaded.save()`` is deliberately not used — it renames on
        collision ("name.0") instead of overwriting.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        if self._program is None or self._project is None:
            raise GhidraError("No database is open.", error_type="NoDatabase")

        df = self._program.getDomainFile()
        log.debug("save: before save %s", self._tx_state())
        if df is not None and df.canSave():
            df.save(TaskMonitor.DUMMY)
            log.debug("save: DomainFile.save done %s", self._tx_state())
        else:
            name = self._program.getName()
            folder = self._project.getProjectData().getRootFolder()
            existing = folder.getFile(name)
            if existing is not None:
                existing.delete()
            folder.createFile(name, self._program, TaskMonitor.DUMMY)
            log.debug("save: createFile done %s", self._tx_state())

    def close(self, save: bool = True) -> dict:
        """Close the current database.

        Raises :class:`GhidraError` on failure.
        """
        if not self.is_open():
            return {"status": "no_database_open"}

        path = self._current_path
        log.debug("close(save=%s): enter %s", save, self._tx_state())
        try:
            if save and self._program is not None and self._project is not None:
                self.save()
            # Release before closing the project: DefaultProjectData.close()
            # defers dispose while inUseCount != 0, which would leave the
            # project .lock file behind.
            if self._program is not None and self._consumer is not None:
                self._program.release(self._consumer)
            if self._project is not None:
                self._project.close()
        except Exception as exc:
            log.exception("Error closing database %s", path)
            raise GhidraError(f"Error closing database {path}", error_type="CloseFailed") from exc
        finally:
            self._program = None
            self._project = None
            self._project_location = None
            self._consumer = None
            self._current_path = None
            self._flat_api = None

        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that raises :class:`GhidraError` if no database is open."""

        def _check():
            if not self.is_open():
                raise GhidraError(
                    "No database is open. Use open_database first.",
                    error_type="NoDatabase",
                )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

                await call_ghidra(_check)
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check()
            return fn(*args, **kwargs)

        return wrapper


# Module-level singleton
session = Session()


def _run_analysis(program, *, mark_analyzed: bool) -> None:
    """Body of :meth:`Session.analyze` for a program not yet owned by the session.

    Mirrors ``GhidraProject.analyze`` (Ghidra 12.1.2 ``GhidraProject.java:534``:
    ``getAnalysisManager`` → ``initializeOptions`` → ``reAnalyzeAll(null)`` →
    ``startAnalysis(monitor)``) inside ``helpers.transaction`` so the pass
    mutates inside a transaction and a failing pass rolls back cleanly.
    ``markProgramAnalyzed`` opens a transaction of its own, so it runs after
    the "Analyze" one has been committed.
    """
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415
    from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    from re_mcp_ghidra.helpers import transaction  # noqa: PLC0415

    with transaction(program, "Analyze"):
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(TaskMonitor.DUMMY)
    if mark_analyzed:
        GhidraProgramUtilities.markProgramAnalyzed(program)


def _get_language_service():
    """Get Ghidra's default language service."""

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415

        return AutoAnalysisManager.getLanguageService()
    except Exception:
        from ghidra.program.util import DefaultLanguageService  # noqa: PLC0415

        return DefaultLanguageService.getLanguageService()


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately."""
    raise SystemExit(0)


# SIGTERM — hard shutdown
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
