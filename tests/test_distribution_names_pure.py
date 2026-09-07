# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Distribution naming and versioning for the fork (issue #48).

The fork publishes ``eo-re-mcp``, ``eo-re-mcp-core``, ``eo-re-mcp-ida`` and
``eo-re-mcp-ghidra`` starting at 1.0.0, never colliding with upstream's
``re-mcp-*`` releases on PyPI. Directory names, import names, CLI names, entry
points and daemon state directories are unchanged. These tests read the
``pyproject.toml`` files with :mod:`tomllib` and need no engine.
"""

from __future__ import annotations

import inspect
import re
import tomllib
from pathlib import Path

import pytest
import re_mcp

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGES = REPO_ROOT / "packages"

# The fork version is read from the root pyproject; the packages must all carry
# the same one, a plain PEP 440 release at or above the first fork release.
ROOT_VERSION = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
    "version"
]
FIRST_FORK_VERSION = (1, 0, 0)

# directory (unchanged) -> distribution name
DISTRIBUTIONS: dict[Path, str] = {
    REPO_ROOT: "eo-re-mcp",
    PACKAGES / "re-mcp-core": "eo-re-mcp-core",
    PACKAGES / "re-mcp-ida": "eo-re-mcp-ida",
    PACKAGES / "re-mcp-ghidra": "eo-re-mcp-ghidra",
}

# CLI names that must survive the rename (users' MCP client configs depend on them)
EXPECTED_SCRIPTS: dict[Path, dict[str, str]] = {
    PACKAGES / "re-mcp-core": {"re-mcp": "re_mcp.supervisor:main"},
    PACKAGES / "re-mcp-ida": {
        "re-mcp-ida": "re_mcp_ida._cli:main",
        "re-mcp-ida-worker": "re_mcp_ida.server:main",
    },
    PACKAGES / "re-mcp-ghidra": {
        "re-mcp-ghidra": "re_mcp_ghidra._cli:main",
        "re-mcp-ghidra-worker": "re_mcp_ghidra.server:main",
    },
}

FORK_REPO = "https://github.com/offense360/eo-re-mcp"

# An upstream distribution name not preceded by a word character or a hyphen
# (so ``eo-re-mcp-core`` does not match but ``re-mcp-core>=0.1`` does).
_UPSTREAM_DEP = re.compile(r"(?<![\w-])(re-mcp-(core|ida|ghidra)|ida-mcp)(?![\w-])")


def _id(value: object) -> str:
    """Readable parametrize id: ``root`` or the package directory name."""
    if isinstance(value, Path):
        return "root" if value == REPO_ROOT else value.name
    return str(value)


def _load(directory: Path) -> dict:
    return tomllib.loads((directory / "pyproject.toml").read_text(encoding="utf-8"))


def _dependency_strings(data: dict) -> list[str]:
    """Every place a pyproject names another distribution."""
    project = data.get("project", {})
    out: list[str] = list(project.get("dependencies", []))
    for group in data.get("dependency-groups", {}).values():
        out.extend(item for item in group if isinstance(item, str))
    out.extend(data.get("tool", {}).get("uv", {}).get("sources", {}).keys())
    return out


@pytest.mark.parametrize(("directory", "name"), DISTRIBUTIONS.items(), ids=_id)
def test_distribution_name_and_version(directory: Path, name: str) -> None:
    project = _load(directory)["project"]
    assert project["name"] == name
    assert project["version"] == ROOT_VERSION
    parts = tuple(int(x) for x in project["version"].split("."))
    assert len(parts) == 3 and parts >= FIRST_FORK_VERSION


@pytest.mark.parametrize("package", ["re-mcp-ida", "re-mcp-ghidra"])
def test_backends_depend_on_fork_core(package: str) -> None:
    deps = _load(PACKAGES / package)["project"]["dependencies"]
    assert any(dep.startswith("eo-re-mcp-core") for dep in deps), deps


def test_root_depends_on_fork_packages() -> None:
    deps = _load(REPO_ROOT)["project"]["dependencies"]
    assert set(deps) == {"eo-re-mcp-core", "eo-re-mcp-ida", "eo-re-mcp-ghidra"}


@pytest.mark.parametrize("directory", DISTRIBUTIONS.keys(), ids=_id)
def test_no_upstream_distribution_names_in_dependencies(directory: Path) -> None:
    offending = [s for s in _dependency_strings(_load(directory)) if _UPSTREAM_DEP.search(s)]
    assert offending == [], offending


def test_workspace_members_match_directories() -> None:
    members = _load(REPO_ROOT)["tool"]["uv"]["workspace"]["members"]
    assert members == ["packages/re-mcp-core", "packages/re-mcp-ida", "packages/re-mcp-ghidra"]


def test_ida_mcp_alias_package_removed() -> None:
    assert not (PACKAGES / "ida-mcp").exists()


def test_get_version_default_is_fork_core() -> None:
    default = inspect.signature(re_mcp.get_version).parameters["package"].default
    assert default == "eo-re-mcp-core"


@pytest.mark.parametrize(("directory", "scripts"), EXPECTED_SCRIPTS.items(), ids=_id)
def test_cli_names_unchanged(directory: Path, scripts: dict[str, str]) -> None:
    assert _load(directory)["project"]["scripts"] == scripts


@pytest.mark.parametrize("directory", DISTRIBUTIONS.keys(), ids=_id)
def test_description_mentions_fork_name(directory: Path) -> None:
    assert "eo-re-mcp" in _load(directory)["project"]["description"]


@pytest.mark.parametrize("package", ["re-mcp-ida", "re-mcp-ghidra"])
def test_project_urls_point_at_fork(package: str) -> None:
    urls = _load(PACKAGES / package)["project"]["urls"]
    assert set(urls) == {"Homepage", "Repository", "Issues", "Documentation"}
    for key, url in urls.items():
        assert url.startswith(FORK_REPO), (key, url)
    text = (PACKAGES / package / "pyproject.toml").read_text(encoding="utf-8")
    assert "jtsylve/ida-mcp" not in text


@pytest.mark.parametrize(
    ("readme", "title"),
    [
        (REPO_ROOT / "README.md", "# eo-re-mcp"),
        (PACKAGES / "re-mcp-core" / "README.md", "# eo-re-mcp-core"),
        (PACKAGES / "re-mcp-ida" / "README.md", "# eo-re-mcp-ida"),
        (PACKAGES / "re-mcp-ghidra" / "README.md", "# eo-re-mcp-ghidra"),
    ],
    ids=["root", "core", "ida", "ghidra"],
)
def test_readme_title(readme: Path, title: str) -> None:
    first_line = readme.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == title


def test_readme_wheel_names_follow_the_version() -> None:
    """The install examples name concrete wheel files; they must match the release version."""
    for readme in (
        REPO_ROOT / "README.md",
        PACKAGES / "re-mcp-ida" / "README.md",
        PACKAGES / "re-mcp-ghidra" / "README.md",
    ):
        versions = set(
            re.findall(
                r"eo_re_mcp(?:_core|_ida|_ghidra)?-(\d+\.\d+\.\d+)-py3-none-any\.whl",
                readme.read_text(encoding="utf-8"),
            )
        )
        assert versions == {ROOT_VERSION}, (readme, versions)
