"""Real static analysis engine for PatchScope — replaces GitHub text search.

Features
--------
- **Repo caching**: clones to ``/tmp/patchscope_repos/<cache-key>/`` and
  skips re-cloning when the directory already exists.
- **Python**: uses stdlib ``ast`` — zero extra dependencies.
- **Java**: uses ``javalang`` for proper AST parsing (not text search).
- **C/C++**: uses ``tree-sitter-c`` for function-level call extraction.
- **Bidirectional call graphs**: ``callee_graph[f]`` = what ``f`` calls;
  ``caller_graph[f]`` = who calls ``f``.
- **BFS path tracing**: ``find_shortest_path`` walks the callee graph from
  a set of entry-point functions to a target function.

Public API
----------
- ``get_or_clone_repo(repo, commit_sha="")`` → ``str``  (cached path)
- ``build_call_graph(repo_path, language, target_function)`` → ``dict``
- ``build_full_call_graph(repo_path, language)`` → ``dict``
- ``find_entry_points_in_repo(repo_path, language)`` → ``list[dict]``
- ``find_shortest_path(callee_graph, sources, target, max_depth=8)``
  → ``list[str] | None``
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Generator

import javalang
import javalang.tree
from tree_sitter import Language, Parser
import tree_sitter_c as _tsc


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Override via environment variable if /tmp isn't writable (e.g. bare Windows).
CACHE_DIR = Path(os.environ.get("PATCHSCOPE_REPO_CACHE", "/tmp/patchscope_repos"))

# Max source files to scan per language to avoid OOM on huge repos.
MAX_FILES = int(os.environ.get("PATCHSCOPE_MAX_FILES", "1000"))


# ---------------------------------------------------------------------------
# Tree-sitter parser (C/C++ only — built once at import time)
# ---------------------------------------------------------------------------

_C_PARSER = Parser(Language(_tsc.language()))


# ---------------------------------------------------------------------------
# Repository caching / cloning
# ---------------------------------------------------------------------------

def _cache_key(repo: str, commit_sha: str) -> str:
    """Produce a filesystem-safe directory name for this (repo, sha) pair."""
    safe = repo.replace("/", "__")
    suffix = commit_sha[:12] if commit_sha else "HEAD"
    return f"{safe}__{suffix}"


def get_or_clone_repo(repo: str, commit_sha: str = "") -> str:
    """Return the path to a cached shallow clone, cloning if necessary.

    Repos are cached under ``CACHE_DIR/<cache_key>/``.  If that directory
    already contains a ``.git/`` folder the clone is reused immediately
    — no network call.

    Args:
        repo: Repository in ``owner/repo`` format, e.g. ``"torvalds/linux"``.
        commit_sha: Optional commit SHA to check out after cloning.

    Returns:
        Absolute path to the local repository clone.

    Raises:
        RuntimeError: If ``git clone`` or checkout fails.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = CACHE_DIR / _cache_key(repo, commit_sha)

    # Cache hit — return existing clone.
    if dest.exists() and (dest / ".git").exists():
        return str(dest)

    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"

    try:
        if commit_sha:
            subprocess.run(
                ["git", "clone", "--depth=50", "--filter=blob:none", url, str(dest)],
                check=True, capture_output=True, timeout=300,
            )
            try:
                subprocess.run(
                    ["git", "checkout", commit_sha],
                    cwd=str(dest), check=True, capture_output=True, timeout=30,
                )
            except subprocess.CalledProcessError:
                # Commit older than depth=50 — fetch it explicitly.
                subprocess.run(
                    ["git", "fetch", "--depth=1", "origin", commit_sha],
                    cwd=str(dest), check=True, capture_output=True, timeout=60,
                )
                subprocess.run(
                    ["git", "checkout", commit_sha],
                    cwd=str(dest), check=True, capture_output=True, timeout=30,
                )
        else:
            subprocess.run(
                ["git", "clone", "--depth=1", "--filter=blob:none", url, str(dest)],
                check=True, capture_output=True, timeout=300,
            )
    except subprocess.CalledProcessError as exc:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
        raise RuntimeError(f"git clone failed for {repo}: {stderr[:500]}") from exc
    except subprocess.TimeoutExpired:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"git clone timed out for {repo}")

    return str(dest)


# ---------------------------------------------------------------------------
# BFS path tracing
# ---------------------------------------------------------------------------

def find_shortest_path(
    callee_graph: dict[str, list[str]],
    sources: list[str],
    target: str,
    max_depth: int = 8,
) -> list[str] | None:
    """BFS: find the shortest call chain from any source to *target*.

    Traverses the forward call graph (``callee_graph[f]`` = what ``f`` calls).

    Args:
        callee_graph: Forward call graph mapping function → list of callees.
        sources: Starting function names (typically entry points).
        target: Vulnerable function name to reach.
        max_depth: Maximum chain length before giving up.

    Returns:
        Ordered list of function names forming the shortest path, or ``None``
        if no path exists within *max_depth* hops.
    """
    # Fast path: target is one of the sources.
    if target in sources:
        return [target]

    visited: set[str] = set(sources)
    queue: deque[tuple[str, list[str]]] = deque()

    for src in sources:
        queue.append((src, [src]))

    while queue:
        current, path = queue.popleft()
        if len(path) >= max_depth:
            continue
        for callee in callee_graph.get(current, []):
            if callee == target:
                return path + [callee]
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rel(path: Path, base: Path) -> str:
    """Forward-slash relative path string."""
    return str(path.relative_to(base)).replace("\\", "/")


def _ts_traverse(node) -> Generator:
    """Depth-first traversal of a tree-sitter AST node."""
    yield node
    for child in node.children:
        yield from _ts_traverse(child)


# ---------------------------------------------------------------------------
# Python — full call graph  (stdlib ast)
# ---------------------------------------------------------------------------

class _PyGraphBuilder(ast.NodeVisitor):
    """Walk a single Python AST and record every call relationship."""

    def __init__(self, rel_path: str) -> None:
        self._rel = rel_path
        self._func_stack: list[str] = []   # fully-qualified current function
        self._class_stack: list[str] = []
        self.callee_graph: dict[str, set[str]] = defaultdict(set)
        self.caller_graph: dict[str, set[str]] = defaultdict(set)
        # callee → list of {file, line, expression, caller} for actual call sites
        self.call_sites_by_callee: dict[str, list[dict]] = defaultdict(list)
        # name → {file, line, class}
        self.all_functions: dict[str, dict] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def _enter_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Use Class.method form so names stay unique within a file.
        fq = (
            f"{self._class_stack[-1]}.{node.name}"
            if self._class_stack else node.name
        )
        self._func_stack.append(fq)
        if fq not in self.all_functions:
            self.all_functions[fq] = {
                "file": self._rel,
                "line": node.lineno,
                "class": self._class_stack[-1] if self._class_stack else None,
            }
        self.generic_visit(node)
        self._func_stack.pop()

    visit_FunctionDef = _enter_func  # type: ignore[assignment]
    visit_AsyncFunctionDef = _enter_func  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        if self._func_stack:
            callee = self._call_name(node)
            if callee:
                caller = self._func_stack[-1]
                self.callee_graph[caller].add(callee)
                self.caller_graph[callee].add(caller)
                self.call_sites_by_callee[callee].append({
                    "file": self._rel,
                    "line": node.lineno,
                    "expression": f"{caller}(…) → {callee}(…)",
                    "caller": caller,
                })
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None


def _build_python_call_graph(repo_path: Path, max_files: int = MAX_FILES) -> dict:
    """Build full Python call graph by parsing every .py file."""
    merged_callee: dict[str, set[str]] = defaultdict(set)
    merged_caller: dict[str, set[str]] = defaultdict(set)
    merged_call_sites: dict[str, list[dict]] = defaultdict(list)
    all_functions: dict[str, dict] = {}
    files_analyzed = 0

    for py_file in list(repo_path.rglob("*.py"))[:max_files]:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        files_analyzed += 1
        builder = _PyGraphBuilder(_rel(py_file, repo_path))
        builder.visit(tree)

        for caller, callees in builder.callee_graph.items():
            merged_callee[caller].update(callees)
        for callee, callers in builder.caller_graph.items():
            merged_caller[callee].update(callers)
        for callee, sites in builder.call_sites_by_callee.items():
            merged_call_sites[callee].extend(sites)
        all_functions.update(builder.all_functions)

    return {
        "callee_graph": {k: list(v) for k, v in merged_callee.items()},
        "caller_graph": {k: list(v) for k, v in merged_caller.items()},
        "call_sites_by_callee": dict(merged_call_sites),
        "all_functions": all_functions,
        "files_analyzed": files_analyzed,
        "analysis_method": "python_ast",
    }


# Python entry point patterns ------------------------------------------------

_PY_ROUTE_ATTRS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
}


def _find_python_entry_points(repo_path: Path, max_files: int = MAX_FILES) -> list[dict]:
    """Detect Python entry points by AST inspection."""
    entry_points: list[dict] = []

    for py_file in list(repo_path.rglob("*.py"))[:max_files]:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        rel = _rel(py_file, repo_path)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    ep_type = _classify_py_decorator(dec)
                    if ep_type:
                        entry_points.append({
                            "function": node.name,
                            "file": rel,
                            "line": node.lineno,
                            "type": ep_type,
                        })
                        break

            # if __name__ == "__main__": block
            if isinstance(node, ast.If):
                test = node.test
                if (
                    isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"
                ):
                    entry_points.append({
                        "function": "__main__",
                        "file": rel,
                        "line": node.lineno,
                        "type": "script_entry",
                    })

    return entry_points


def _classify_py_decorator(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        if dec.attr in _PY_ROUTE_ATTRS:
            return "http_route"
        if dec.attr in {"command", "group"}:
            return "cli_command"
    if isinstance(dec, ast.Name):
        if dec.id in {"command", "task"}:
            return "cli_command"
    return None


# ---------------------------------------------------------------------------
# Java — full call graph  (javalang)
# ---------------------------------------------------------------------------

_JAVA_HTTP_ANNOTATIONS = {
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping", "WebServlet",
}
_JAVA_SERVLET_METHODS = {"doGet", "doPost", "doDelete", "doPut", "service"}


def _build_java_call_graph(repo_path: Path, max_files: int = MAX_FILES) -> dict:
    """Build full Java call graph using javalang AST parsing."""
    callee_graph: dict[str, set[str]] = defaultdict(set)
    caller_graph: dict[str, set[str]] = defaultdict(set)
    call_sites_by_callee: dict[str, list[dict]] = defaultdict(list)
    all_functions: dict[str, dict] = {}
    files_analyzed = 0

    for java_file in list(repo_path.rglob("*.java"))[:max_files]:
        try:
            source = java_file.read_text(encoding="utf-8", errors="ignore")
            tree = javalang.parse.parse(source)
        except Exception:
            continue  # malformed / partially-supported syntax

        files_analyzed += 1
        rel = _rel(java_file, repo_path)

        def _process_member(name: str, decl_line: int) -> None:
            if name not in all_functions:
                all_functions[name] = {"file": rel, "line": decl_line}

        # --- Method declarations ---
        for _path, method in tree.filter(javalang.tree.MethodDeclaration):
            name = method.name
            line = method.position.line if method.position else 0
            _process_member(name, line)

            for _, inv in method.filter(javalang.tree.MethodInvocation):
                callee = inv.member
                call_line = inv.position.line if inv.position else line
                callee_graph[name].add(callee)
                caller_graph[callee].add(name)
                call_sites_by_callee[callee].append({
                    "file": rel,
                    "line": call_line,
                    "expression": f"{name}(…) → {callee}(…)",
                    "caller": name,
                })

        # --- Constructors ---
        for _path, ctor in tree.filter(javalang.tree.ConstructorDeclaration):
            name = ctor.name
            line = ctor.position.line if ctor.position else 0
            _process_member(name, line)

            for _, inv in ctor.filter(javalang.tree.MethodInvocation):
                callee = inv.member
                call_line = inv.position.line if inv.position else line
                callee_graph[name].add(callee)
                caller_graph[callee].add(name)
                call_sites_by_callee[callee].append({
                    "file": rel,
                    "line": call_line,
                    "expression": f"{name}(…) → {callee}(…)",
                    "caller": name,
                })

    return {
        "callee_graph": {k: list(v) for k, v in callee_graph.items()},
        "caller_graph": {k: list(v) for k, v in caller_graph.items()},
        "call_sites_by_callee": dict(call_sites_by_callee),
        "all_functions": all_functions,
        "files_analyzed": files_analyzed,
        "analysis_method": "javalang",
    }


def _find_java_entry_points(repo_path: Path, max_files: int = MAX_FILES) -> list[dict]:
    """Detect Java entry points via javalang: Spring controllers, servlets, main."""
    entry_points: list[dict] = []

    for java_file in list(repo_path.rglob("*.java"))[:max_files]:
        try:
            source = java_file.read_text(encoding="utf-8", errors="ignore")
            tree = javalang.parse.parse(source)
        except Exception:
            continue

        rel = _rel(java_file, repo_path)

        for _path, method in tree.filter(javalang.tree.MethodDeclaration):
            name = method.name
            line = method.position.line if method.position else 0
            annotations = [a.name for a in (method.annotations or [])]

            # Spring / Jakarta HTTP endpoint annotations
            for ann in annotations:
                if ann in _JAVA_HTTP_ANNOTATIONS:
                    entry_points.append({
                        "function": name,
                        "file": rel,
                        "line": line,
                        "type": "http_endpoint",
                        "annotation": ann,
                    })
                    break

            # Servlet doGet / doPost / etc.
            if name in _JAVA_SERVLET_METHODS:
                entry_points.append({
                    "function": name,
                    "file": rel,
                    "line": line,
                    "type": "servlet_handler",
                })

            # public static void main(String[] args)
            if name == "main":
                mods = method.modifiers or set()
                if "public" in mods and "static" in mods:
                    entry_points.append({
                        "function": "main",
                        "file": rel,
                        "line": line,
                        "type": "main_entry",
                    })

    return entry_points


# ---------------------------------------------------------------------------
# C/C++ — full call graph  (tree-sitter-c)
# ---------------------------------------------------------------------------

def _collect_c_func_defs(root) -> list[dict]:
    """Return all C function definitions with name, start_line, end_line."""
    functions: list[dict] = []
    for node in _ts_traverse(root):
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if not declarator:
                continue
            for sub in _ts_traverse(declarator):
                if sub.type == "function_declarator":
                    name_node = sub.child_by_field_name("declarator")
                    if name_node:
                        functions.append({
                            "name": name_node.text.decode(),
                            "start_line": node.start_point[0] + 1,
                            "end_line": node.end_point[0] + 1,
                        })
                    break
    return functions


def _enclosing_c_func(line: int, functions: list[dict]) -> dict | None:
    best = None
    for f in functions:
        if f["start_line"] <= line <= f["end_line"]:
            if best is None or f["start_line"] > best["start_line"]:
                best = f
    return best


def _build_c_call_graph(repo_path: Path, max_files: int = MAX_FILES) -> dict:
    """Build full C call graph using tree-sitter-c AST parsing."""
    callee_graph: dict[str, set[str]] = defaultdict(set)
    caller_graph: dict[str, set[str]] = defaultdict(set)
    call_sites_by_callee: dict[str, list[dict]] = defaultdict(list)
    all_functions: dict[str, dict] = {}
    files_analyzed = 0

    c_files = (
        list(repo_path.rglob("*.c")) + list(repo_path.rglob("*.h"))
    )[:max_files]

    for c_file in c_files:
        try:
            source_bytes = c_file.read_bytes()
            tree = _C_PARSER.parse(source_bytes)
        except Exception:
            continue

        files_analyzed += 1
        rel = _rel(c_file, repo_path)
        func_defs = _collect_c_func_defs(tree.root_node)

        for fd in func_defs:
            if fd["name"] not in all_functions:
                all_functions[fd["name"]] = {"file": rel, "line": fd["start_line"]}

        for node in _ts_traverse(tree.root_node):
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if not func_node:
                    continue
                callee_name = func_node.text.decode()
                call_line = node.start_point[0] + 1   # actual call site line
                enclosing = _enclosing_c_func(call_line, func_defs)
                if enclosing:
                    caller_name = enclosing["name"]
                    callee_graph[caller_name].add(callee_name)
                    caller_graph[callee_name].add(caller_name)
                    call_sites_by_callee[callee_name].append({
                        "file": rel,
                        "line": call_line,
                        "expression": node.text.decode()[:120],
                        "caller": caller_name,
                    })

    return {
        "callee_graph": {k: list(v) for k, v in callee_graph.items()},
        "caller_graph": {k: list(v) for k, v in caller_graph.items()},
        "call_sites_by_callee": dict(call_sites_by_callee),
        "all_functions": all_functions,
        "files_analyzed": files_analyzed,
        "analysis_method": "tree_sitter_c",
    }


# C entry point detection ----------------------------------------------------

_C_EP_NAMES: dict[str, str] = {
    "main": "main_entry",
    "nfnetlink_rcv": "netlink_handler",
    "nfnetlink_rcv_msg": "netlink_handler",
}
_C_MODULE_INIT_RE = re.compile(r'\bmodule_init\s*\(\s*(\w+)\s*\)')
_SYSCALL_DEFINE_RE = re.compile(r'^SYSCALL_DEFINE\d\s*\(\s*(\w+)', re.MULTILINE)


def _find_c_entry_points(repo_path: Path, max_files: int = MAX_FILES) -> list[dict]:
    """Detect C entry points via tree-sitter + regex for SYSCALL_DEFINE macros."""
    entry_points: list[dict] = []

    for c_file in list(repo_path.rglob("*.c"))[:max_files]:
        try:
            source_bytes = c_file.read_bytes()
            tree = _C_PARSER.parse(source_bytes)
            source = source_bytes.decode(errors="ignore")
        except Exception:
            continue

        rel = _rel(c_file, repo_path)
        func_defs = _collect_c_func_defs(tree.root_node)

        for fd in func_defs:
            ep_type = _classify_c_ep(fd["name"], source)
            if ep_type:
                entry_points.append({
                    "function": fd["name"],
                    "file": rel,
                    "line": fd["start_line"],
                    "type": ep_type,
                })

        # SYSCALL_DEFINE* macros don't parse as function_definition in tree-sitter
        for m in _SYSCALL_DEFINE_RE.finditer(source):
            line_no = source[:m.start()].count("\n") + 1
            entry_points.append({
                "function": f"sys_{m.group(1)}",
                "file": rel,
                "line": line_no,
                "type": "syscall_handler",
            })

    return entry_points


def _classify_c_ep(name: str, source: str) -> str | None:
    if name in _C_EP_NAMES:
        return _C_EP_NAMES[name]
    for m in _C_MODULE_INIT_RE.finditer(source):
        if m.group(1) == name:
            return "module_init"
    if re.search(rf'\.rcv\s*=\s*{re.escape(name)}\b', source):
        return "netlink_rcv_op"
    if re.search(rf'\.ndo_open\s*=\s*{re.escape(name)}\b', source):
        return "net_device_op"
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_full_call_graph(repo_path: str, language: str) -> dict:
    """Build the complete bidirectional call graph for a repository.

    Returns the entire ``callee_graph`` and ``caller_graph`` so that callers
    can perform BFS path tracing via :func:`find_shortest_path`.

    Args:
        repo_path: Absolute path to the cloned repository on disk.
        language: Source language — ``"Python"``, ``"Java"``, ``"C"``,
            ``"C++"``.

    Returns:
        Dict with:
        - ``callee_graph``: ``{func: [callee, ...]}`` (forward edges).
        - ``caller_graph``: ``{func: [caller, ...]}`` (reverse edges).
        - ``all_functions``: ``{func: {file, line}}`` — all discovered funcs.
        - ``files_analyzed``: int.
        - ``analysis_method``: ``"python_ast"``, ``"javalang"``,
          ``"tree_sitter_c"``, or ``"unsupported"``.
        - ``error``: present only when the language is not supported.
    """
    path = Path(repo_path)
    lang = language.lower()

    if lang == "python":
        return _build_python_call_graph(path)
    elif lang == "java":
        return _build_java_call_graph(path)
    elif lang in ("c", "c++", "cpp"):
        return _build_c_call_graph(path)
    else:
        return {
            "callee_graph": {},
            "caller_graph": {},
            "call_sites_by_callee": {},
            "all_functions": {},
            "files_analyzed": 0,
            "analysis_method": "unsupported",
            "error": (
                f"Language '{language}' is not supported for static analysis. "
                "Use the GitHub code search fallback tools instead."
            ),
        }


def build_call_graph(repo_path: str, language: str, target_function: str) -> dict:
    """Build a call graph focused on *target_function*.

    Internally builds the full bidirectional call graph then extracts the
    direct callers and call sites for *target_function*.  Also returns the
    full ``callee_graph`` and ``caller_graph`` so the caller can run BFS.

    This function is API-compatible with ``static_analysis.build_call_graph``.

    Args:
        repo_path: Absolute path to the cloned repository on disk.
        language: Source language (``"Python"``, ``"Java"``, ``"C"`` …).
        target_function: Function/method name whose callers to find.

    Returns:
        Dict with ``callers``, ``call_sites``, ``callee_graph``,
        ``caller_graph``, ``files_analyzed``, ``analysis_method``.
        ``callers`` is a list of ``{function, class, file, line}`` dicts.
    """
    full = build_full_call_graph(repo_path, language)

    if "error" in full:
        return {
            "callers": [],
            "call_sites": [],
            "callee_graph": {},
            "caller_graph": {},
            "files_analyzed": 0,
            "analysis_method": full["analysis_method"],
            "error": full["error"],
        }

    caller_graph: dict[str, list[str]] = full["caller_graph"]
    all_functions: dict[str, dict] = full["all_functions"]
    call_sites_by_callee: dict[str, list[dict]] = full.get("call_sites_by_callee", {})

    # Direct callers of target_function
    direct_caller_names = caller_graph.get(target_function, [])
    callers: list[dict] = []
    seen: set[str] = set()

    for caller_name in direct_caller_names:
        if caller_name in seen:
            continue
        seen.add(caller_name)
        info = all_functions.get(caller_name, {})
        callers.append({
            "function": caller_name,
            "class": info.get("class"),
            "file": info.get("file", ""),
            "line": info.get("line", 0),
        })

    # Actual call sites for target_function (with real line numbers)
    raw_sites = call_sites_by_callee.get(target_function, [])
    call_sites = [
        {"file": s["file"], "line": s["line"], "expression": s["expression"]}
        for s in raw_sites
    ]

    return {
        "callers": callers,
        "call_sites": call_sites,
        "callee_graph": full["callee_graph"],
        "caller_graph": full["caller_graph"],
        "files_analyzed": full["files_analyzed"],
        "analysis_method": full["analysis_method"],
    }


def find_entry_points_in_repo(repo_path: str, language: str) -> list[dict]:
    """Find entry points in a repository by AST analysis.

    API-compatible with ``static_analysis.find_entry_points_in_repo``.

    Args:
        repo_path: Absolute path to the cloned repository on disk.
        language: Source language — ``"Python"``, ``"Java"``, ``"C"``.

    Returns:
        List of ``{function, file, line, type}`` dicts.
    """
    path = Path(repo_path)
    lang = language.lower()

    if lang == "python":
        return _find_python_entry_points(path)
    elif lang == "java":
        return _find_java_entry_points(path)
    elif lang in ("c", "c++", "cpp"):
        return _find_c_entry_points(path)
    else:
        return []
