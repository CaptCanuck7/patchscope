"""Static analysis engine for building real call graphs from cloned repos.

Clones GitHub repositories (shallow clone for speed) and uses tree-sitter
and Python's ast module to parse source code, extracting accurate call
graphs and entry points — replacing text-based GitHub code search.

Supported languages:
  - Python  → stdlib ast module
  - Java    → tree-sitter-java
  - C/C++   → tree-sitter-c
"""

import ast
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Generator

from tree_sitter import Language, Parser
import tree_sitter_python as _tspy
import tree_sitter_java as _tsjava
import tree_sitter_c as _tsc


# ---------------------------------------------------------------------------
# Pre-built parsers (constructed once at import time)
# ---------------------------------------------------------------------------

_PY_PARSER = Parser(Language(_tspy.language()))
_JAVA_PARSER = Parser(Language(_tsjava.language()))
_C_PARSER = Parser(Language(_tsc.language()))


# ---------------------------------------------------------------------------
# Repository cloning
# ---------------------------------------------------------------------------

def clone_repo(repo: str, commit_sha: str = "") -> str:
    """Shallow-clone a GitHub repository to a temporary directory.

    Uses ``--depth=1 --filter=blob:none`` for speed.  When *commit_sha* is
    provided the clone fetches enough history to check out that exact commit.

    Args:
        repo: Repository in ``owner/repo`` format, e.g. ``"torvalds/linux"``.
        commit_sha: Optional commit SHA to check out after cloning.

    Returns:
        Absolute path to the cloned repository directory.

    Raises:
        RuntimeError: If ``git clone`` or checkout fails.
    """
    tmp = tempfile.mkdtemp(prefix="patchscope_clone_")
    url = f"https://github.com/{repo}.git"

    try:
        if commit_sha:
            # Clone recent history so we can reach the commit
            subprocess.run(
                ["git", "clone", "--depth=50", "--filter=blob:none", url, tmp],
                check=True, capture_output=True, timeout=180,
            )
            try:
                subprocess.run(
                    ["git", "checkout", commit_sha],
                    cwd=tmp, check=True, capture_output=True, timeout=30,
                )
            except subprocess.CalledProcessError:
                # Commit older than depth=50 — fetch it explicitly
                subprocess.run(
                    ["git", "fetch", "--depth=1", "origin", commit_sha],
                    cwd=tmp, check=True, capture_output=True, timeout=60,
                )
                subprocess.run(
                    ["git", "checkout", commit_sha],
                    cwd=tmp, check=True, capture_output=True, timeout=30,
                )
        else:
            subprocess.run(
                ["git", "clone", "--depth=1", "--filter=blob:none", url, tmp],
                check=True, capture_output=True, timeout=180,
            )
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
        raise RuntimeError(
            f"git clone failed for {repo}: {stderr[:500]}"
        ) from exc
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone timed out for {repo}")

    return tmp


def cleanup_clone(repo_path: str) -> None:
    """Remove a cloned repository directory created by :func:`clone_repo`."""
    if repo_path and os.path.isdir(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Generic tree-sitter traversal helper
# ---------------------------------------------------------------------------

def _ts_traverse(node) -> Generator:
    """Yield every node in the tree-sitter AST (depth-first)."""
    yield node
    for child in node.children:
        yield from _ts_traverse(child)


def _rel(path: Path, base: Path) -> str:
    """Return a forward-slash relative path string."""
    return str(path.relative_to(base)).replace("\\", "/")


# ---------------------------------------------------------------------------
# Python call graph analysis  (stdlib ast)
# ---------------------------------------------------------------------------

class _PythonCallFinder(ast.NodeVisitor):
    """Collect all call sites of *target* within a Python AST."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.hits: list[dict] = []
        self._func_stack: list[str] = []
        self._class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if name == self.target or name.endswith(f".{self.target}"):
            self.hits.append({
                "line": node.lineno,
                "function": self._func_stack[-1] if self._func_stack else None,
                "class": self._class_stack[-1] if self._class_stack else None,
                "expression": name,
            })
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""


def _analyze_python_call_graph(repo_path: Path, target_func: str) -> dict:
    """Build a call graph for *target_func* by walking all .py files."""
    callers: list[dict] = []
    call_sites: list[dict] = []
    files_analyzed = 0

    for py_file in repo_path.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        files_analyzed += 1
        rel = _rel(py_file, repo_path)
        visitor = _PythonCallFinder(target_func)
        visitor.visit(tree)

        seen = set()
        for hit in visitor.hits:
            call_sites.append({
                "file": rel,
                "line": hit["line"],
                "expression": hit["expression"],
            })
            key = (rel, hit["function"])
            if key not in seen:
                seen.add(key)
                callers.append({
                    "function": hit["function"] or f"<module:{rel}>",
                    "class": hit["class"],
                    "file": rel,
                    "line": hit["line"],
                })

    return {
        "callers": callers,
        "call_sites": call_sites,
        "files_analyzed": files_analyzed,
        "analysis_method": "python_ast",
    }


# ---------------------------------------------------------------------------
# Python entry point detection  (stdlib ast)
# ---------------------------------------------------------------------------

# Decorators that signal HTTP route entry points
_PY_ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
}
# Libraries that provide those decorators
_PY_ROUTE_LIBS = {
    "app", "router", "blueprint", "api", "bp",
}


def _find_python_entry_points(repo_path: Path) -> list[dict]:
    """Find Python entry points by analysing decorated functions and main."""
    entry_points: list[dict] = []

    for py_file in repo_path.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        rel = _rel(py_file, repo_path)

        for node in ast.walk(tree):
            # HTTP route decorators: @app.route, @router.get, …
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    ep_type = _classify_python_decorator(dec)
                    if ep_type:
                        entry_points.append({
                            "function": node.name,
                            "file": rel,
                            "line": node.lineno,
                            "type": ep_type,
                        })
                        break

            # if __name__ == "__main__": … (CLI / script entry)
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


def _classify_python_decorator(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        if dec.attr in _PY_ROUTE_DECORATORS:
            return "http_route"
        if dec.attr in {"command", "group"}:
            return "cli_command"
    if isinstance(dec, ast.Name):
        if dec.id in {"command", "task"}:
            return "cli_command"
    return None


# ---------------------------------------------------------------------------
# Java call graph analysis  (tree-sitter-java)
# ---------------------------------------------------------------------------

def _collect_java_methods(root) -> list[dict]:
    """Return all method/constructor declarations with line ranges."""
    methods: list[dict] = []
    for node in _ts_traverse(root):
        if node.type in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node:
                methods.append({
                    "name": name_node.text.decode(),
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                })
    return methods


def _enclosing_java_method(line: int, methods: list[dict]) -> dict | None:
    """Return the innermost method definition that contains *line*."""
    best = None
    for m in methods:
        if m["start_line"] <= line <= m["end_line"]:
            if best is None or m["start_line"] > best["start_line"]:
                best = m
    return best


def _collect_java_class(node) -> str | None:
    """Walk up to find the enclosing class_declaration name."""
    for n in _ts_traverse(node):
        if n.type == "class_declaration":
            name_node = n.child_by_field_name("name")
            return name_node.text.decode() if name_node else None
    return None


def _analyze_java_call_graph(repo_path: Path, target_method: str) -> dict:
    """Build a call graph for *target_method* by parsing all .java files."""
    callers: list[dict] = []
    call_sites: list[dict] = []
    files_analyzed = 0

    for java_file in repo_path.rglob("*.java"):
        try:
            source = java_file.read_bytes()
            tree = _JAVA_PARSER.parse(source)
        except Exception:
            continue

        files_analyzed += 1
        rel = _rel(java_file, repo_path)
        methods = _collect_java_methods(tree.root_node)

        seen: set[tuple] = set()
        for node in _ts_traverse(tree.root_node):
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                if name_node and name_node.text.decode() == target_method:
                    line = node.start_point[0] + 1
                    call_sites.append({
                        "file": rel,
                        "line": line,
                        "expression": node.text.decode()[:120],
                    })
                    enclosing = _enclosing_java_method(line, methods)
                    key = (rel, enclosing["name"] if enclosing else None)
                    if key not in seen:
                        seen.add(key)
                        callers.append({
                            "function": enclosing["name"] if enclosing else f"<top:{rel}>",
                            "class": None,
                            "file": rel,
                            "line": line,
                        })

    return {
        "callers": callers,
        "call_sites": call_sites,
        "files_analyzed": files_analyzed,
        "analysis_method": "tree_sitter_java",
    }


# ---------------------------------------------------------------------------
# Java entry point detection  (tree-sitter-java)
# ---------------------------------------------------------------------------

# Spring / Jakarta annotations that mark HTTP endpoints
_JAVA_HTTP_ANNOTATIONS = {
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping",
    "WebServlet",
}
_JAVA_CLI_PATTERNS = {"main"}


def _find_java_entry_points(repo_path: Path) -> list[dict]:
    """Find Java entry points: Spring controllers, servlets, main()."""
    entry_points: list[dict] = []

    for java_file in repo_path.rglob("*.java"):
        try:
            source = java_file.read_bytes()
            tree = _JAVA_PARSER.parse(source)
        except Exception:
            continue

        rel = _rel(java_file, repo_path)

        for node in _ts_traverse(tree.root_node):
            if node.type == "method_declaration":
                name_node = node.child_by_field_name("name")
                method_name = name_node.text.decode() if name_node else None
                line = node.start_point[0] + 1

                # Check for HTTP endpoint annotations above method
                annotations = _get_java_annotations(node)
                for ann in annotations:
                    if ann in _JAVA_HTTP_ANNOTATIONS:
                        entry_points.append({
                            "function": method_name,
                            "file": rel,
                            "line": line,
                            "type": "http_endpoint",
                            "annotation": ann,
                        })
                        break

                # Servlet doGet / doPost
                if method_name in {"doGet", "doPost", "doDelete", "doPut", "service"}:
                    entry_points.append({
                        "function": method_name,
                        "file": rel,
                        "line": line,
                        "type": "servlet_handler",
                    })

                # public static void main(String[] args)
                if method_name == "main" and _is_java_main(node):
                    entry_points.append({
                        "function": "main",
                        "file": rel,
                        "line": line,
                        "type": "main_entry",
                    })

    return entry_points


def _get_java_annotations(method_node) -> list[str]:
    """Return annotation names appearing before a method declaration."""
    annotations = []
    # Modifiers node contains annotations
    for child in method_node.children:
        if child.type == "modifiers":
            for mod in child.children:
                if mod.type == "annotation":
                    name_node = mod.child_by_field_name("name")
                    if name_node:
                        annotations.append(name_node.text.decode())
    return annotations


def _is_java_main(method_node) -> bool:
    """Check if method has public static void signature."""
    text = method_node.text.decode()
    return bool(re.search(r'\bpublic\b.*\bstatic\b.*\bvoid\b.*\bmain\b', text))


# ---------------------------------------------------------------------------
# C/C++ call graph analysis  (tree-sitter-c)
# ---------------------------------------------------------------------------

def _collect_c_functions(root) -> list[dict]:
    """Return all C function definitions with name and line range."""
    functions: list[dict] = []
    for node in _ts_traverse(root):
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if not declarator:
                continue
            # Drill through pointer_declarator wrappers
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


def _enclosing_c_function(line: int, functions: list[dict]) -> dict | None:
    """Return the innermost C function definition that contains *line*."""
    best = None
    for f in functions:
        if f["start_line"] <= line <= f["end_line"]:
            if best is None or f["start_line"] > best["start_line"]:
                best = f
    return best


def _analyze_c_call_graph(repo_path: Path, target_func: str) -> dict:
    """Build a call graph for *target_func* by parsing all .c/.h files."""
    callers: list[dict] = []
    call_sites: list[dict] = []
    files_analyzed = 0

    c_files = list(repo_path.rglob("*.c")) + list(repo_path.rglob("*.h"))
    for c_file in c_files:
        try:
            source = c_file.read_bytes()
            tree = _C_PARSER.parse(source)
        except Exception:
            continue

        files_analyzed += 1
        rel = _rel(c_file, repo_path)
        functions = _collect_c_functions(tree.root_node)

        seen: set[tuple] = set()
        for node in _ts_traverse(tree.root_node):
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and func_node.text.decode() == target_func:
                    line = node.start_point[0] + 1
                    call_sites.append({
                        "file": rel,
                        "line": line,
                        "expression": node.text.decode()[:120],
                    })
                    enclosing = _enclosing_c_function(line, functions)
                    key = (rel, enclosing["name"] if enclosing else None)
                    if key not in seen:
                        seen.add(key)
                        callers.append({
                            "function": enclosing["name"] if enclosing else f"<top:{rel}>",
                            "class": None,
                            "file": rel,
                            "line": line,
                        })

    return {
        "callers": callers,
        "call_sites": call_sites,
        "files_analyzed": files_analyzed,
        "analysis_method": "tree_sitter_c",
    }


# ---------------------------------------------------------------------------
# C entry point detection  (tree-sitter-c + regex for macros)
# ---------------------------------------------------------------------------

def _find_c_entry_points(repo_path: Path) -> list[dict]:
    """Find C entry points: syscall handlers, netlink handlers, main()."""
    entry_points: list[dict] = []

    for c_file in repo_path.rglob("*.c"):
        try:
            source_bytes = c_file.read_bytes()
            tree = _C_PARSER.parse(source_bytes)
            source = source_bytes.decode(errors="ignore")
        except Exception:
            continue

        rel = _rel(c_file, repo_path)
        functions = _collect_c_functions(tree.root_node)

        for func in functions:
            name = func["name"]
            ep_type = _classify_c_function(name, source, func["start_line"])
            if ep_type:
                entry_points.append({
                    "function": name,
                    "file": rel,
                    "line": func["start_line"],
                    "type": ep_type,
                })

        # SYSCALL_DEFINE* macros don't parse as function_definition in tree-sitter
        # — detect them with regex directly on source
        for m in re.finditer(
            r'^SYSCALL_DEFINE\d\s*\(\s*(\w+)', source, re.MULTILINE
        ):
            line_no = source[:m.start()].count("\n") + 1
            entry_points.append({
                "function": f"sys_{m.group(1)}",
                "file": rel,
                "line": line_no,
                "type": "syscall_handler",
            })

    return entry_points


# Names / patterns that identify C entry points
_C_EP_NAMES = {
    "main": "main_entry",
    "nfnetlink_rcv": "netlink_handler",
    "nfnetlink_rcv_msg": "netlink_handler",
}
_C_NET_HANDLER_PATTERNS = re.compile(
    r'\b(rcv|recv|send|handler|accept|listen|connect)\b', re.IGNORECASE
)
_C_MODULE_INIT_PATTERN = re.compile(r'\bmodule_init\s*\(\s*(\w+)\s*\)')


def _classify_c_function(name: str, source: str, start_line: int) -> str | None:
    """Return an entry-point type label for a C function, or None."""
    if name in _C_EP_NAMES:
        return _C_EP_NAMES[name]
    # module_init(func) — look for registration on nearby lines
    for m in _C_MODULE_INIT_PATTERN.finditer(source):
        if m.group(1) == name:
            return "module_init"
    # Functions registered as netlink/socket operations via struct
    if re.search(rf'\.rcv\s*=\s*{re.escape(name)}\b', source):
        return "netlink_rcv_op"
    if re.search(rf'\.ndo_open\s*=\s*{re.escape(name)}\b', source):
        return "net_device_op"
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_call_graph(repo_path: str, language: str, target_function: str) -> dict:
    """Build a real call graph for *target_function* by parsing source files.

    Dispatches to the appropriate language-specific analyser.

    Args:
        repo_path: Absolute path to the cloned repository on disk.
        language: Source language — ``"Python"``, ``"Java"``, ``"C"``,
            or ``"C++"``.
        target_function: Function/method name to trace callers of.

    Returns:
        Dict with keys ``callers``, ``call_sites``, ``files_analyzed``,
        and ``analysis_method``.  Each caller entry has ``function``,
        ``class``, ``file``, and ``line``.  When the language is not yet
        supported an ``error`` key is present and callers is empty.
    """
    path = Path(repo_path)
    lang = language.lower()

    if lang == "python":
        return _analyze_python_call_graph(path, target_function)
    elif lang == "java":
        return _analyze_java_call_graph(path, target_function)
    elif lang in ("c", "c++", "cpp"):
        return _analyze_c_call_graph(path, target_function)
    else:
        return {
            "callers": [],
            "call_sites": [],
            "files_analyzed": 0,
            "analysis_method": "unsupported",
            "error": (
                f"Language '{language}' is not yet supported for static "
                "analysis. Use the analyze_call_graph tool (GitHub search) "
                "as a fallback."
            ),
        }


def find_entry_points_in_repo(repo_path: str, language: str) -> list[dict]:
    """Find real entry points by parsing ASTs in *repo_path*.

    Args:
        repo_path: Absolute path to the cloned repository on disk.
        language: Source language — ``"Python"``, ``"Java"``, or ``"C"``.

    Returns:
        List of dicts, each with ``function``, ``file``, ``line``, and
        ``type`` (e.g. ``"http_route"``, ``"syscall_handler"``).
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
