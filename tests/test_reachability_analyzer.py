"""Tests for the Reachability Analyzer agent tools and branching logic."""

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from patchscope.agents.reachability_analyzer import (
    analyze_call_graph,
    clone_and_analyze_call_graph,
    detect_entry_points,
    find_entry_points_static,
    trace_data_flow,
    detect_auth_gates,
)
from patchscope.tools.code_search import (
    search_code,
    fetch_file_content,
    search_function_callers,
    search_entry_points,
)
from patchscope.tools.static_analysis import (
    build_call_graph,
    find_entry_points_in_repo,
    clone_repo,
    cleanup_clone,
)
from patchscope.agents.reachability_analyzer import _detect_patterns_in_content


# ---------------------------------------------------------------------------
# Helpers: temporary repos with known source files
# ---------------------------------------------------------------------------

def _make_python_repo() -> str:
    """Create a temp directory with Python source resembling a real repo."""
    tmp = tempfile.mkdtemp(prefix="test_repo_py_")
    (Path(tmp) / "handler.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/api/items')\n"
        "def list_items():\n"
        "    return process_items()\n\n"
        "def process_items():\n"
        "    return vulnerable_func(data)\n"
    )
    (Path(tmp) / "core.py").write_text(
        "def vulnerable_func(data):\n"
        "    return data\n\n"
        "def helper():\n"
        "    vulnerable_func(None)\n"
    )
    return tmp


def _make_java_repo() -> str:
    """Create a temp directory with Java source resembling a Spring app."""
    tmp = tempfile.mkdtemp(prefix="test_repo_java_")
    (Path(tmp) / "TableController.java").write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "public class TableController {\n"
        "    @PostMapping(\"/tables\")\n"
        "    public void createTable(String name) {\n"
        "        deactivateSet(name);\n"
        "    }\n"
        "    private void cleanup() {\n"
        "        deactivateSet(null);\n"
        "    }\n"
        "    public static void main(String[] args) {}\n"
        "}\n"
    )
    return tmp


def _make_c_repo() -> str:
    """Create a temp directory with C source resembling a kernel module."""
    tmp = tempfile.mkdtemp(prefix="test_repo_c_")
    (Path(tmp) / "nf_tables.c").write_text(
        "#include <linux/netfilter.h>\n\n"
        "static int nf_tables_delset(struct nft_ctx *ctx) {\n"
        "    return nft_set_deactivate(ctx);\n"
        "}\n\n"
        "static int nfnetlink_rcv_msg(struct sk_buff *skb) {\n"
        "    return nf_tables_delset(NULL);\n"
        "}\n\n"
        "SYSCALL_DEFINE2(socket, int, family, int, type)\n"
        "{\n"
        "    return sock_create(family, type);\n"
        "}\n"
    )
    return tmp


# =====================================================================
# code_search.py unit tests
# =====================================================================

class TestSearchCode:
    @patch("patchscope.tools.code_search.requests.get")
    @patch("patchscope.tools.code_search._rate_limit_code_search")
    def test_search_code_returns_results(self, mock_rate, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "total_count": 2,
                "items": [
                    {
                        "path": "net/netfilter/nf_tables_api.c",
                        "repository": {"full_name": "torvalds/linux"},
                        "html_url": "https://github.com/torvalds/linux/blob/main/net/netfilter/nf_tables_api.c",
                        "text_matches": [{"fragment": "nft_set_deactivate(ctx);"}],
                    },
                    {
                        "path": "net/netfilter/nft_set.c",
                        "repository": {"full_name": "torvalds/linux"},
                        "html_url": "https://github.com/torvalds/linux/blob/main/net/netfilter/nft_set.c",
                        "text_matches": [],
                    },
                ],
            },
        )
        results = search_code("nft_set_deactivate", "torvalds/linux")
        assert len(results) == 2
        assert results[0]["path"] == "net/netfilter/nf_tables_api.c"
        assert results[0]["repository"] == "torvalds/linux"

    @patch("patchscope.tools.code_search.requests.get")
    @patch("patchscope.tools.code_search._rate_limit_code_search")
    def test_search_code_empty_results(self, mock_rate, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"total_count": 0, "items": []},
        )
        results = search_code("nonexistent_func_xyz", "torvalds/linux")
        assert results == []


class TestFetchFileContent:
    @patch("patchscope.tools.code_search.requests.get")
    def test_fetch_file_content(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            text="int main() { return 0; }",
        )
        content = fetch_file_content("torvalds/linux", "init/main.c")
        assert "int main()" in content

    @patch("patchscope.tools.code_search.requests.get")
    def test_fetch_file_not_found(self, mock_get):
        import requests as req
        mock_get.return_value = MagicMock(status_code=404)
        mock_get.return_value.raise_for_status.side_effect = req.HTTPError("404")
        with pytest.raises(req.HTTPError):
            fetch_file_content("torvalds/linux", "nonexistent.c")


class TestDetectPatternsInContent:
    def test_c_main_detected(self):
        content = "int main(int argc, char **argv) {\n  return 0;\n}"
        patterns = _detect_patterns_in_content(content, "C")
        assert "main()" in patterns

    def test_c_syscall_detected(self):
        content = "SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)\n{}"
        patterns = _detect_patterns_in_content(content, "C")
        assert "SYSCALL_DEFINE" in patterns

    def test_python_route_detected(self):
        content = '@app.route("/users")\ndef list_users():\n    pass'
        patterns = _detect_patterns_in_content(content, "Python")
        assert "@app.route" in patterns

    def test_no_patterns_in_generic_code(self):
        content = "static void helper(int x) { return x + 1; }"
        patterns = _detect_patterns_in_content(content, "C")
        assert patterns == []

    def test_nfnetlink_rcv_detected(self):
        content = "static int nfnetlink_rcv(struct sk_buff *skb) {\n  return 0;\n}"
        patterns = _detect_patterns_in_content(content, "C")
        assert "nfnetlink_rcv" in patterns


# =====================================================================
# Tool unit tests (mocked API calls)
# =====================================================================

def _mock_code_search_results(paths):
    """Helper to build mock search_function_callers return values."""
    return [
        {
            "path": p,
            "repository": "torvalds/linux",
            "url": f"https://github.com/torvalds/linux/blob/main/{p}",
            "text_matches": [{"fragment": f"call in {p}"}],
        }
        for p in paths
    ]


class TestAnalyzeCallGraph:
    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_finds_callers(self, mock_search):
        mock_search.return_value = _mock_code_search_results([
            "net/netfilter/nf_tables_api.c",
            "net/netfilter/nft_dynset.c",
        ])
        result = analyze_call_graph("torvalds/linux", "nft_set_deactivate", "C")
        assert result["function_name"] == "nft_set_deactivate"
        assert result["caller_count"] == 2
        assert result["callers"][0]["path"] == "net/netfilter/nf_tables_api.c"

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_no_callers_found(self, mock_search):
        mock_search.return_value = []
        result = analyze_call_graph("torvalds/linux", "obscure_internal_func", "C")
        assert result["caller_count"] == 0
        assert result["callers"] == []

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_api_error_returns_error_dict(self, mock_search):
        import requests
        mock_search.side_effect = requests.ConnectionError("rate limited")
        result = analyze_call_graph("torvalds/linux", "nft_set_deactivate")
        assert "error" in result
        assert result["caller_count"] == 0


class TestDetectEntryPoints:
    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_file_inspection_finds_entry_point(self, mock_fetch):
        mock_fetch.return_value = (
            "SYSCALL_DEFINE3(socket, int, family, int, type, int, proto)\n"
            "{\n  return sock_create(family, type, proto);\n}\n"
        )
        result = detect_entry_points(
            "torvalds/linux", "C",
            file_paths=["net/socket.c"],
        )
        assert result["entry_point_count"] == 1
        assert result["entry_points"][0]["is_entry_point"] is True
        assert "SYSCALL_DEFINE" in result["entry_points"][0]["patterns_found"]

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_file_inspection_no_entry_point(self, mock_fetch):
        mock_fetch.return_value = (
            "static void helper_func(int x) {\n  do_stuff(x);\n}\n"
        )
        result = detect_entry_points(
            "torvalds/linux", "C",
            file_paths=["net/netfilter/helper.c"],
        )
        assert result["entry_point_count"] == 0
        assert result["entry_points"][0]["is_entry_point"] is False

    @patch("patchscope.agents.reachability_analyzer._search_entry_points")
    def test_repo_wide_search(self, mock_search):
        mock_search.return_value = [
            {
                "path": "net/socket.c",
                "pattern_matched": "SYSCALL_DEFINE",
                "text_matches": [{"fragment": "SYSCALL_DEFINE3(socket, ...)"}],
                "url": "https://github.com/torvalds/linux/blob/main/net/socket.c",
            },
        ]
        result = detect_entry_points("torvalds/linux", "C")
        assert result["entry_point_count"] == 1

    @patch("patchscope.agents.reachability_analyzer._search_entry_points")
    def test_api_error_graceful(self, mock_search):
        import requests
        mock_search.side_effect = requests.ConnectionError("fail")
        result = detect_entry_points("torvalds/linux", "C")
        assert "error" in result
        assert result["entry_point_count"] == 0


class TestTraceDataFlow:
    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_direct_path_found(self, mock_search):
        """Source function found in first hop of callers."""
        mock_search.return_value = [
            {
                "path": "net/netfilter/nf_tables_api.c",
                "text_matches": [
                    {"fragment": "void nfnetlink_rcv_msg(...) {\n  nft_set_deactivate(ctx);\n}"}
                ],
                "url": "https://github.com/torvalds/linux/blob/main/net/netfilter/nf_tables_api.c",
            },
        ]
        result = trace_data_flow(
            "torvalds/linux", "nfnetlink_rcv_msg", "nft_set_deactivate",
        )
        assert result["path_found"] is True
        assert result["hop_count"] == 1
        assert "nfnetlink_rcv_msg" in result["call_chain"]
        assert "nft_set_deactivate" in result["call_chain"]

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_no_callers_no_path(self, mock_search):
        mock_search.return_value = []
        result = trace_data_flow(
            "torvalds/linux", "main", "obscure_func",
        )
        assert result["path_found"] is False
        assert result["call_chain"] == ["obscure_func"]

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_multi_hop_path(self, mock_search):
        """Caller of caller contains the source function (2 hops)."""
        # First call: callers of target_func → finds intermediate_func
        # Second call: callers of intermediate_func → finds source_func
        mock_search.side_effect = [
            # Hop 1: callers of nft_set_deactivate
            [{
                "path": "net/netfilter/nf_tables_api.c",
                "text_matches": [
                    {"fragment": "static int nf_tables_delset(...) {\n  nft_set_deactivate(set);\n}"}
                ],
                "url": "url1",
            }],
            # Hop 2: callers of nf_tables_delset → finds nfnetlink_rcv
            [{
                "path": "net/netfilter/nfnetlink.c",
                "text_matches": [
                    {"fragment": "void nfnetlink_rcv(...) {\n  nf_tables_delset(...);\n}"}
                ],
                "url": "url2",
            }],
        ]
        result = trace_data_flow(
            "torvalds/linux", "nfnetlink_rcv", "nft_set_deactivate",
        )
        assert result["path_found"] is True
        assert result["hop_count"] == 2


class TestDetectAuthGates:
    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_c_capability_check_detected(self, mock_fetch):
        mock_fetch.return_value = (
            "#include <linux/capability.h>\n"
            "static int nfnetlink_rcv_msg(struct sk_buff *skb) {\n"
            "    if (!capable(CAP_NET_ADMIN))\n"
            "        return -EPERM;\n"
            "    /* process message */\n"
            "}\n"
        )
        result = detect_auth_gates("torvalds/linux", "net/netfilter/nfnetlink.c")
        assert result["has_auth_gate"] is True
        assert len(result["auth_mechanisms"]) >= 1
        types = [m["type"] for m in result["auth_mechanisms"]]
        assert "capability_check" in types

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_python_login_required_detected(self, mock_fetch):
        mock_fetch.return_value = (
            "from flask_login import login_required\n\n"
            "@login_required\n"
            "def dashboard():\n"
            "    return render_template('dashboard.html')\n"
        )
        result = detect_auth_gates("org/webapp", "app/views.py")
        assert result["has_auth_gate"] is True
        labels = [m["label"] for m in result["auth_mechanisms"]]
        assert "login_required" in labels

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_no_auth_gates(self, mock_fetch):
        mock_fetch.return_value = (
            "static void process_data(struct data *d) {\n"
            "    transform(d->buf, d->len);\n"
            "    output(d);\n"
            "}\n"
        )
        result = detect_auth_gates("torvalds/linux", "lib/data.c")
        assert result["has_auth_gate"] is False
        assert result["auth_mechanisms"] == []

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_api_error_graceful(self, mock_fetch):
        import requests
        mock_fetch.side_effect = requests.ConnectionError("fail")
        result = detect_auth_gates("torvalds/linux", "some/file.c")
        assert "error" in result
        assert result["has_auth_gate"] is False


# =====================================================================
# Branching scenario tests
# =====================================================================

class TestBranchingScenarios:
    """Verify tool outputs produce the signals that drive agent branching."""

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_callers_found_proceed_to_entry_points(self, mock_search):
        """When callers exist, agent should check if they are entry points."""
        mock_search.return_value = _mock_code_search_results([
            "net/netfilter/nf_tables_api.c",
        ])
        result = analyze_call_graph("torvalds/linux", "nft_set_deactivate", "C")
        assert result["caller_count"] > 0  # Agent: proceed to detect_entry_points

    @patch("patchscope.agents.reachability_analyzer.search_function_callers")
    def test_no_callers_signals_low_reachability(self, mock_search):
        """No callers → agent should report low reachability confidence."""
        mock_search.return_value = []
        result = analyze_call_graph("torvalds/linux", "static_internal_func", "C")
        assert result["caller_count"] == 0  # Agent: report low confidence

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_entry_point_found_skip_trace(self, mock_fetch):
        """Caller IS an entry point → no need for trace_data_flow."""
        mock_fetch.return_value = (
            "SYSCALL_DEFINE3(socket, int, family, int, type, int, proto)\n{}\n"
        )
        result = detect_entry_points(
            "torvalds/linux", "C",
            file_paths=["net/socket.c"],
        )
        assert result["entry_point_count"] > 0  # Agent: skip to auth gates

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_no_entry_point_signals_trace_needed(self, mock_fetch):
        """Caller is not an entry point → agent should use trace_data_flow."""
        mock_fetch.return_value = "static void internal_helper(int x) { }"
        result = detect_entry_points(
            "torvalds/linux", "C",
            file_paths=["net/netfilter/internal.c"],
        )
        assert result["entry_point_count"] == 0  # Agent: use trace_data_flow

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_auth_gate_affects_bypassability(self, mock_fetch):
        """Auth gate detected → agent should note it reduces exploit ease."""
        mock_fetch.return_value = (
            "if (!capable(CAP_NET_ADMIN))\n"
            "    return -EPERM;\n"
        )
        result = detect_auth_gates("torvalds/linux", "net/netfilter/nfnetlink.c")
        assert result["has_auth_gate"] is True  # Agent: note auth barrier

    @patch("patchscope.agents.reachability_analyzer.fetch_file_content")
    def test_no_auth_gate_increases_risk(self, mock_fetch):
        """No auth gate → agent should note code is unprotected."""
        mock_fetch.return_value = "void process(void *buf) { memcpy(dst, buf, len); }"
        result = detect_auth_gates("torvalds/linux", "net/core/skbuff.c")
        assert result["has_auth_gate"] is False  # Agent: higher risk


# =====================================================================
# Integration tests (require network — mark so they can be skipped)
# =====================================================================

@pytest.mark.integration
class TestIntegrationReachability:
    """Full reachability analysis with real GitHub API."""

    def test_nft_set_deactivate_reachability(self):
        """CVE-2023-32233: trace callers of nft_set_deactivate in torvalds/linux."""
        result = analyze_call_graph("torvalds/linux", "nft_set_deactivate", "C")
        assert result["caller_count"] > 0
        print(f"\n  Callers of nft_set_deactivate: {result['caller_count']}")
        for c in result["callers"][:3]:
            print(f"    - {c['path']}")

        # Check if any caller files have entry points
        caller_paths = [c["path"] for c in result["callers"][:3]]
        ep_result = detect_entry_points(
            "torvalds/linux", "C", file_paths=caller_paths,
        )
        print(f"  Entry points found: {ep_result['entry_point_count']}")

        # Check for auth gates in a known nfnetlink file
        auth_result = detect_auth_gates(
            "torvalds/linux", "net/netfilter/nfnetlink.c",
        )
        print(f"  Auth gates: {auth_result['has_auth_gate']}")
        if auth_result["has_auth_gate"]:
            for m in auth_result["auth_mechanisms"]:
                print(f"    - {m['label']}: {m['line']}")


# =====================================================================
# Static analysis unit tests  (no network required)
# =====================================================================

class TestBuildCallGraphPython:
    """build_call_graph with Python source using stdlib ast."""

    def setup_method(self):
        self.repo = _make_python_repo()

    def teardown_method(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_finds_direct_callers(self):
        result = build_call_graph(self.repo, "Python", "vulnerable_func")
        assert result["analysis_method"] == "python_ast"
        functions = {c["function"] for c in result["callers"]}
        assert "process_items" in functions
        assert "helper" in functions

    def test_call_sites_have_line_numbers(self):
        result = build_call_graph(self.repo, "Python", "vulnerable_func")
        for site in result["call_sites"]:
            assert "line" in site
            assert isinstance(site["line"], int)
            assert site["line"] > 0

    def test_unrelated_function_not_in_callers(self):
        result = build_call_graph(self.repo, "Python", "vulnerable_func")
        functions = {c["function"] for c in result["callers"]}
        assert "list_items" not in functions  # list_items calls process_items, not vulnerable_func

    def test_no_callers_returns_empty(self):
        result = build_call_graph(self.repo, "Python", "totally_missing_xyz")
        assert result["callers"] == []
        assert result["call_sites"] == []
        assert result["files_analyzed"] > 0

    def test_files_analyzed_count(self):
        result = build_call_graph(self.repo, "Python", "vulnerable_func")
        assert result["files_analyzed"] == 2


class TestBuildCallGraphJava:
    """build_call_graph with Java source using tree-sitter-java."""

    def setup_method(self):
        self.repo = _make_java_repo()

    def teardown_method(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_finds_java_callers(self):
        result = build_call_graph(self.repo, "Java", "deactivateSet")
        assert result["analysis_method"] == "tree_sitter_java"
        functions = {c["function"] for c in result["callers"]}
        assert "createTable" in functions
        assert "cleanup" in functions

    def test_java_call_sites_have_lines(self):
        result = build_call_graph(self.repo, "Java", "deactivateSet")
        assert len(result["call_sites"]) == 2
        for site in result["call_sites"]:
            assert site["line"] > 0

    def test_java_no_callers_for_unknown(self):
        result = build_call_graph(self.repo, "Java", "doesNotExist")
        assert result["callers"] == []

    def test_java_files_analyzed(self):
        result = build_call_graph(self.repo, "Java", "deactivateSet")
        assert result["files_analyzed"] == 1


class TestBuildCallGraphC:
    """build_call_graph with C source using tree-sitter-c."""

    def setup_method(self):
        self.repo = _make_c_repo()

    def teardown_method(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_finds_c_caller(self):
        result = build_call_graph(self.repo, "C", "nft_set_deactivate")
        assert result["analysis_method"] == "tree_sitter_c"
        functions = {c["function"] for c in result["callers"]}
        assert "nf_tables_delset" in functions

    def test_c_call_site_line_number(self):
        result = build_call_graph(self.repo, "C", "nft_set_deactivate")
        assert len(result["call_sites"]) == 1
        assert result["call_sites"][0]["line"] == 4

    def test_c_no_callers_for_unknown(self):
        result = build_call_graph(self.repo, "C", "unknown_func_xyz")
        assert result["callers"] == []

    def test_unsupported_language_returns_error(self):
        result = build_call_graph(self.repo, "Go", "some_func")
        assert result["analysis_method"] == "unsupported"
        assert "error" in result


class TestFindEntryPointsInRepo:
    """find_entry_points_in_repo across all three languages."""

    def test_python_http_route_detected(self):
        repo = _make_python_repo()
        try:
            eps = find_entry_points_in_repo(repo, "Python")
            types = {ep["type"] for ep in eps}
            assert "http_route" in types
            names = {ep["function"] for ep in eps}
            assert "list_items" in names
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_java_spring_endpoint_detected(self):
        repo = _make_java_repo()
        try:
            eps = find_entry_points_in_repo(repo, "Java")
            types = {ep["type"] for ep in eps}
            assert "http_endpoint" in types
            names = {ep["function"] for ep in eps}
            assert "createTable" in names
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_java_main_detected(self):
        repo = _make_java_repo()
        try:
            eps = find_entry_points_in_repo(repo, "Java")
            types = {ep["type"] for ep in eps}
            assert "main_entry" in types
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_c_syscall_detected(self):
        repo = _make_c_repo()
        try:
            eps = find_entry_points_in_repo(repo, "C")
            types = {ep["type"] for ep in eps}
            assert "syscall_handler" in types
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_c_netlink_handler_detected(self):
        repo = _make_c_repo()
        try:
            eps = find_entry_points_in_repo(repo, "C")
            types = {ep["type"] for ep in eps}
            assert "netlink_handler" in types
            names = {ep["function"] for ep in eps}
            assert "nfnetlink_rcv_msg" in names
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_unsupported_language_returns_empty(self):
        repo = _make_python_repo()
        try:
            eps = find_entry_points_in_repo(repo, "Rust")
            assert eps == []
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class TestCloneAndAnalyzeCallGraph:
    """clone_and_analyze_call_graph tool — mocking the clone step."""

    @patch("patchscope.agents.reachability_analyzer.clone_repo")
    @patch("patchscope.agents.reachability_analyzer.build_call_graph")
    def test_returns_callers_and_repo_path(self, mock_build, mock_clone):
        mock_clone.return_value = "/tmp/fake_clone"
        mock_build.return_value = {
            "callers": [{"function": "foo", "class": None, "file": "a.py", "line": 10}],
            "call_sites": [{"file": "a.py", "line": 10, "expression": "target_func()"}],
            "files_analyzed": 5,
            "analysis_method": "python_ast",
        }
        result = clone_and_analyze_call_graph(
            "owner/repo", "target_func", "Python"
        )
        assert result["caller_count"] == 1
        assert result["callers"][0]["function"] == "foo"
        assert result["repo_path"] == "/tmp/fake_clone"
        assert result["analysis_method"] == "python_ast"

    @patch("patchscope.agents.reachability_analyzer.clone_repo")
    def test_clone_failure_returns_error(self, mock_clone):
        mock_clone.side_effect = RuntimeError("git clone timed out")
        result = clone_and_analyze_call_graph(
            "owner/repo", "target_func", "Python"
        )
        assert "error" in result
        assert result["caller_count"] == 0
        assert result["analysis_method"] == "clone_failed"

    def test_unsupported_language_skips_clone(self):
        # Should return immediately without calling clone_repo
        result = clone_and_analyze_call_graph(
            "owner/repo", "target_func", "Go"
        )
        assert result["analysis_method"] == "unsupported"
        assert "error" in result
        assert result["caller_count"] == 0


class TestFindEntryPointsStaticTool:
    """find_entry_points_static tool — mocking the clone step."""

    @patch("patchscope.agents.reachability_analyzer.clone_repo")
    @patch("patchscope.agents.reachability_analyzer.find_entry_points_in_repo")
    def test_fresh_clone_returns_entry_points(self, mock_find, mock_clone):
        mock_clone.return_value = "/tmp/fake_clone"
        mock_find.return_value = [
            {"function": "main", "file": "Main.java", "line": 5, "type": "main_entry"},
        ]
        result = find_entry_points_static("owner/repo", "Java")
        assert result["entry_point_count"] == 1
        assert result["entry_points"][0]["function"] == "main"
        assert result["repo_path"] == "/tmp/fake_clone"

    @patch("patchscope.agents.reachability_analyzer.find_entry_points_in_repo")
    def test_reuses_existing_repo_path(self, mock_find):
        """When repo_path is provided, no clone is performed."""
        mock_find.return_value = [
            {"function": "handler", "file": "h.py", "line": 1, "type": "http_route"},
        ]
        result = find_entry_points_static(
            "owner/repo", "Python", repo_path="/tmp/existing"
        )
        assert result["entry_point_count"] == 1
        mock_find.assert_called_once_with("/tmp/existing", "Python")

    @patch("patchscope.agents.reachability_analyzer.clone_repo")
    def test_clone_failure_returns_error(self, mock_clone):
        mock_clone.side_effect = RuntimeError("network error")
        result = find_entry_points_static("owner/repo", "Python")
        assert "error" in result
        assert result["entry_point_count"] == 0


# =====================================================================
# Integration test — real clone + static analysis (requires network + git)
# =====================================================================

@pytest.mark.integration
class TestIntegrationStaticAnalysis:
    """Static analysis with a real GitHub clone."""

    def test_static_call_graph_linux_nft_set_deactivate(self):
        """CVE-2023-32233: build real call graph for nft_set_deactivate."""
        result = clone_and_analyze_call_graph(
            "torvalds/linux", "nft_set_deactivate", "C",
        )
        try:
            assert result["analysis_method"] in ("tree_sitter_c", "clone_failed")
            if result["analysis_method"] == "tree_sitter_c":
                assert result["caller_count"] > 0
                print(f"\n  Static callers of nft_set_deactivate: {result['caller_count']}")
                for c in result["callers"][:5]:
                    print(f"    {c['function']} in {c['file']}:{c['line']}")
        finally:
            if "repo_path" in result:
                cleanup_clone(result["repo_path"])
