"""Tests for the agentic patch parser tools, diff utilities, and branching logic."""

import pytest
from unittest.mock import patch, MagicMock

from patchscope.utils.diff_parser import (
    extract_changed_lines,
    find_security_keywords,
    extract_function_names,
    assess_diff_quality,
)
from patchscope.agents.patch_parser import (
    nvd_lookup,
    search_github_commits,
    fetch_commit,
    search_github_advisories,
    fetch_related_commits,
)


# =====================================================================
# Diff parser unit tests
# =====================================================================

class TestExtractChangedLines:
    SAMPLE_PATCH = """\
@@ -10,7 +10,9 @@ void handle_request(char *hostname) {
-  strcpy(buf, hostname);
+  if(strlen(hostname) > sizeof(buf) - 1) {
+    return CURLE_BAD_FUNCTION_ARGUMENT;
+  }
+  strncpy(buf, hostname, sizeof(buf) - 1);
"""

    def test_extract_changed_lines(self):
        result = extract_changed_lines(self.SAMPLE_PATCH)
        assert len(result["added"]) == 4
        assert len(result["removed"]) == 1
        assert "strcpy(buf, hostname);" in result["removed"][0]

    def test_find_security_keywords(self):
        keywords = find_security_keywords(self.SAMPLE_PATCH)
        assert "strcpy" in keywords
        assert "sizeof" in keywords


class TestExtractFunctionNames:
    def test_c_function_from_hunk_header(self):
        patch = "@@ -10,7 +10,9 @@ void handle_request(char *hostname) {\n-old\n+new\n"
        assert "handle_request" in extract_function_names(patch)

    def test_python_def(self):
        patch = "@@ -5,3 +5,5 @@ def process_input(data):\n-old\n+new\n"
        assert "process_input" in extract_function_names(patch)

    def test_rust_fn(self):
        patch = "@@ -1,3 +1,5 @@ fn validate_token(tok: &str) -> bool {\n-old\n+new\n"
        funcs = extract_function_names(patch)
        assert "validate_token" in funcs

    def test_javascript_function(self):
        patch = "@@ -1,3 +1,5 @@ function handleAuth(req, res) {\n-old\n+new\n"
        assert "handleAuth" in extract_function_names(patch)

    def test_no_function_context(self):
        patch = "@@ -1,3 +1,3 @@\n-old\n+new\n"
        assert extract_function_names(patch) == []

    def test_empty_context_after_at(self):
        patch = "@@ -1,3 +1,3 @@   \n-old\n+new\n"
        assert extract_function_names(patch) == []

    def test_multiple_hunks_deduplicated(self):
        patch = (
            "@@ -10,3 +10,3 @@ int funcA(int x) {\n-a\n+b\n"
            "@@ -20,3 +20,3 @@ int funcA(int x) {\n-c\n+d\n"
            "@@ -30,3 +30,3 @@ int funcB(int y) {\n-e\n+f\n"
        )
        funcs = extract_function_names(patch)
        assert funcs == ["funcA", "funcB"]

    def test_plain_text_not_treated_as_function(self):
        """Non-hunk lines starting with @@ shouldn't be parsed."""
        patch = "some code with @@ in it\n-old\n+new\n"
        assert extract_function_names(patch) == []


class TestAssessDiffQuality:
    def test_high_quality_all_signals(self):
        files = [{
            "additions": 10, "deletions": 5,
            "patch": "something",
            "security_keywords": ["overflow", "buffer"],
            "functions_modified": ["handle_request"],
        }]
        q = assess_diff_quality(files)
        assert q["is_sufficient"] is True
        assert q["quality_score"] == 1.0
        assert q["issues"] == []

    def test_zero_lines_zero_everything(self):
        files = [{
            "additions": 0, "deletions": 0,
            "patch": "",
            "security_keywords": [],
            "functions_modified": [],
        }]
        q = assess_diff_quality(files)
        assert q["is_sufficient"] is False
        assert q["quality_score"] == 0.0
        assert "no_changed_lines" in q["issues"]
        assert "no_patch_content" in q["issues"]

    def test_few_changes_with_patch_and_keywords(self):
        files = [{
            "additions": 1, "deletions": 1,
            "patch": "+validate(input)",
            "security_keywords": ["validate"],
            "functions_modified": [],
        }]
        q = assess_diff_quality(files)
        # 0.15 (few lines) + 0.3 (patch) + 0.2 (keywords) = 0.65
        assert q["is_sufficient"] is True
        assert q["quality_score"] == 0.65

    def test_good_lines_no_keywords_no_functions(self):
        files = [{
            "additions": 10, "deletions": 5,
            "patch": "logic changes",
            "security_keywords": [],
            "functions_modified": [],
        }]
        q = assess_diff_quality(files)
        # 0.3 (lines) + 0.3 (patch) = 0.6
        assert q["is_sufficient"] is True
        assert "no_security_keywords" in q["issues"]
        assert "no_functions_identified" in q["issues"]

    def test_empty_files_list(self):
        q = assess_diff_quality([])
        assert q["is_sufficient"] is False
        assert q["total_changed_lines"] == 0

    def test_multiple_files_aggregate(self):
        files = [
            {
                "additions": 3, "deletions": 1, "patch": "a",
                "security_keywords": ["auth"], "functions_modified": ["login"],
            },
            {
                "additions": 2, "deletions": 0, "patch": "b",
                "security_keywords": [], "functions_modified": [],
            },
        ]
        q = assess_diff_quality(files)
        assert q["total_changed_lines"] == 6
        assert q["total_security_keywords"] == 1
        assert q["files_with_patches"] == 2
        assert q["functions_found"] == 1


# =====================================================================
# Tool unit tests (mocked API calls)
# =====================================================================

def _nvd_response(cve_id, description, severity, references):
    """Helper to build a mock NVD fetch_cve_data return value."""
    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "references": references,
        "raw_data": {},
    }


class TestNvdLookup:
    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_tagged_patch_urls(self, mock_fetch):
        """NVD has Patch-tagged commit URLs → patch_urls populated."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2023-32233", "Use-after-free in nf_tables",
            {"score": 7.8, "severity": "HIGH"},
            [
                {"url": "https://github.com/torvalds/linux/commit/abc123", "tags": ["Patch"]},
                {"url": "https://security-tracker.debian.org/foo", "tags": ["Third Party Advisory"]},
            ],
        )
        result = nvd_lookup("CVE-2023-32233")
        assert result["cve_id"] == "CVE-2023-32233"
        assert len(result["patch_urls"]) == 1
        assert "abc123" in result["patch_urls"][0]
        assert len(result["advisory_urls"]) == 1

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_fallback_to_untagged_commits(self, mock_fetch):
        """No Patch tags but commit URLs exist → fallback picks them up."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2023-99999", "Some vulnerability", None,
            [
                {"url": "https://github.com/org/repo/commit/def456", "tags": []},
                {"url": "https://github.com/org/repo/issues/42", "tags": []},
            ],
        )
        result = nvd_lookup("CVE-2023-99999")
        assert len(result["patch_urls"]) == 1
        assert "def456" in result["patch_urls"][0]

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_no_github_urls_at_all(self, mock_fetch):
        """NVD has no GitHub URLs → empty patch_urls signals agent to escalate."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2023-38545", "curl SOCKS5 heap overflow",
            {"score": 9.8, "severity": "CRITICAL"},
            [
                {"url": "https://curl.se/docs/CVE-2023-38545.html", "tags": ["Vendor Advisory"]},
            ],
        )
        result = nvd_lookup("CVE-2023-38545")
        assert len(result["patch_urls"]) == 0
        assert len(result["github_urls"]) == 0
        assert len(result["advisory_urls"]) == 1

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_invalid_cve_returns_error(self, mock_fetch):
        """Invalid CVE format → error dict instead of exception."""
        mock_fetch.side_effect = ValueError("Invalid CVE ID format: 'NOTACVE'.")
        result = nvd_lookup("NOTACVE")
        assert "error" in result


class TestSearchGitHubCommits:
    @patch("patchscope.agents.patch_parser._search_commits")
    def test_finds_commits(self, mock_search):
        mock_search.return_value = {
            "total_count": 1,
            "commits": [{
                "sha": "abc123",
                "message": "Fix CVE-2023-38545",
                "author": "dev",
                "date": "2023-10-11T00:00:00Z",
                "url": "https://github.com/curl/curl/commit/abc123",
                "repository": "curl/curl",
            }],
        }
        result = search_github_commits("CVE-2023-38545")
        assert result["total_count"] == 1
        assert result["commits"][0]["repository"] == "curl/curl"

    @patch("patchscope.agents.patch_parser._search_commits")
    def test_no_results(self, mock_search):
        mock_search.return_value = {"total_count": 0, "commits": []}
        result = search_github_commits("CVE-9999-99999")
        assert result["total_count"] == 0

    @patch("patchscope.agents.patch_parser._search_commits")
    def test_api_error_returns_error_dict(self, mock_search):
        """Network error → graceful error dict, not exception."""
        import requests
        mock_search.side_effect = requests.ConnectionError("timeout")
        result = search_github_commits("CVE-2023-38545")
        assert "error" in result
        assert result["total_count"] == 0


class TestSearchGitHubAdvisories:
    @patch("patchscope.agents.patch_parser._search_advisories")
    def test_finds_advisory_with_fix_commit(self, mock_search):
        mock_search.return_value = {
            "total_found": 1,
            "advisories": [{
                "ghsa_id": "GHSA-xxxx-yyyy",
                "cve_id": "CVE-2023-38545",
                "summary": "SOCKS5 heap overflow",
                "severity": "critical",
                "fix_commits": ["https://github.com/curl/curl/commit/abc123"],
                "references": [],
                "vulnerabilities": [],
                "source_repository": "https://github.com/curl/curl",
            }],
        }
        result = search_github_advisories("CVE-2023-38545")
        assert result["total_found"] == 1
        assert len(result["advisories"][0]["fix_commits"]) == 1

    @patch("patchscope.agents.patch_parser._search_advisories")
    def test_no_advisories(self, mock_search):
        mock_search.return_value = {"total_found": 0, "advisories": []}
        result = search_github_advisories("CVE-9999-99999")
        assert result["total_found"] == 0

    @patch("patchscope.agents.patch_parser._search_advisories")
    def test_api_error_graceful(self, mock_search):
        import requests
        mock_search.side_effect = requests.ConnectionError("fail")
        result = search_github_advisories("CVE-2023-38545")
        assert "error" in result
        assert result["total_found"] == 0


class TestFetchCommit:
    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_returns_quality_and_functions(self, mock_diff):
        """fetch_commit enriches diff with functions and quality assessment."""
        mock_diff.return_value = {
            "repository": "torvalds/linux",
            "sha": "c1592a8",
            "message": "netfilter: nf_tables: deactivate anonymous set",
            "author": "Pablo",
            "date": "2023-05-01",
            "diff_summary": "1 file changed",
            "files": [{
                "filename": "net/netfilter/nf_tables_api.c",
                "language": "C",
                "status": "modified",
                "additions": 10,
                "deletions": 3,
                "patch": (
                    "@@ -5,3 +5,10 @@ void nft_set_deactivate(struct nft_ctx *ctx) {\n"
                    "-  old_code;\n"
                    "+  if (set->flags & NFT_SET_ANONYMOUS)\n"
                    "+    nft_deactivate(set);\n"
                    "+  free(old);\n"
                ),
            }],
        }
        result = fetch_commit("https://github.com/torvalds/linux/commit/c1592a8")
        assert "quality" in result
        assert result["quality"]["total_changed_lines"] == 13
        assert "nft_set_deactivate" in result["files"][0]["functions_modified"]
        assert "free" in result["files"][0]["security_keywords"]

    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_empty_patch_flagged_low_quality(self, mock_diff):
        mock_diff.return_value = {
            "repository": "some/repo",
            "sha": "abc123",
            "message": "Update config",
            "author": "Dev",
            "date": "2023-01-01",
            "diff_summary": "1 file changed",
            "files": [{
                "filename": "config.json",
                "language": "Other",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": "",
            }],
        }
        result = fetch_commit("https://github.com/some/repo/commit/abc123")
        assert result["quality"]["is_sufficient"] is False
        assert "no_patch_content" in result["quality"]["issues"]

    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_invalid_url_returns_error(self, mock_diff):
        mock_diff.side_effect = ValueError("Not a valid GitHub HTTPS URL")
        result = fetch_commit("not-a-url")
        assert "error" in result


class TestFetchRelatedCommits:
    @patch("patchscope.agents.patch_parser._fetch_related")
    def test_returns_parent_commits(self, mock_related):
        mock_related.return_value = {
            "repository": "torvalds/linux",
            "base_sha": "abc123",
            "parent_commits": [
                {
                    "sha": "def456",
                    "message": "Related preceding change",
                    "author": "Dev",
                    "date": "2023-01-01",
                    "url": "https://github.com/torvalds/linux/commit/def456",
                },
            ],
        }
        result = fetch_related_commits("torvalds/linux", "abc123")
        assert len(result["parent_commits"]) == 1
        assert result["parent_commits"][0]["sha"] == "def456"

    @patch("patchscope.agents.patch_parser._fetch_related")
    def test_api_error_graceful(self, mock_related):
        import requests
        mock_related.side_effect = requests.ConnectionError("fail")
        result = fetch_related_commits("org/repo", "abc")
        assert "error" in result


# =====================================================================
# Branching scenario tests
# =====================================================================

class TestBranchingScenarios:
    """Verify tool outputs produce the signals that drive agent branching."""

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_nvd_with_patches_no_escalation_needed(self, mock_fetch):
        """When NVD returns patch URLs, the agent can go straight to fetch_commit."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2023-32233", "nf_tables UAF",
            {"score": 7.8, "severity": "HIGH"},
            [{"url": "https://github.com/torvalds/linux/commit/c1592a8", "tags": ["Patch"]}],
        )
        result = nvd_lookup("CVE-2023-32233")
        assert len(result["patch_urls"]) > 0  # Agent: proceed to fetch_commit

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_nvd_no_patches_signals_advisory_fallback(self, mock_fetch):
        """No patch URLs → agent should try search_github_advisories next."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2023-38545", "curl heap overflow",
            {"score": 9.8, "severity": "CRITICAL"},
            [{"url": "https://curl.se/advisory", "tags": ["Vendor Advisory"]}],
        )
        result = nvd_lookup("CVE-2023-38545")
        assert len(result["patch_urls"]) == 0  # Agent: try advisories
        assert len(result["advisory_urls"]) > 0  # Hint: advisories exist

    @patch("patchscope.agents.patch_parser.fetch_cve_data")
    def test_nvd_no_refs_signals_github_search(self, mock_fetch):
        """No references at all → agent should fall back to GitHub search."""
        mock_fetch.return_value = _nvd_response(
            "CVE-2024-00001", "Obscure vulnerability", None, [],
        )
        result = nvd_lookup("CVE-2024-00001")
        assert len(result["patch_urls"]) == 0
        assert len(result["advisory_urls"]) == 0
        # Agent: last resort is search_github_commits

    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_low_quality_signals_fetch_related(self, mock_diff):
        """Low quality diff → agent should call fetch_related_commits."""
        mock_diff.return_value = {
            "repository": "org/repo", "sha": "aaa111",
            "message": "Bump version", "author": "bot",
            "date": "2023-06-01", "diff_summary": "1 file",
            "files": [{
                "filename": "VERSION", "language": "Other",
                "status": "modified", "additions": 1, "deletions": 1,
                "patch": "+1.2.4",
            }],
        }
        result = fetch_commit("https://github.com/org/repo/commit/aaa111")
        assert result["quality"]["is_sufficient"] is False  # Agent: fetch related
        assert result["quality"]["quality_score"] < 0.5

    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_sufficient_quality_proceed_to_classify(self, mock_diff):
        """Good quality → agent can classify without further tool calls."""
        mock_diff.return_value = {
            "repository": "torvalds/linux", "sha": "c1592a8",
            "message": "netfilter: fix UAF",
            "author": "Pablo", "date": "2023-05-01",
            "diff_summary": "3 files",
            "files": [{
                "filename": "net/netfilter/nf_tables_api.c",
                "language": "C", "status": "modified",
                "additions": 10, "deletions": 5,
                "patch": (
                    "@@ -10,7 +10,12 @@ void nft_set_deactivate(struct nft_ctx *ctx) {\n"
                    "-  old_code;\n"
                    "+  if (set->flags & NFT_SET_ANONYMOUS)\n"
                    "+    nft_deactivate_next(net, set);\n"
                    "+  free(old);\n"
                ),
            }],
        }
        result = fetch_commit("https://github.com/torvalds/linux/commit/c1592a8")
        assert result["quality"]["is_sufficient"] is True  # Agent: classify now
        assert result["quality"]["quality_score"] >= 0.6

    @patch("patchscope.agents.patch_parser._fetch_commit_diff")
    def test_no_functions_but_otherwise_ok(self, mock_diff):
        """No functions identified but good changes → still sufficient for config fixes."""
        mock_diff.return_value = {
            "repository": "org/app", "sha": "bbb222",
            "message": "Fix open redirect in config",
            "author": "dev", "date": "2023-07-01",
            "diff_summary": "1 file",
            "files": [{
                "filename": "config/routes.yaml",
                "language": "Other", "status": "modified",
                "additions": 5, "deletions": 3,
                "patch": (
                    "@@ -1,5 +1,7 @@\n"
                    "- redirect: *\n"
                    "+ redirect: /dashboard\n"
                    "+ validate: origin\n"
                ),
            }],
        }
        result = fetch_commit("https://github.com/org/app/commit/bbb222")
        # Lines (0.3) + patch (0.3) + keywords "redirect" + "origin" (0.2) = 0.8
        assert result["quality"]["is_sufficient"] is True
        assert "no_functions_identified" in result["quality"]["issues"]


# =====================================================================
# Integration tests (require network — mark so they can be skipped)
# =====================================================================

@pytest.mark.integration
class TestIntegrationNvdToCommit:
    """Full NVD→commit pipeline with real APIs."""

    def test_cve_2023_32233_pipeline(self):
        """CVE-2023-32233: nvd_lookup finds patches → fetch_commit parses them."""
        nvd = nvd_lookup("CVE-2023-32233")
        assert nvd["cve_id"] == "CVE-2023-32233"
        assert len(nvd["patch_urls"]) > 0

        result = fetch_commit(nvd["patch_urls"][0])
        assert result["repository"] == "torvalds/linux"
        assert len(result["files"]) > 0
        assert result["quality"]["is_sufficient"] is True

        all_keywords = set()
        all_functions = []
        for f in result["files"]:
            all_keywords.update(f["security_keywords"])
            all_functions.extend(f["functions_modified"])
        assert len(all_keywords) > 0

        print(f"\n  CVE: {nvd['cve_id']}")
        print(f"  Repo: {result['repository']}")
        print(f"  Quality: {result['quality']}")
        print(f"  Keywords: {sorted(all_keywords)}")
        print(f"  Functions: {all_functions}")


@pytest.mark.integration
class TestIntegrationDirectCommit:
    """Test fetch_commit with a known URL."""

    def test_known_linux_commit(self):
        url = "https://github.com/torvalds/linux/commit/c1592a89942e9678f7d9c8030efa777c0d57edab"
        result = fetch_commit(url)
        assert result["repository"] == "torvalds/linux"
        assert len(result["files"]) > 0
        assert "quality" in result
        assert "commit_message" in result
