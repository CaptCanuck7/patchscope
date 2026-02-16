"""Tests for patchscope.tools.github_client."""

import pytest
from patchscope.tools.github_client import parse_commit_url, fetch_commit_diff


class TestParseCommitUrl:
    def test_valid_url(self):
        url = "https://github.com/curl/curl/commit/3ee79c1674fd6f99e8efad5c0ac956302ee47b1"
        owner, repo, sha = parse_commit_url(url)
        assert owner == "curl"
        assert repo == "curl"
        assert sha == "3ee79c1674fd6f99e8efad5c0ac956302ee47b1"

    def test_short_sha(self):
        url = "https://github.com/owner/repo/commit/abcdef1"
        owner, repo, sha = parse_commit_url(url)
        assert sha == "abcdef1"

    def test_rejects_http(self):
        with pytest.raises(ValueError, match="HTTPS"):
            parse_commit_url("http://github.com/o/r/commit/abc1234")

    def test_rejects_non_github(self):
        with pytest.raises(ValueError, match="GitHub"):
            parse_commit_url("https://gitlab.com/o/r/commit/abc1234")

    def test_rejects_non_commit_path(self):
        with pytest.raises(ValueError, match="commit"):
            parse_commit_url("https://github.com/curl/curl/pull/123")


class TestFetchCommitDiff:
    """Integration test — requires network access."""

    def test_known_commit(self):
        # CVE-2023-32233 Linux kernel nf_tables fix
        url = "https://github.com/torvalds/linux/commit/c1592a89942e9678f7d9c8030efa777c0d57edab"
        result = fetch_commit_diff(url)

        assert result["repository"] == "torvalds/linux"
        assert result["sha"] == "c1592a89942e9678f7d9c8030efa777c0d57edab"
        assert len(result["files"]) > 0
        assert "message" in result
        assert "diff_summary" in result

        # Check file structure
        f = result["files"][0]
        assert "filename" in f
        assert "patch" in f
        assert "language" in f
