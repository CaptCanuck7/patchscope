"""GitHub API client for fetching commit diffs."""

import os
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"

_COMMIT_PATH_RE = re.compile(
    r"^/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)/commit/([a-f0-9]{7,40})$"
)

_EXTENSION_LANGUAGES = {
    ".c": "C", ".h": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++",
    ".py": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".sh": "Shell",
}


def parse_commit_url(url: str) -> tuple[str, str, str]:
    """Parse and validate a GitHub commit URL.

    Returns:
        (owner, repo, sha)

    Raises:
        ValueError: if the URL is not a valid GitHub commit URL.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ValueError(f"Not a valid GitHub HTTPS URL: {url}")

    match = _COMMIT_PATH_RE.match(parsed.path)
    if not match:
        raise ValueError(f"URL path is not a GitHub commit: {parsed.path}")

    return match.group(1), match.group(2), match.group(3)


def _detect_language(filename: str) -> str:
    suffix = PurePosixPath(filename).suffix.lower()
    return _EXTENSION_LANGUAGES.get(suffix, "Other")


def fetch_commit_diff(commit_url: str) -> dict:
    """Fetch commit metadata and file-level diffs from GitHub.

    Args:
        commit_url: Full GitHub commit URL,
                    e.g. https://github.com/curl/curl/commit/abc123def

    Returns:
        dict with keys: repository, sha, message, author, date,
        files (list of file diffs), diff_summary.
    """
    owner, repo, sha = parse_commit_url(commit_url)

    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    api_url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    resp = requests.get(api_url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    files = []
    total_add = 0
    total_del = 0

    for f in data.get("files", []):
        files.append({
            "filename": f["filename"],
            "status": f["status"],
            "additions": f["additions"],
            "deletions": f["deletions"],
            "patch": f.get("patch", ""),
            "language": _detect_language(f["filename"]),
        })
        total_add += f["additions"]
        total_del += f["deletions"]

    names = [f["filename"] for f in files[:5]]
    summary_files = ", ".join(names)
    if len(files) > 5:
        summary_files += f" ... (+{len(files) - 5} more)"
    diff_summary = f"{len(files)} file(s) changed: {summary_files}. +{total_add} -{total_del}"

    return {
        "repository": f"{owner}/{repo}",
        "sha": sha,
        "message": data["commit"]["message"],
        "author": data["commit"]["author"]["name"],
        "date": data["commit"]["author"]["date"],
        "files": files,
        "diff_summary": diff_summary,
        "commit_url": commit_url,
    }


def _github_headers() -> dict:
    """Build standard GitHub API headers with optional auth."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def search_commits(query: str, repo: str = "") -> dict:
    """Search GitHub for commits matching a query string.

    Args:
        query: Free-text search (e.g. a CVE ID or vulnerability keywords).
        repo: Optional ``owner/repo`` filter.

    Returns:
        Dict with ``total_count`` and a ``commits`` list (max 5) containing
        sha, message, author, date, url, and repository for each match.
    """
    q = query
    if repo:
        q += f" repo:{repo}"

    resp = requests.get(
        f"{GITHUB_API}/search/commits",
        params={"q": q, "per_page": 5, "sort": "committer-date", "order": "desc"},
        headers=_github_headers(),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    commits = []
    for item in data.get("items", [])[:5]:
        commits.append({
            "sha": item["sha"],
            "message": item["commit"]["message"][:500],
            "author": item["commit"]["author"]["name"],
            "date": item["commit"]["author"]["date"],
            "url": item["html_url"],
            "repository": item["repository"]["full_name"],
        })

    return {
        "total_count": data.get("total_count", 0),
        "commits": commits,
    }


def search_advisories(cve_id: str) -> dict:
    """Search the GitHub Advisory Database for a CVE.

    Args:
        cve_id: CVE identifier, e.g. ``CVE-2023-38545``.

    Returns:
        Dict with ``total_found`` and an ``advisories`` list containing
        GHSA ID, severity, references, fix commit URLs, and affected packages.
    """
    resp = requests.get(
        f"{GITHUB_API}/advisories",
        params={"cve_id": cve_id, "per_page": 5},
        headers=_github_headers(),
        timeout=30,
    )
    resp.raise_for_status()
    advisories_data = resp.json()

    advisories = []
    for adv in advisories_data[:5]:
        # Extract commit URLs from references
        fix_commits: list[str] = []
        refs = adv.get("references", []) or []
        for ref_url in refs:
            if isinstance(ref_url, str) and "github.com" in ref_url and "/commit/" in ref_url:
                fix_commits.append(ref_url)

        vulnerabilities = []
        for vuln in adv.get("vulnerabilities", []) or []:
            pkg = vuln.get("package", {}) or {}
            vulnerabilities.append({
                "ecosystem": pkg.get("ecosystem", ""),
                "name": pkg.get("name", ""),
                "vulnerable_range": vuln.get("vulnerable_version_range", ""),
                "patched_version": (
                    (vuln.get("first_patched_version") or {}).get("identifier", "")
                ),
            })

        advisories.append({
            "ghsa_id": adv.get("ghsa_id", ""),
            "cve_id": adv.get("cve_id", ""),
            "summary": adv.get("summary", ""),
            "severity": adv.get("severity", ""),
            "fix_commits": fix_commits,
            "references": refs,
            "vulnerabilities": vulnerabilities,
            "source_repository": adv.get("source_code_location") or "",
        })

    return {
        "total_found": len(advisories),
        "advisories": advisories,
    }


def fetch_related_commits(repo: str, sha: str) -> dict:
    """Fetch ancestor commits near a given SHA for additional context.

    Useful when an initial commit diff is low quality — related commits
    may be part of the same fix series.

    Args:
        repo: Repository in ``owner/repo`` format.
        sha: Commit SHA to look around.

    Returns:
        Dict with ``parent_commits`` list (up to 5 ancestor commits).
    """
    resp = requests.get(
        f"{GITHUB_API}/repos/{repo}/commits",
        params={"sha": sha, "per_page": 6},
        headers=_github_headers(),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    # First entry is the commit itself — skip it
    related = []
    for item in data[1:]:
        related.append({
            "sha": item["sha"],
            "message": item["commit"]["message"][:500],
            "author": item["commit"]["author"]["name"],
            "date": item["commit"]["author"]["date"],
            "url": item["html_url"],
        })

    return {
        "repository": repo,
        "base_sha": sha,
        "parent_commits": related,
    }
