"""GitHub Code Search and file content API client for reachability analysis."""

import os
import re
import time

import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"

# Code search rate limit: 10 req/min (authenticated)
_CODE_SEARCH_INTERVAL = 6.5  # seconds between code search requests
_last_code_search_time = 0.0


def _github_headers() -> dict:
    """Build standard GitHub API headers with optional auth."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _rate_limit_code_search():
    """Enforce code search rate limit (10 req/min authenticated)."""
    global _last_code_search_time
    now = time.time()
    elapsed = now - _last_code_search_time
    if elapsed < _CODE_SEARCH_INTERVAL:
        time.sleep(_CODE_SEARCH_INTERVAL - elapsed)
    _last_code_search_time = time.time()


def search_code(query: str, repo: str) -> list[dict]:
    """Search for code in a GitHub repository using the code search API.

    Args:
        query: Search query (e.g. a function name or pattern).
        repo: Repository in owner/repo format.

    Returns:
        List of dicts with path, repository, url, and text_matches.
    """
    _rate_limit_code_search()

    q = f"{query} repo:{repo}"
    headers = _github_headers()
    headers["Accept"] = "application/vnd.github.text-match+json"

    resp = requests.get(
        f"{GITHUB_API}/search/code",
        params={"q": q, "per_page": 10},
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    results = []
    for item in data.get("items", [])[:10]:
        text_matches = []
        for tm in item.get("text_matches", []):
            text_matches.append({
                "fragment": tm.get("fragment", ""),
            })

        results.append({
            "path": item["path"],
            "repository": item["repository"]["full_name"],
            "url": item["html_url"],
            "text_matches": text_matches,
        })

    return results


def fetch_file_content(repo: str, path: str, ref: str = "HEAD") -> str:
    """Fetch raw file content from a GitHub repository.

    Args:
        repo: Repository in owner/repo format.
        path: File path within the repository.
        ref: Git ref (branch, tag, or SHA). Defaults to HEAD.

    Returns:
        File content as a string.
    """
    headers = _github_headers()
    headers["Accept"] = "application/vnd.github.raw+json"

    resp = requests.get(
        f"{GITHUB_API}/repos/{repo}/contents/{path}",
        params={"ref": ref},
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.text


def search_function_callers(func_name: str, repo: str) -> list[dict]:
    """Find files that call a given function in a repository.

    Uses GitHub code search to locate invocations of func_name.

    Args:
        func_name: Name of the function to search for callers of.
        repo: Repository in owner/repo format.

    Returns:
        List of dicts with path, text_matches, and url.
    """
    # Search for function name being called (with opening paren)
    return search_code(f"{func_name}(", repo)


# Language-specific entry point patterns
_ENTRY_POINT_PATTERNS = {
    "C": [
        "int main(",
        "socket(",
        "accept(",
        "recv(",
        "read(",
        "ioctl(",
        "syscall",
        "SYSCALL_DEFINE",
        "nfnetlink_rcv",
        "nla_parse",
    ],
    "C++": [
        "int main(",
        "socket(",
        "accept(",
        "recv(",
        "read(",
        "HandleRequest",
        "OnMessage",
    ],
    "Python": [
        "@app.route",
        "@router.",
        "def view(",
        "class.*View",
        "urlpatterns",
        "if __name__",
        "def main(",
        "click.command",
        "argparse",
    ],
    "JavaScript": [
        "app.get(",
        "app.post(",
        "app.put(",
        "app.delete(",
        "router.get(",
        "router.post(",
        "express()",
        "addEventListener",
        "module.exports",
    ],
    "Go": [
        "func main(",
        "http.HandleFunc",
        "http.Handle",
        "ServeHTTP(",
        "ListenAndServe",
    ],
    "Java": [
        "@RequestMapping",
        "@GetMapping",
        "@PostMapping",
        "public static void main(",
        "doGet(",
        "doPost(",
        "HttpServlet",
    ],
    "Rust": [
        "fn main(",
        "async fn",
        "#[get(",
        "#[post(",
        "TcpListener",
    ],
}


def search_entry_points(repo: str, language: str) -> list[dict]:
    """Search for common entry point patterns in a repository by language.

    Args:
        repo: Repository in owner/repo format.
        language: Programming language (e.g. "C", "Python", "JavaScript").

    Returns:
        List of dicts with path, pattern_matched, and text_matches.
    """
    patterns = _ENTRY_POINT_PATTERNS.get(language, [])
    if not patterns:
        # Fallback: search for generic entry points
        patterns = ["main(", "handler(", "serve("]

    results = []
    seen_paths = set()

    # Search for up to 3 patterns to avoid rate limits
    for pattern in patterns[:3]:
        try:
            matches = search_code(pattern, repo)
            for match in matches:
                if match["path"] not in seen_paths:
                    seen_paths.add(match["path"])
                    results.append({
                        "path": match["path"],
                        "pattern_matched": pattern,
                        "text_matches": match["text_matches"],
                        "url": match["url"],
                    })
        except requests.RequestException:
            continue

    return results
