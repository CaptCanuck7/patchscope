"""Utilities for parsing unified diffs and detecting security-relevant patterns."""

import re


def extract_changed_lines(patch: str) -> dict:
    """Extract added and removed lines from a unified diff patch.

    Args:
        patch: Unified diff text (the ``patch`` field from GitHub's commit API).

    Returns:
        dict with ``added`` and ``removed`` lists of stripped line content.
    """
    added = []
    removed = []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())
    return {"added": added, "removed": removed}


# Keywords grouped by security domain
_SECURITY_KEYWORDS = {
    # Memory safety
    "overflow", "buffer", "heap", "stack", "bounds", "boundary",
    "malloc", "calloc", "realloc", "free", "alloc", "memcpy",
    "memmove", "strcpy", "strncpy", "sprintf", "sizeof",
    "use-after-free", "double-free", "null",
    # Input validation
    "validate", "sanitize", "escape", "encode", "decode",
    "length", "limit", "max", "min", "range", "check", "truncat",
    # Auth & access
    "auth", "permission", "privilege", "token", "session", "credential",
    "password", "secret", "role", "access",
    # Injection
    "inject", "sql", "command", "exec", "eval", "shell",
    "deserializ", "unpickle", "yaml.load",
    # Crypto
    "encrypt", "decrypt", "hash", "hmac", "random", "nonce", "iv",
    # Concurrency
    "race", "lock", "mutex", "atomic", "concurrent",
    # Network
    "ssrf", "redirect", "origin", "cors", "header",
    "traversal", "path",
}


def find_security_keywords(patch: str) -> list[str]:
    """Identify security-relevant keywords present in a diff patch.

    Args:
        patch: Unified diff text.

    Returns:
        Sorted list of unique security keywords found (case-insensitive).
    """
    patch_lower = patch.lower()
    return sorted(kw for kw in _SECURITY_KEYWORDS if kw in patch_lower)


# Regex for extracting function names from diff hunk headers.
# Unified diff format: @@ -old,count +new,count @@ <function context>
_HUNK_HEADER_RE = re.compile(r"^@@\s.*?@@\s*(.*)")

# Patterns to extract function names from hunk context lines.
_FUNC_PATTERNS = [
    # C/C++/Java/Go: return_type func_name(
    re.compile(r"(?:[\w*&]+\s+)+\*?(\w+)\s*\("),
    # Python: def func_name(
    re.compile(r"def\s+(\w+)\s*\("),
    # Ruby: def method_name
    re.compile(r"def\s+(\w+)"),
    # Rust: fn func_name(
    re.compile(r"fn\s+(\w+)\s*[<(]"),
    # JavaScript/TypeScript: function name( or name(
    re.compile(r"function\s+(\w+)\s*\("),
]


def extract_function_names(patch: str) -> list[str]:
    """Extract function/method names from diff hunk header context lines.

    Git includes the enclosing function signature in ``@@`` hunk headers for
    languages it recognises (C, Python, etc.).  This function parses those
    headers and returns the detected function names in order, deduplicated.

    Args:
        patch: Unified diff text.

    Returns:
        List of unique function names found, preserving first-occurrence order.
    """
    functions: list[str] = []
    seen: set[str] = set()
    for line in patch.splitlines():
        m = _HUNK_HEADER_RE.match(line)
        if not m:
            continue
        context = m.group(1).strip()
        if not context:
            continue
        # Try each pattern against the context line
        for pat in _FUNC_PATTERNS:
            fm = pat.search(context)
            if fm:
                name = fm.group(1)
                if name not in seen:
                    seen.add(name)
                    functions.append(name)
                break
    return functions


def assess_diff_quality(files: list[dict]) -> dict:
    """Assess the quality of parsed diff data for agent decision-making.

    Returns a quality report the agent uses to decide whether to proceed
    with classification or gather more context (e.g. fetch related commits).

    Args:
        files: List of per-file analysis dicts, each containing at minimum
               ``additions``, ``deletions``, ``patch``, ``security_keywords``,
               and ``functions_modified``.

    Returns:
        Dict with ``quality_score`` (0.0–1.0), ``is_sufficient`` bool,
        ``issues`` list, and counts of what was found.
    """
    total_lines = sum(f.get("additions", 0) + f.get("deletions", 0) for f in files)
    total_keywords = sum(len(f.get("security_keywords", [])) for f in files)
    files_with_patches = sum(1 for f in files if f.get("patch"))
    functions_found = sum(len(f.get("functions_modified", [])) for f in files)

    issues: list[str] = []

    if total_lines == 0:
        issues.append("no_changed_lines")
    elif total_lines < 3:
        issues.append("very_few_changes")
    if total_keywords == 0:
        issues.append("no_security_keywords")
    if functions_found == 0:
        issues.append("no_functions_identified")
    if files_with_patches == 0:
        issues.append("no_patch_content")

    # Weighted score: line changes and patch content matter most
    score = 0.0
    if total_lines >= 3:
        score += 0.3
    elif total_lines > 0:
        score += 0.15
    if files_with_patches > 0:
        score += 0.3
    if total_keywords > 0:
        score += 0.2
    if functions_found > 0:
        score += 0.2

    return {
        "quality_score": round(score, 2),
        "total_changed_lines": total_lines,
        "total_security_keywords": total_keywords,
        "files_with_patches": files_with_patches,
        "functions_found": functions_found,
        "issues": issues,
        "is_sufficient": score >= 0.5,
    }
