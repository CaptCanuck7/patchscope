#!/usr/bin/env python3
"""Standalone validation script — run the Patch Parser tools on a CVE.

Exercises the agentic tool chain manually (without the LLM) to verify
that the NVD→GitHub→diff pipeline produces usable data.

Usage:
    python scripts/test_cve.py                       # default: CVE-2023-32233
    python scripts/test_cve.py CVE-2021-44228         # custom CVE
"""

import json
import sys
from pathlib import Path

# Ensure the package is importable when run from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchscope.agents.patch_parser import nvd_lookup, fetch_commit


def main() -> int:
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2023-32233"

    print(f"{'=' * 60}")
    print(f" PatchScope - Patch Parser validation")
    print(f" CVE: {cve_id}")
    print(f"{'=' * 60}\n")

    # Step 1: NVD Lookup
    print("[1] NVD lookup ...")
    nvd = nvd_lookup(cve_id)

    if "error" in nvd:
        print(f"[FAIL] {nvd['error']}")
        return 1

    print(f"[OK] CVE:        {nvd['cve_id']}")
    print(f"[OK] Severity:   {nvd['severity']}")
    print(f"[OK] Patch URLs: {len(nvd['patch_urls'])}")
    print(f"[OK] GitHub URLs:{len(nvd['github_urls'])}")
    print(f"[OK] Advisories: {len(nvd['advisory_urls'])}")
    print(f"\nDescription:\n  {nvd['description'][:300]}...\n")

    if not nvd["patch_urls"]:
        print("[WARN] No patch commit URLs found.")
        if nvd["github_urls"]:
            print("  GitHub URLs found (not commits):")
            for url in nvd["github_urls"]:
                print(f"    - {url}")
        return 1

    # Step 2: Fetch first commit
    commit_url = nvd["patch_urls"][0]
    print(f"[2] Fetching commit: {commit_url} ...")
    result = fetch_commit(commit_url)

    if "error" in result:
        print(f"[FAIL] {result['error']}")
        return 1

    print(f"[OK] Repository: {result['repository']}")
    print(f"[OK] Author:     {result['author']}  ({result['date']})")
    print(f"[OK] Diff:       {result['diff_summary']}")
    print(f"[OK] Quality:    {result['quality']['quality_score']:.2f} "
          f"({'sufficient' if result['quality']['is_sufficient'] else 'INSUFFICIENT'})")
    if result["quality"]["issues"]:
        print(f"     Issues:     {', '.join(result['quality']['issues'])}")
    print(f"\nCommit message:\n  {result['commit_message'][:300]}\n")

    print(f"Files ({len(result['files'])}):")
    for i, f in enumerate(result["files"], 1):
        kw = ", ".join(f["security_keywords"]) or "(none)"
        fn = ", ".join(f["functions_modified"]) or "(none)"
        print(f"  {i}. {f['filename']}  [{f['language']}]  +{f['additions']} -{f['deletions']}")
        print(f"     Functions: {fn}")
        print(f"     Security keywords: {kw}")
        for line in f["added_lines"][:3]:
            print(f"       + {line}")
        for line in f["removed_lines"][:3]:
            print(f"       - {line}")
        print()

    # Merge NVD + commit data for the saved result
    full_result = {
        "cve_id": nvd["cve_id"],
        "cve_description": nvd["description"],
        "severity": nvd["severity"],
        **result,
        "additional_patch_urls": nvd["patch_urls"][1:],
    }

    out_path = Path(f"{cve_id.replace('-', '_').lower()}.result.json")
    out_path.write_text(json.dumps(full_result, indent=2))
    print(f"Full result saved to: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
