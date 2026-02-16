"""Run PatchScope agents individually for a CVE analysis."""

import sys
import json

# Add project root to path
sys.path.insert(0, ".")

from patchscope.agents.patch_parser import (
    nvd_lookup, search_github_commits, fetch_commit,
    search_github_advisories, fetch_related_commits,
)
from patchscope.agents.reachability_analyzer import (
    analyze_call_graph, detect_entry_points,
    trace_data_flow, detect_auth_gates,
)


def run_patch_parser(cve_id: str) -> dict:
    """Manually run the patch parser tool chain."""
    print(f"\n{'='*60}")
    print(f"  AGENT 1: Patch Parser — {cve_id}")
    print(f"{'='*60}")

    # Step 1: NVD lookup
    print("\n[1] NVD Lookup...")
    nvd = nvd_lookup(cve_id)
    if "error" in nvd:
        print(f"  ERROR: {nvd['error']}")
        return nvd
    print(f"  Description: {nvd['description'][:120]}...")
    print(f"  Severity: {nvd['severity']}")
    print(f"  Patch URLs: {len(nvd['patch_urls'])}")
    print(f"  GitHub URLs: {len(nvd['github_urls'])}")
    print(f"  Advisory URLs: {len(nvd['advisory_urls'])}")

    commit_url = None

    # Step 2: Try patch URLs
    if nvd["patch_urls"]:
        commit_url = nvd["patch_urls"][0]
        print(f"\n[2] Using patch URL: {commit_url}")
    else:
        # Step 2b: Try advisories
        print("\n[2] No patch URLs — searching advisories...")
        advisories = search_github_advisories(cve_id)
        if advisories.get("total_found", 0) > 0:
            for adv in advisories["advisories"]:
                print(f"  Advisory: {adv['ghsa_id']} ({adv['severity']})")
                if adv["fix_commits"]:
                    commit_url = adv["fix_commits"][0]
                    print(f"  Fix commit: {commit_url}")
                    break
                if adv.get("source_repository"):
                    print(f"  Source repo: {adv['source_repository']}")

        if not commit_url:
            # Step 2c: Try GitHub commit search
            print("\n[2c] No fix commits in advisories — searching GitHub commits...")
            search = search_github_commits(cve_id)
            if search["total_count"] > 0:
                commit_url = search["commits"][0]["url"]
                print(f"  Found: {commit_url}")
                print(f"  Message: {search['commits'][0]['message'][:100]}")
            else:
                print("  No commits found via search either.")

    if not commit_url:
        print("\n  FAILED: Could not locate a patch commit.")
        return {"error": "No commit found", "nvd": nvd}

    # Step 3: Fetch commit
    print(f"\n[3] Fetching commit diff...")
    result = fetch_commit(commit_url)
    if "error" in result:
        print(f"  ERROR: {result['error']}")
        return result

    print(f"  Repository: {result['repository']}")
    print(f"  SHA: {result['sha']}")
    print(f"  Message: {result['commit_message'][:100]}")
    print(f"  Files: {len(result['files'])}")
    print(f"  Quality: {result['quality']}")

    all_functions = []
    all_files = []
    for f in result["files"]:
        all_files.append(f["filename"])
        all_functions.extend(f["functions_modified"])
        if f["functions_modified"]:
            print(f"  {f['filename']}: {f['functions_modified']}")

    return {
        "cve_id": cve_id,
        "commit_url": commit_url,
        "repository": result["repository"],
        "files_changed": all_files,
        "functions_modified": list(set(all_functions)),
        "severity": nvd["severity"],
        "description": nvd["description"],
    }


def run_reachability_analyzer(patch_result: dict) -> dict:
    """Manually run the reachability analyzer tool chain."""
    print(f"\n{'='*60}")
    print(f"  AGENT 2: Reachability Analyzer")
    print(f"{'='*60}")

    repo = patch_result["repository"]
    functions = patch_result["functions_modified"]
    files = patch_result["files_changed"]

    if not functions:
        print("  No functions to analyze — skipping.")
        return {"reachable": "unknown", "reason": "no functions identified"}

    primary_func = functions[0]
    # Detect language from file extensions
    language = "C"  # default
    for f in files:
        if f.endswith(".py"):
            language = "Python"
        elif f.endswith(".js"):
            language = "JavaScript"
        elif f.endswith(".go"):
            language = "Go"

    # Step 1: Call graph
    print(f"\n[1] Analyzing call graph for {primary_func} in {repo}...")
    cg = analyze_call_graph(repo, primary_func, language)
    if "error" in cg:
        print(f"  ERROR: {cg['error']}")
    else:
        print(f"  Callers found: {cg['caller_count']}")
        for c in cg["callers"][:5]:
            print(f"    - {c['path']}")

    # Step 2: Entry points
    caller_paths = [c["path"] for c in cg.get("callers", [])[:3]]
    if caller_paths:
        print(f"\n[2] Checking entry points in caller files...")
        ep = detect_entry_points(repo, language, file_paths=caller_paths)
        print(f"  Entry points found: {ep['entry_point_count']}")
        for e in ep["entry_points"]:
            if e["is_entry_point"]:
                print(f"    - {e['path']}: {e['patterns_found']}")
    else:
        print(f"\n[2] Searching repo-wide entry points...")
        ep = detect_entry_points(repo, language)
        print(f"  Entry points found: {ep['entry_point_count']}")

    # Step 3: Trace data flow (if we have callers)
    if cg.get("callers"):
        print(f"\n[3] Tracing data flow...")
        # Try a few known entry point functions
        for source in ["main", "Curl_connect", "curl_easy_perform", "nfnetlink_rcv"]:
            trace = trace_data_flow(repo, source, primary_func)
            if trace["path_found"]:
                print(f"  Path found from {source}: {' → '.join(trace['call_chain'])}")
                break
            else:
                print(f"  No path from {source} (partial: {trace['call_chain']})")
    else:
        trace = {"path_found": False, "call_chain": [], "files_in_path": []}

    # Step 4: Auth gates
    print(f"\n[4] Checking auth gates...")
    auth_results = []
    check_files = (caller_paths or files)[:3]
    for fpath in check_files:
        ag = detect_auth_gates(repo, fpath)
        auth_results.append(ag)
        if ag.get("has_auth_gate"):
            print(f"  {fpath}: {ag['gate_details']}")
        else:
            print(f"  {fpath}: no auth gates")

    print(f"\n{'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'='*60}")

    return {
        "call_graph": cg,
        "entry_points": ep,
        "auth_gates": auth_results,
    }


if __name__ == "__main__":
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2023-32233"
    patch = run_patch_parser(cve_id)
    if "error" not in patch:
        run_reachability_analyzer(patch)
    else:
        print(f"\nPatch analysis failed: {patch}")
