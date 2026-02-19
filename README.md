# PatchScope

**AI-Powered Exploit Probability Scorer**

PatchScope analyzes CVE security patches to determine how exploitable vulnerabilities actually are. Unlike CVSS scores that rate severity from the outside, PatchScope reads the actual code to assess exploitability from the inside.

---

## The Problem

Security teams are drowning in CVEs. Thousands get published every year, each with a CVSS score that says how *bad* a vulnerability is — but not how *exploitable* it actually is. A "Critical 10.0" buried in unused code is less urgent than a "High 7.5" in your public API.

## The Solution

PatchScope uses a multi-agent AI pipeline to:

1. Fetch and parse vulnerability patches
2. Analyze code reachability from attack surfaces
3. Assess exploitation complexity
4. Detect existing mitigations
5. Generate a final exploit probability score

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PatchScope Pipeline                                │
└─────────────────────────────────────────────────────────────────────────────────┘

    ┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
    │  CVE ID  │────▶│   Agent 1    │────▶│   Agent 2   │────▶│   Agent 3    │
    │  Input   │     │ Patch Parser │     │ Reachability│     │  Complexity  │
    └──────────┘     └──────────────┘     └─────────────┘     └──────────────┘
                            │                    │                    │
                            ▼                    ▼                    ▼
                     ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
                     │ • NVD API   │      │ • Call graph│      │ • Exploit   │
                     │ • GitHub API│      │ • Data flow │      │   conditions│
                     │ • Diff parse│      │ • Entry pts │      │ • PoC search│
                     └─────────────┘      └─────────────┘      └─────────────┘
                                                                      │
    ┌──────────┐     ┌──────────────┐     ┌─────────────┐             │
    │  Final   │◀────│   Agent 5    │◀────│   Agent 4   │◀────────────┘
    │  Score   │     │ Final Scorer │     │ Mitigations │
    └──────────┘     └──────────────┘     └─────────────┘
                            │                    │
                            ▼                    ▼
                     ┌─────────────┐      ┌─────────────┐
                     │ • Aggregate │      │ • ASLR/DEP  │
                     │ • Calibrate │      │ • Sandboxing│
                     │ • Report    │      │ • Auth gates│
                     └─────────────┘      └─────────────┘


                    ┌─────────────────────────────────────┐
                    │         ReAct Agent Pattern         │
                    ├─────────────────────────────────────┤
                    │  Thought ──▶ Action ──▶ Observation │
                    │      │                      │       │
                    │      └──────── Loop ────────┘       │
                    └─────────────────────────────────────┘
```

### Implemented Agents

#### Agent 1: Patch Parser (`patchscope/agents/patch_parser.py`)
Fetches and analyzes CVE security patches from NVD and GitHub.

| Tool | Purpose |
|------|---------|
| `nvd_lookup` | Query NVD for CVE metadata and reference URLs |
| `search_github_commits` | Free-text commit search on GitHub |
| `fetch_commit` | Fetch and parse a GitHub commit diff with quality assessment |
| `search_github_advisories` | Query GitHub Advisory DB for fix commits |
| `fetch_related_commits` | Get ancestor commits for additional context |

**Output:** CVE metadata, files changed, functions modified, bug class classification, severity, confidence score.

#### Agent 2: Reachability Analyzer (`patchscope/agents/reachability_analyzer.py`)
Determines whether vulnerable code is reachable from external/untrusted input.

| Tool | Purpose |
|------|---------|
| `analyze_call_graph` | Find direct callers of the vulnerable function |
| `detect_entry_points` | Find public interfaces (HTTP handlers, syscalls, etc.) |
| `trace_data_flow` | Find call chain between entry point and vulnerable function |
| `detect_auth_gates` | Check files for authentication/authorization barriers |

**Output:** Reachability verdict, entry points, shortest call path, auth gates, attack surface classification.

#### Agent 3: Complexity Assessor (`patchscope/agents/complexity_assessor.py`)
Evaluates how difficult exploitation would be, with dynamic tool selection based on vulnerability type.

| Tool | Purpose |
|------|---------|
| `exploit_db_search` | Search Exploit-DB for known public exploits |
| `poc_search` | Search GitHub repos and Metasploit for PoC code |
| `memory_protection_analyzer` | Assess ASLR/DEP/stack canary bypass requirements |
| `prerequisite_extractor` | Extract exploitation prerequisites from patch context |

**Dynamic routing:** memory_corruption → memory protection analysis first; injection → payload constraint analysis; race_condition → timing analysis.

**Output:** Exploitation complexity rating (low/medium/high/very_high), prerequisites, attacker requirements, memory protection bypass needs, public exploit availability, exploitation reliability, confidence score.

### Agentic Flow

| Feature | Description |
|---------|-------------|
| **ReAct Pattern** | Agents emit Thought → Action → Observation traces, showing their reasoning |
| **Dynamic Tool Selection** | Agents choose which tools to use based on what they discover |
| **Fallback Chains** | If one data source fails, agents autonomously try alternatives |
| **Self-Correction** | Low-confidence results trigger additional analysis |
| **Confidence Scoring** | Every output includes a confidence assessment |

---

## License

MIT

---

## Author

Built by [CaptCanuck7](https://github.com/CaptCanuck7)

---
