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
