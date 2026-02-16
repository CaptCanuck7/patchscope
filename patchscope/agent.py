"""ADK entry point — exposes root_agent for `adk run` / `adk web`."""

from google.adk.agents import SequentialAgent

from patchscope.agents.patch_parser import patch_parser_agent
from patchscope.agents.reachability_analyzer import reachability_analyzer_agent

root_agent = SequentialAgent(
    name="patchscope_pipeline",
    description=(
        "Multi-agent CVE analysis pipeline: parses security patches, then "
        "analyzes whether the vulnerable code is reachable from untrusted input."
    ),
    sub_agents=[patch_parser_agent, reachability_analyzer_agent],
)
