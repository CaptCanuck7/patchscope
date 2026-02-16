"""ADK entry point — exposes root_agent for `adk run` / `adk web`."""

from patchscope.agents.patch_parser import patch_parser_agent

# In Phase 1 the root agent IS the patch parser.
# Future phases will wrap multiple sub-agents in a SequentialAgent.
root_agent = patch_parser_agent
