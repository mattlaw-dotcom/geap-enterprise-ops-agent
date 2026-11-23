"""GEAP Enterprise Operations Multi-Agent ADK package.

Exposes ``agent`` (containing ``root_agent`` and ``app``) so ``adk run``,
``adk web``, ``adk eval``, and ``adk deploy agent_engine`` discover the
application automatically.
"""

from agent_app import agent
from agent_app.agent import app, build_agent_app, build_runner, root_agent

__all__ = ["agent", "app", "build_agent_app", "build_runner", "root_agent"]
