"""LangGraph single-node graph template.

Returns a predefined response. Replace logic and configuration as needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from langgraph.graph import StateGraph
from langgraph.runtime import Runtime
from typing_extensions import TypedDict
from langchain_openai import ChatOpenAI

from orchestrator_agent.tools import delegate_task


class Context(TypedDict, total=False):
    """Context parameters for the agent.

    Set these when creating assistants OR when invoking the graph.
    See: https://langchain-ai.github.io/langgraph/cloud/how-tos/configuration_cloud/
    """

    my_configurable_param: str


@dataclass
class State:
    """Input state for the agent.

    Defines the initial structure of incoming data.
    See: https://langchain-ai.github.io/langgraph/concepts/low_level/#state
    """

    changeme: str = "example"

# Initialize vLLM-backed LLM once at import time
_llm = ChatOpenAI(
    model="Qwen/Qwen2.5-Coder-7B-Instruct-AWQ",   # must match /v1/models
    base_url="http://localhost:8000/v1",
    api_key="local-token",
    temperature=0,
)

async def call_model(state: State, runtime: Runtime[Context]) -> Dict[str, Any]:
    """Process input and return output from vLLM."""
    cfg = (runtime.context or {}).get("my_configurable_param", "")
    prompt = (
        "You are a helpful coding assistant.\n"
        f"Config: {cfg}\n"
        f"Input: {state.changeme}\n"
        "Reply with a short, direct answer."
    )

    # ainvoke returns an AIMessage
    msg = await _llm.ainvoke(prompt)

    return {"changeme": msg.content}

graph = (
    StateGraph(State, context_schema=Context)
    .add_node(call_model)
    .add_edge("__start__", "call_model")
    .compile(name="New Graph")
)
