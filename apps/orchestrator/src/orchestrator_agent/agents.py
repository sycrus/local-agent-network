# agents.py

from dataclasses import dataclass, field
from typing import Any, Dict, List, TypedDict
from typing_extensions import Protocol

from langgraph.graph import StateGraph
from langgraph.runtime import Runtime
from langchain_openai import ChatOpenAI

class Context(TypedDict, total=False):
    """Context parameters for the agent."""

    my_configurable_param: str

@dataclass
class State:
    """Input state for the agent."""

    changeme: str = "example"
    trace: List[str] = field(default_factory=list)

async def planner_agent(state: State, runtime: Runtime[Context]) -> Dict[str, Any]:
    print("🧠 planner_agent invoked")
    # Example: prepend guidance or transform the task
    planned = f"[PLAN] {state.changeme}"
    return {
        "changeme": planned,
        "trace": state.trace + ["planner_agent"],
    }

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

    return {
        "changeme": msg.content,
        "trace": state.trace + ["call_model"],
    }