from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from langgraph.graph import StateGraph
from langgraph.runtime import Runtime
from typing_extensions import TypedDict

from orchestrator_agent.tools import delegate_task


class Context(TypedDict, total=False):
    pass


@dataclass
class State:
    task: str = ""
    result: str = ""


async def run_delegate(state: State, runtime: Runtime[Context]) -> Dict[str, Any]:
    out = await delegate_task.ainvoke({"task": state.task})
    return {"result": out}


graph = (
    StateGraph(State, context_schema=Context)
    .add_node("delegate", run_delegate)
    .add_edge("__start__", "delegate")
    .compile(name="delegate_task")
)
