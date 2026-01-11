# apps/orchestrator/state.py
from typing import TypedDict, List

class AgentState(TypedDict):
    task: str
    steps: List[str]
