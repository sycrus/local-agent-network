import requests
from langchain_core.tools import tool

A2A_AGENT_URL = "http://127.0.0.1:9999"  # your A2A agent base

@tool
def delegate_task(task: str) -> str:
    """
    Delegate a coding task to the A2A agent network and return a concise result.
    PoC: calls a single A2A agent.
    """
    # NOTE: The exact A2A endpoint/payload depends on your A2A SDK/server.
    # Keep this as a placeholder until you align with your A2A server's request shape.
    resp = requests.post(
        f"{A2A_AGENT_URL}/tasks",
        json={"task": task},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    # Return a short, tool-friendly string. (You can return JSON too.)
    return data.get("result", str(data))
