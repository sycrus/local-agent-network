# A2A + MCP + LangGraph PoC

This repository is a **proof of concept** showing how to integrate:

* **Continue (VS Code)** as the IDE interface
* **LangGraph** as an MCP server / agent orchestrator
* **A2A-style agents** as external specialist services
* **Local vLLM models** for inference

The result is a working end-to-end delegation pipeline:

> **Continue → MCP → LangGraph → delegate_task → A2A agent → result**

---

## Architecture Overview

```
Continue (VS Code)
   |
   |  MCP (streamable HTTP)
   v
LangGraph Orchestrator (port 2024)
   |
   |  HTTP tool call
   v
A2A Agent Service (port 9999)
```

* Continue never talks to A2A directly
* Continue only sees **MCP tools**
* LangGraph turns agent logic into MCP-callable tools
* A2A agents can be simple stubs or full multi-agent systems

---

## Project Structure

```
poc-a2a-mcp/
├─ pocenv/                     # Python virtual environment (shared)
│
├─ apps/
│  ├─ a2a-agent/               # A2A agent service (stub)
│  │  └─ a2a_stub.py
│  │
│  └─ orchestrator/            # LangGraph MCP server
│     ├─ src/
│     │  └─ orchestrator_agent/
│     │     ├─ __init__.py
│     │     ├─ graph.py        # vLLM-backed chat graph
│     │     ├─ delegate_graph.py  # MCP tool: delegate_task
│     │     └─ tools.py        # delegate_task → A2A HTTP call
│     │
│     ├─ langgraph.json
│     ├─ pyproject.toml
│     └─ .env
```

---

## Services and Ports

| Service   | Purpose                   | Port |
| --------- | ------------------------- | ---- |
| vLLM      | Local model inference     | 8000 |
| LangGraph | MCP server / orchestrator | 2024 |
| A2A Agent | External agent service    | 9999 |

All three must be running for delegation to work.

---

## Setup

### 1) Activate the virtual environment

From repo root:

```bat
pocenv\Scripts\activate
```

---

### 2) Start the A2A agent

```bat
cd apps\a2a-agent
uvicorn a2a_stub:app --host 127.0.0.1 --port 9999
```

Verify:

```bat
curl http://127.0.0.1:9999/tasks ^
  -H "Content-Type: application/json" ^
  -d "{\"task\":\"ping\"}"
```

---

### 3) Start LangGraph (MCP server)

```bat
cd apps\orchestrator
langgraph dev --no-reload
```

LangGraph exposes MCP at:

```
http://127.0.0.1:2024/mcp
```

---

### 4) Start vLLM

Enter WSL if you are not already in it.
```
wsl
```

Start the vLLM server via shell script:
```bat
cd ~
~/bin/start-vllm.sh
```

### 5) Verify MCP tools

```bat
curl http://127.0.0.1:2024/mcp ^
  -H "Content-Type: application/json" ^
  -H "Accept: application/json" ^
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}"
```

You should see:

* `delegate_task`
* `New Graph` (vLLM chat graph)

---

## Continue Configuration

Add this to `config.yaml`:

```yaml
mcpServers:
  - name: Agent Orchestrator
    type: streamable-http
    url: http://127.0.0.1:2024/mcp
```

Restart VS Code / reload Continue.

---

## Using the PoC

In **Continue → Agent mode**, ask:

> “Use delegate_task with input ‘Create a React controlled input with validation and return a patch.’”

What happens:

1. Continue invokes the MCP tool
2. LangGraph calls `delegate_task`
3. `delegate_task` forwards the task to A2A
4. A2A returns a result
5. Continue displays the output

---

## Notes

* MCP endpoints require **POST** + **JSON-RPC 2.0**
* `/mcp` does not respond to GET
* Editable install (`pip install -e .`) is only needed when:

  * package names change
  * new top-level packages are added
  * dependencies change

---

## Next Steps

Possible extensions:

* Return structured `{plan, diff, tests}` instead of plain text
* Add `apply_patch` MCP tool
* Add tracing (OpenTelemetry)
* Replace A2A stub with real multi-agent workflows
* Gate delegation (small tasks local, large tasks delegated)

---

## Status

✅ End-to-end MCP delegation working
✅ Continue ↔ LangGraph ↔ A2A verified
✅ Local-only, no cloud dependency



