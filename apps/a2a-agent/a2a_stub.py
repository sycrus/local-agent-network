from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class TaskIn(BaseModel):
    task: str

class TaskOut(BaseModel):
    result: str

@app.post("/tasks", response_model=TaskOut)
async def tasks(req: TaskIn) -> TaskOut:
    # PoC: just echo. Replace with real agent logic later.
    return TaskOut(result=f"[A2A stub] received task: {req.task}")
