from fastapi import FastAPI,Request
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import shlex
import re

app = FastAPI()

class RequestBody(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str

@app.get("/")
def home():
    return {"message": "GA5 Q2 API is running"}

@app.post("/charge")
def charge(req: RequestBody):
    delta = req.new_price - req.old_price

    if req.spec == "v1":
        ans = delta * (req.days_remaining / 30)
    elif req.spec == "v2":
        ans = delta * (req.days_remaining / req.days_in_actual_month)
    else:
        return {"error": "Invalid spec"}

    return {"charge": round(ans, 2)}

class ToolRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


@app.post("/check")
def check(body: ToolRequest):

    tool = body.tool

    if tool == "bash":

        cmd = (body.command or "").replace("$HOME", "/home/agent")
        cmd = cmd.replace("~", "/home/agent")

        if "/home/agent/.npmrc" in cmd:
            return {
                "decision": "block",
                "reason": "Reading protected secret"
            }

        return {
            "decision": "allow",
            "reason": "Command allowed"
        }

    elif tool == "write_file":

        p = os.path.normpath(body.path or "")

        if p.startswith("/srv/reports"):
            return {
                "decision": "allow",
                "reason": "Inside reports directory"
            }

        return {
            "decision": "block",
            "reason": "Write outside allowed directory"
        }

    elif tool == "http_request":

        host = urlparse(body.url or "").hostname

        allowed = {
            "registry.npmjs.org",
            "api.github.com"
        }

        if host in allowed:
            return {
                "decision": "allow",
                "reason": "Allowed host"
            }

        return {
            "decision": "block",
            "reason": "Host not allowed"
        }

    return {
        "decision": "allow",
        "reason": "Unknown tool"
    }