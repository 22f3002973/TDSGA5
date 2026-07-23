from fastapi import FastAPI,Request
from fastapi import Body
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import shlex
import re
import json

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

from pydantic import BaseModel
import re

class SkillRequest(BaseModel):
    skill: str

@app.post("/scan")
def scan(req: SkillRequest):

    text = req.skill
    categories = []

    lower = text.lower()

    ####################################
    # hardcoded_secret
    ####################################

    secret_patterns = [
        r'api[_-]?key\s*[:=]',
        r'secret\s*[:=]',
        r'token\s*[:=]',
        r'password\s*[:=]',
        r'whsec_[A-Za-z0-9]+',
        r'authorization:\s*bearer',
        r'-----begin.*private key-----'
    ]

    for p in secret_patterns:
        if re.search(p, text, re.IGNORECASE):
            categories.append("hardcoded_secret")
            break

    ####################################
    # excessive_permissions
    ####################################

    excessive_patterns = [
        r'entire filesystem',
        r'whole filesystem',
        r'read-write access to the entire filesystem',
        r'unrestricted egress',
        r'any host',
        r'any external domain',
        r'unlimited',
        r'unrestricted'
    ]

    for p in excessive_patterns:
        if re.search(p, lower):
            categories.append("excessive_permissions")
            break

    ####################################
    # prompt injection
    ####################################

    if (
        ("ignore" in lower or "override" in lower or "disregard" in lower)
        and ("stop" in lower or "cancel" in lower or "pause" in lower)
        and "user" in lower
    ):
        categories.append("prompt_injection")

    ####################################
    # unclear provenance
    ####################################

    if (
        "author:" not in lower
        and "version:" not in lower
        and "changelog" not in lower
    ):
        categories.append("unclear_provenance")

    if (
        "clear the changelog" in lower
        or "rewrite its own version" in lower
        or "silently update" in lower
    ):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {"categories": categories}

class Step(BaseModel):
    step_number: int
    tool: str
    args: dict
    tokens_used: int


class BudgetRequest(BaseModel):
    budget_tokens: int
    steps: list[Step]

def normalize(value):
    if isinstance(value, dict):
        return {
            k: normalize(v)
            for k, v in sorted(value.items())
            if k != "request_id"
        }

    elif isinstance(value, list):
        return [normalize(x) for x in value]

    elif isinstance(value, str):
        return " ".join(value.split())

    else:
        return value

@app.post("/budget")
def budget_guard(req: BudgetRequest):

    steps = req.steps
    budget = req.budget_tokens

    ##################################################
    # Budget Rule
    ##################################################

    total = sum(step.tokens_used for step in steps)

    if total >= budget:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({budget})."
        }

    ##################################################
    # 3 identical consecutive calls
    ##################################################

    count = 1

    for i in range(1, len(steps)):

        prev = steps[i-1]
        cur = steps[i]

        same_tool = prev.tool == cur.tool

        same_args = normalize(prev.args) == normalize(cur.args)

        if same_tool and same_args:
            count += 1
            if count >= 3:
                return {
                    "decision": "halt",
                    "reason": "Identical tool call repeated 3 or more times."
                }
        else:
            count = 1

    ##################################################
    # ABABAB cycle
    ##################################################

    if len(steps) >= 6:

        last = steps[-6:]

        def key(s):
            return (
                s.tool,
                json.dumps(normalize(s.args), sort_keys=True)
            )

        A = key(last[0])
        B = key(last[1])

        cycle = True

        for i in range(6):

            expected = A if i % 2 == 0 else B

            if key(last[i]) != expected:
                cycle = False
                break

        if cycle and A != B:
            return {
                "decision": "halt",
                "reason": "Detected repeating two-step cycle."
            }

    ##################################################

    return {
        "decision": "continue",
        "reason": "Under budget and making progress."
    }