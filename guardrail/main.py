from fastapi import FastAPI
from pydantic import BaseModel
import os
import requests
import ipaddress
from urllib.parse import urlparse, parse_qs

app = FastAPI()

ROOT = "/srv/agent-redteam/sandbox-74a2330712"
ALLOWED = {"example.com", "www.iana.org"}




class Call(BaseModel):
    tool: str
    arguments: dict


def inside(path):
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(ROOT, path))

    root = os.path.normpath(ROOT)

    return full == root or full.startswith(root + os.sep), full


def internal(value):
    try:
        host = urlparse(value).hostname or value
    except:
        host = value

    host = host.lower()

    if host == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )
    except:
        pass

    if host.startswith("169.254."):
        return True

    if host.startswith("127."):
        return True

    return False


@app.post("/check")
def check(call: Call):

    if call.tool == "read_file":

        ok, full = inside(call.arguments["path"])

        if not ok:
            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None,
            }

        try:
            with open(full) as f:
                txt = f.read()

            return {
                "action": "allow",
                "reason": "inside sandbox",
                "result": txt,
            }

        except Exception as e:
            return {
                "action": "allow",
                "reason": str(e),
                "result": "",
            }

    elif call.tool == "fetch_url":

        url = call.arguments["url"]

        p = urlparse(url)

        host = (p.hostname or "").lower()

        if host not in ALLOWED:
            return {
                "action": "block",
                "reason": "host not allowed",
                "result": None,
            }

        if p.username or p.password:
            return {
                "action": "block",
                "reason": "userinfo",
                "result": None,
            }

        for vals in parse_qs(p.query).values():
            for v in vals:
                if internal(v):
                    return {
                        "action": "block",
                        "reason": "redirect target",
                        "result": None,
                    }

        try:
            r = requests.get(url, allow_redirects=False, timeout=5)

            return {
                "action": "allow",
                "reason": "ok",
                "result": r.text,
            }

        except Exception as e:
            return {
                "action": "allow",
                "reason": str(e),
                "result": "",
            }

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None,
    }