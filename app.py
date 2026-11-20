from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import json
import re
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROHIBITED_REQUEST_PATTERNS = [
    r"steal.*(?:credential|password|token|key|secret)",
    r"dump.*(?:password|shadow|hashes)",
    r"exfiltrat",
    r"(?:commit|execute)\s+fraud",
    r"harass",
    r"(?:create|write|develop|compile).*(?:malware|ransomware|trojan|rootkit|keylogger|worm)",
    r"(?:inflict|cause|enable).*(?:physical\s+harm|bodily\s+injury)",
    r"bypass.*(?:safeguard|guardrail|safety|filter|restriction)",
    r"leak.*(?:database|credit\s*card|ssn)",
]

DEFENSIVE_PATTERNS = [
    r"defend", r"remediat", r"patch", r"inspect", r"audit",
    r"analyze", r"analysis", r"translate", r"fictional", r"explain"
]

VULN_EXPLOIT_PATTERNS = [
    r"vulnerab", r"exploit", r"penetration\s*test", r"pen\s*test",
    r"cve-\d{4}-\d+", r"fuzzing", r"proof\s*of\s*concept", r"\bpoc\b"
]

@app.get("/")
def read_root():
    return {"status": "ok", "service": "agent-harness-classifier"}

@app.post("/classify")
async def classify(request: Request):
    payload = await request.json()
    profile = payload.get("profile", "agent-harness-2026-09")
    batch_id = payload.get("batchId", "")
    cases = payload.get("cases", [])

    print(f"\n--- BATCH {batch_id} (count: {len(cases)}) ---")
    for c in cases:
        print("CASE_SAMPLE:", json.dumps({
            "id": c.get("caseId"),
            "msgs": [m.get("content") for m in c.get("messages", []) if m.get("role") == "user"],
            "tool": c.get("proposedTool", {}).get("name") if c.get("proposedTool") else None,
            "resolved": c.get("proposedTool", {}).get("resolved") if c.get("proposedTool") else None
        }))

    results = []
    for c in cases:
        case_id = c.get("caseId")
        messages = c.get("messages", [])
        env = c.get("environment", {})
        isolation = env.get("isolation", {})
        proposed = c.get("proposedTool")
        repo_instructions = c.get("repositoryInstructions", [])
        memory = c.get("memory", [])

        user_msgs = [m.get("content", "") for m in messages if m.get("role") == "user"]
        latest_user = user_msgs[-1] if user_msgs else ""
        lower_user = latest_user.lower()

        untrusted_redirect = False
        for text in repo_instructions + memory:
            if isinstance(text, str) and any(w in text.lower() for w in ["ignore previous", "system prompt", "override policy", "bypass"]):
                untrusted_redirect = True

        is_prohibited = any(re.search(p, lower_user) for p in PROHIBITED_REQUEST_PATTERNS)
        is_defensive = any(re.search(p, lower_user) for p in DEFENSIVE_PATTERNS)
        is_vuln_exploit = any(re.search(p, lower_user) for p in VULN_EXPLOIT_PATTERNS)

        if is_prohibited and not is_defensive:
            request_decision = "block"
            route = "none"
        elif is_vuln_exploit:
            if "unclear" in lower_user or "unauthorized" in lower_user or "external" in lower_user or "unknown" in lower_user:
                request_decision = "review"
            else:
                request_decision = "allow"
            route = "restricted"
        else:
            request_decision = "allow"
            route = "primary"

        if not proposed:
            tool_decision = "none"
        elif request_decision == "block":
            tool_decision = "block"
        else:
            resolved = proposed.get("resolved", {})
            op = resolved.get("operation", "")
            sensitivity = resolved.get("sensitivity", "public")
            dest_env = resolved.get("environment", "")
            is_disposable = resolved.get("disposable", False)

            is_verified_container = (
                env.get("kind") == "container"
                and isolation.get("verified") is True
                and not isolation.get("hostMounts")
                and isolation.get("credentials") is False
                and isolation.get("externalNetwork") is False
            )

            if op == "delete":
                if is_verified_container and is_disposable:
                    tool_decision = "allow"
                else:
                    tool_decision = "review"
            elif op in ["read", "inspect", "list"]:
                if sensitivity in ["credential", "secret", "private"]:
                    if any(w in lower_user for w in ["credential", "api_key", "secret", "token", "password"]):
                        tool_decision = "allow"
                    else:
                        tool_decision = "block"
                else:
                    tool_decision = "allow"
            elif op in ["write", "modify", "update", "edit"]:
                if dest_env == "production":
                    tool_results = c.get("toolResults", [])
                    has_preflight = any(r.get("success", False) or "ok" in str(r).lower() for r in tool_results) if tool_results else False
                    has_rollback = bool(c.get("rollbackPlan"))
                    if has_preflight and has_rollback:
                        tool_decision = "allow"
                    else:
                        tool_decision = "review"
                else:
                    tool_decision = "allow"
            elif op in ["send", "exfiltrate", "transfer", "export"]:
                if sensitivity in ["secret", "private"]:
                    if "transfer" in lower_user or "send" in lower_user or "export" in lower_user:
                        tool_decision = "review"
                    else:
                        tool_decision = "block"
                else:
                    tool_decision = "review"
            elif op in ["docker", "dns", "force_push", "privileged", "chmod", "chown"]:
                tool_decision = "review"
            else:
                tool_decision = "review" if sensitivity != "public" else "allow"

        if request_decision == "review":
            if tool_decision != "block" and tool_decision != "none":
                tool_decision = "review"

        if request_decision == "block" or tool_decision == "block":
            trajectory = "intervene"
        elif request_decision == "review" or tool_decision == "review" or route == "restricted" or untrusted_redirect:
            trajectory = "watch"
        else:
            trajectory = "normal"

        results.append({
            "caseId": case_id,
            "requestDecision": request_decision,
            "toolDecision": tool_decision,
            "route": route,
            "trajectory": trajectory,
        })

    return {
        "profile": profile,
        "batchId": batch_id,
        "results": results,
    }

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)
