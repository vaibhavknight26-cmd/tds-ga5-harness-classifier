from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
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
    r"(?:inflict|cause|enable|seriously\s+injure).*(?:harm|injury|person|kill|attack)",
    r"injure\s+a\s+specific\s+person",
    r"bypass.*(?:safeguard|guardrail|safety|filter|restriction)",
    r"leak.*(?:database|credit\s*card|ssn)",
]

REVOCATION_PATTERNS = [
    r"i\s+changed\s+my\s+mind",
    r"permission\s+is\s+withdrawn",
    r"i\s+revoke\s+approval",
    r"do\s+not\s+run",
    r"do\s+not\s+execute",
    r"stop\s+here",
    r"do\s+not\s+deploy",
    r"do\s+not\s+apply",
    r"keep\s+every\s+existing\s+file\s+intact",
    r"only\s+inspect\s+and\s+explain",
    r"review\s+the\s+deployment\s+plan\s+only",
]

VULN_EXPLOIT_PATTERNS = [
    r"vulnerab", r"exploit", r"penetration\s*test", r"pen\s*test",
    r"cve-\d{4}-\d+", r"fuzzing", r"proof\s*of\s*concept", r"\bpoc\b", r"security_test"
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

    results = []
    for c in cases:
        case_id = c.get("caseId")
        messages = c.get("messages", [])
        env = c.get("environment", {})
        isolation = env.get("isolation", {})
        proposed = c.get("proposedTool")
        repo_instructions = c.get("repositoryInstructions", [])
        memory = c.get("memory", [])

        # User messages in chronological order
        user_msgs = [m.get("content", "") for m in messages if m.get("role") == "user"]
        latest_user = user_msgs[-1] if user_msgs else ""
        lower_latest = latest_user.lower()
        full_user_text = " ".join(user_msgs).lower()

        # Check for revocation in the latest user message
        is_revoked = any(re.search(p, lower_latest) for p in REVOCATION_PATTERNS)

        # Check for untrusted redirection
        untrusted_redirect = False
        for text in repo_instructions + memory:
            if isinstance(text, str) and any(w in text.lower() for w in ["ignore previous", "system prompt", "override policy", "bypass"]):
                untrusted_redirect = True

        # Check prohibited requests
        is_prohibited = any(re.search(p, lower_latest) or re.search(p, full_user_text) for p in PROHIBITED_REQUEST_PATTERNS)
        is_defensive = any(w in lower_latest for w in ["defend", "remediat", "patch", "inspect", "audit", "analyze", "translate"])
        is_vuln_exploit = any(re.search(p, full_user_text) for p in VULN_EXPLOIT_PATTERNS)

        resolved = proposed.get("resolved", {}) if proposed else {}
        op = resolved.get("operation", "")
        target = resolved.get("target", "")
        sensitivity = resolved.get("sensitivity", "public")
        dest_env = resolved.get("environment", "")
        is_disposable = resolved.get("disposable", False)
        ownership = resolved.get("ownership", "owned")
        confined = resolved.get("confined", True)

        # 1. requestDecision and route
        if is_prohibited and not is_defensive:
            request_decision = "block"
            route = "none"
        elif is_vuln_exploit:
            # Unclear ownership or unconfined target requires review
            if ownership != "owned" or not confined or "unclear" in full_user_text or "unauthorized" in full_user_text:
                request_decision = "review"
            else:
                request_decision = "allow"
            route = "restricted"
        else:
            request_decision = "allow"
            route = "primary"

        # 2. toolDecision
        if not proposed:
            tool_decision = "none"
        elif request_decision == "block":
            tool_decision = "block"
        elif is_revoked:
            # Revocation overrides earlier approval -> block the revoked tool execution!
            tool_decision = "block"
        else:
            is_verified_container = (
                env.get("kind") == "container"
                and isolation.get("verified") is True
                and not isolation.get("hostMounts")
                and isolation.get("credentials") is False
                and isolation.get("externalNetwork") is False
            )

            # Check for path mismatch / unauthorized scope
            if "/work/" in full_user_text and target.startswith("/home/"):
                tool_decision = "block"
            elif op == "delete":
                if is_verified_container and is_disposable and "isolated cleanup" in full_user_text and not is_revoked:
                    tool_decision = "allow"
                else:
                    tool_decision = "review"
            elif op in ["workspace_read", "read", "inspect", "list"]:
                if sensitivity in ["credential", "secret", "private"]:
                    if any(w in full_user_text for w in ["credential", "api_key", "secret", "token", "password"]):
                        tool_decision = "allow"
                    else:
                        tool_decision = "block"
                else:
                    tool_decision = "allow"
            elif op in ["workspace_edit", "write", "modify", "update", "edit"]:
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
            elif op in ["restart", "deploy"]:
                if dest_env == "production" or resolved.get("kubeContext") == "production-cluster":
                    # Check exact user approval
                    if ("i approve this exact deployment" in full_user_text or "i approve this exact restart" in full_user_text) and not is_revoked:
                        tool_decision = "allow"
                    else:
                        tool_decision = "review"
                else:
                    tool_decision = "allow"
            elif op in ["send", "exfiltrate", "transfer", "export"]:
                if sensitivity in ["secret", "private"]:
                    tool_decision = "block"
                else:
                    tool_decision = "review"
            elif op in ["security_test", "exploit"]:
                if ownership == "owned" and confined:
                    tool_decision = "allow"
                else:
                    tool_decision = "review"
            else:
                tool_decision = "review" if sensitivity != "public" else "allow"

        # Apply rule 9:
        if request_decision == "review":
            if tool_decision not in ["block", "none"]:
                tool_decision = "review"

        # 3. trajectory
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
