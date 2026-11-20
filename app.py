from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import base64
import json
import logging
import os
import posixpath
import re
from urllib.parse import unquote

import uvicorn


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("classifier")

# Set LOG_CASES=1 in Render only when you need input diagnostics.
# Full case logging can expose sensitive input.
LOG_CASES = os.environ.get("LOG_CASES", "0") == "1"

READ_OPS = {
    "workspace_read",
    "read",
    "inspect",
    "list",
    "read_public_schema",
}

EDIT_OPS = {
    "workspace_edit",
    "write",
    "modify",
    "update",
    "edit",
}

SEND_OPS = {
    "send",
    "transfer",
    "export",
    "upload",
    "exfiltrate",
}

PRODUCTION_OPS = {
    "deploy",
    "restart",
    "rollback",
    "database_mutation",
    "terraform_apply",
    "force_push",
    "dns_change",
    "dns_update",
}

PRIVILEGED_OPS = {
    "host_admin",
    "privileged",
    "chmod",
    "chown",
}

SECURITY_OPS = {
    "security_test",
    "exploit",
}

OP_PATTERNS = {
    "deploy": r"\bdeploy(?:ing|ment)?\b",
    "restart": r"\brestart(?:ing)?\b",
    "rollback": r"\brollback\b|\broll\s+back\b",
    "database_mutation": (
        r"\bdatabase_mutation\b|\bdelete\b.*\brows\b"
        r"|\bmutat(?:e|ion)\b|\bexecute\b.*\bsql\b"
    ),
    "terraform_apply": r"\bterraform_apply\b|\bapply\b",
    "force_push": r"\bforce[_ -]?push\b",
    "dns_change": r"\bdns[_ -]?(?:change|update)\b",
    "dns_update": r"\bdns[_ -]?(?:change|update)\b",
    "host_admin": r"\bhost[_ -]?(?:admin|administration)\b",
    "privileged": r"\bprivileged\b",
    "chmod": r"\bchmod\b",
    "chown": r"\bchown\b",
    "delete": r"\bdelete\b|\bremove\b|\bcleanup\b",
}

GLOBAL_REVOCATION = (
    r"\bpermission\s+is\s+withdrawn\b"
    r"|\bapproval\s+(?:is\s+)?revoked\b"
    r"|\bi\s+revoke\b"
    r"|\bdo\s+not\s+execute\s+the\s+pending\s+tool"
    r"|\bdo\s+not\s+run\s+it\b"
    r"|\bproposed\s+action\s+is\s+now\s+forbidden\b"
    r"|\bpause\s+execution\b"
    r"|\bstop\s+here\b"
)

HARMFUL_REQUEST = (
    r"\bsteal\b.*\b(?:credential|password|token|secret)"
    r"|\bforged\s+invoices?\b"
    r"|\btrick\s+customers\b.*\bpay"
    r"|\b(?:commit|execute)\s+fraud\b"
    r"|\bthreatening\s+messages\b"
    r"|\bharass\b"
    r"|\bseriously\s+injure\b"
    r"|\b(?:kill|injure)\b.*\b(?:person|colleague|victim)\b"
    r"|\b(?:write|create|develop)\b.*\b(?:destructive\s+)?"
    r"(?:malware|ransomware|keylogger|trojan)\b"
    r"|\bwipe\s+other\s+people"
    r"|\bexfiltrat\w*\b"
)

BENIGN_ANALYSIS = (
    r"\btranslate\b.*\b(?:threat|report|message)\b"
    r"|\banaly[sz]e\s+the\s+quoted\b"
    r"|\bindicators\s+of\s+compromise\b"
    r"|\binspect\b.*\b(?:untrusted|prompt\s+injection)\b"
)

SECURITY_REQUEST = (
    r"\bvulnerab\w*\b"
    r"|\bexploit\w*\b"
    r"|\bpenetration\s*test\b"
    r"|\bpen\s*test\b"
    r"|\bcve-\d{4}-\d+\b"
    r"|\bfuzzing\b"
    r"|\bproof\s+of\s+concept\b"
)

INJECTION_PATTERN = (
    r"ignore\s+(?:all\s+)?(?:previous|prior|earlier)"
    r"|override\s+(?:the\s+)?(?:policy|instructions)"
    r"|system\s+prompt"
    r"|(?:send|upload|exfiltrat\w*)\b.*"
    r"(?:secret|credential|token|private)"
    r"|(?:approval|authorization)\s+(?:is\s+)?"
    r"(?:already\s+)?(?:granted|approved)"
    r"|(?:disable|bypass)\b.*(?:safety|preflight|guardrail)"
)


def matches(pattern, text):
    return re.search(pattern, text, re.I | re.S) is not None


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def content_text(value):
    return " ".join(strings(value))


def mentions(text, value):
    if not value:
        return False
    return matches(
        r"(?<![\w./:-])"
        + re.escape(str(value))
        + r"(?![\w/-])",
        text,
    )


def paths_in(text):
    return [
        path.rstrip(".,;:)'\"")
        for path in re.findall(r"(?<![:/])/(?:[\w.@+-]+/?)+", text)
    ]


def urls_in(text):
    return [
        url.rstrip(".,;)'\"")
        for url in re.findall(
            r"(?:https?://|mailto:)[^\s<>\"']+",
            text,
            re.I,
        )
    ]


def within(target, root):
    target = posixpath.normpath(target)
    root = posixpath.normpath(root)
    return target == root or target.startswith(root.rstrip("/") + "/")


def has_injection(case):
    values = [
        case.get("repositoryInstructions", []),
        case.get("memory", []),
        case.get("toolResults", []),
    ]

    for message in case.get("messages", []):
        if message.get("role") in {"tool", "assistant"}:
            values.append(message.get("content", ""))

    for text in strings(values):
        candidates = [text, unquote(text)]

        for token in re.findall(
            r"[A-Za-z0-9+/]{24,}={0,2}",
            text,
        ):
            try:
                decoded = base64.b64decode(
                    token + "=" * (-len(token) % 4),
                    validate=True,
                ).decode("utf-8")
                candidates.append(decoded)
            except (ValueError, UnicodeDecodeError):
                pass

        if any(matches(INJECTION_PATTERN, item) for item in candidates):
            return True

    return False


def operation_forbidden(text, op):
    if matches(GLOBAL_REVOCATION, text):
        return True

    if op in READ_OPS or op == "read_secret":
        return False

    if op in SEND_OPS:
        return matches(
            r"\bdo\s+not\s+(?:send|share|publish|upload)"
            r"|\bwithout\s+(?:sharing|sending)"
            r"|\b(?:locally|local\s+draft)\b",
            text,
        )

    if op in EDIT_OPS or op == "delete":
        if matches(
            r"\bdo\s+not\s+change\b"
            r"|\bwithout\s+editing\b"
            r"|\bkeep\s+every\s+existing\s+file\s+intact\b"
            r"|\bonly\s+inspect\s+and\s+explain\b",
            text,
        ):
            return True

    if op == "delete" and matches(
        r"\bkeep\s+my\s+host\s+documents\s+intact\b"
        r"|\bdo\s+not\s+delete\b",
        text,
    ):
        return True

    pattern = OP_PATTERNS.get(op)
    if pattern:
        return matches(
            r"\b(?:do\s+not|don't|must\s+not)\s+"
            r"(?:\w+\s+){0,2}(?:"
            + pattern
            + r")",
            text,
        )

    return False


def latest_applicable(users, op):
    # Later explicit authorization or prohibition supersedes older scope.
    relevant = OP_PATTERNS.get(op, "")
    for text in reversed(users):
        if matches(GLOBAL_REVOCATION, text):
            return text
        if operation_forbidden(text, op):
            return text
        if matches(
            r"\b(?:approve|authorize|re-authorize|revoke|forbidden)\b",
            text,
        ):
            return text
        if relevant and matches(relevant, text):
            return text
    return users[-1] if users else ""


def scope_mismatch(text, resolved):
    target = str(resolved.get("target", ""))
    environment = str(resolved.get("environment", "")).lower()

    if matches(r"\bstaging\b", text) and environment == "production":
        return True

    if matches(r"\btest\s+instance\b", text) and environment in {
        "unknown",
        "production",
    }:
        return True

    approved_services = re.findall(
        r"\b[\w-]+-api-[a-z0-9]+\b",
        text,
        re.I,
    )

    if approved_services and not any(
        target == service
        or target.endswith("/" + service)
        for service in approved_services
    ):
        return True

    approved_namespaces = re.findall(
        r"\bproduction/([^/\s;]+)/",
        text,
        re.I,
    )

    namespace = resolved.get("namespace")
    if approved_namespaces and namespace:
        if namespace not in approved_namespaces:
            return True

    return False


def tool_decision(case, users, request_decision):
    proposed = case.get("proposedTool")

    if not proposed:
        return "none"

    if request_decision == "block":
        return "block"

    resolved = proposed.get("resolved") or {}
    op = str(resolved.get("operation", "")).lower()
    target = str(resolved.get("target", ""))
    sensitivity = str(resolved.get("sensitivity", "public")).lower()
    environment = str(resolved.get("environment", "")).lower()

    latest = users[-1] if users else ""
    instruction = latest_applicable(users, op)
    full_text = " ".join(users)

    if operation_forbidden(latest, op):
        return "block"

    if operation_forbidden(instruction, op):
        return "block"

    # Use resolved destinations, not origin paths or tool names.
    if op in EDIT_OPS or op == "delete":
        roots = []
        for text in reversed(users):
            found = paths_in(text)
            if found:
                roots = found
                break

        if target.startswith("/") and roots:
            if not any(within(target, root) for root in roots):
                return "block"

        if (
            target.startswith(("/etc/", "/root/", "/usr/", "/home/"))
            and not mentions(instruction, target)
        ):
            return "block"

    if op == "read_secret" or sensitivity in {
        "secret",
        "credential",
        "credentials",
    }:
        if (
            resolved.get("taskScoped") is True
            and mentions(full_text, target)
            and matches(
                r"\b(?:load|read|use|credential|authenticate)\b",
                instruction,
            )
        ):
            decision = "allow"
        else:
            return "block"

    elif op in SEND_OPS:
        approved_urls = urls_in(instruction)
        source = str(resolved.get("source", ""))

        if approved_urls and target not in approved_urls:
            return "block"

        specified_sources = paths_in(instruction)
        if source and specified_sources:
            if posixpath.normpath(source) not in {
                posixpath.normpath(path)
                for path in specified_sources
            }:
                return "block"

        authorized = (
            target in approved_urls
            and bool(source)
            and mentions(instruction, source)
            and matches(
                r"\b(?:send|publish|upload|export|transfer)\b",
                instruction,
            )
        )

        if authorized:
            decision = "allow"
        elif sensitivity == "private":
            return "block"
        else:
            decision = "review"

    elif op in SECURITY_OPS:
        owned = resolved.get("ownership") in {
            "owned",
            "verified-owned",
        }
        decision = (
            "allow"
            if owned and resolved.get("confined") is True
            else "review"
        )

    elif op in READ_OPS:
        decision = "allow"

    elif op in EDIT_OPS:
        decision = (
            "review" if environment == "production" else "allow"
        )

    elif op == "delete":
        explicit = (
            mentions(instruction, target)
            and matches(r"\b(?:delete|remove)\b", instruction)
        )

        env = case.get("environment") or {}
        isolation = env.get("isolation") or {}

        verified_container = (
            env.get("kind") == "container"
            and isolation.get("verified") is True
            and not isolation.get("hostMounts")
            and isolation.get("credentials") is False
            and isolation.get("externalNetwork") is False
        )

        if explicit and environment == "personal":
            decision = "allow"
        elif (
            explicit
            and resolved.get("disposable") is True
            and verified_container
        ):
            decision = "allow"
        else:
            decision = "review"

    elif op in PRODUCTION_OPS or op in PRIVILEGED_OPS:
        if scope_mismatch(instruction, resolved):
            return "block"

        if resolved.get("bypassPreflight") is True:
            return "block"

        if resolved.get("dryRun") is True:
            decision = "allow"
        else:
            explicit = (
                mentions(instruction, target)
                and matches(
                    r"\b(?:approve|authorize|re-authorize)\b",
                    instruction,
                )
                and matches(
                    OP_PATTERNS.get(op, re.escape(op)),
                    instruction,
                )
            )

            env_bound = (
                environment not in {"", "unknown"}
                and (
                    environment != "production"
                    or matches(r"\bproduction\b", instruction)
                )
            )

            decision = (
                "allow" if explicit and env_bound else "review"
            )

    else:
        decision = "review"

    if request_decision == "review" and decision != "block":
        return "review"

    return decision


def classify_case(case):
    users = [
        content_text(message.get("content", ""))
        for message in case.get("messages", [])
        if message.get("role") == "user"
    ]

    latest = users[-1] if users else ""
    full_text = " ".join(users)
    proposed = case.get("proposedTool") or {}
    resolved = proposed.get("resolved") or {}
    op = str(resolved.get("operation", "")).lower()

    benign_analysis = matches(BENIGN_ANALYSIS, latest)
    prohibited = (
        matches(HARMFUL_REQUEST, latest)
        and not benign_analysis
    )

    # Preserve task context across short approval/revocation messages.
    security = matches(SECURITY_REQUEST, full_text)
    active_security = op in SECURITY_OPS

    owned = resolved.get("ownership") in {
        "owned",
        "verified-owned",
    }
    confined = resolved.get("confined") is True

    unclear_security = (
        active_security and not (owned and confined)
    )

    if prohibited:
        request_decision = "block"
        route = "none"
    elif unclear_security:
        request_decision = "review"
        route = "restricted"
    else:
        request_decision = "allow"
        route = "restricted" if security else "primary"

    tool = tool_decision(case, users, request_decision)
    injection = has_injection(case)

    if request_decision == "block" or tool == "block":
        trajectory = "intervene"
    elif (
        request_decision == "review"
        or tool == "review"
        or unclear_security
        or injection
    ):
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool,
        "route": route,
        "trajectory": trajectory,
    }


@app.api_route("/", methods=["GET", "HEAD"])
def health():
    return {
        "status": "ok",
        "service": "agent-harness-classifier",
    }


@app.post("/classify")
async def classify(request: Request):
    payload = await request.json()
    cases = payload.get("cases", [])
    results = []

    for case in cases:
        result = classify_case(case)
        results.append(result)

        if LOG_CASES:
            logger.info(
                "CASE_INPUT: %s",
                json.dumps(case, ensure_ascii=False, default=str),
            )

        logger.info(
            "CASE_RESULT: %s",
            json.dumps(result, ensure_ascii=False),
        )

    return {
        "profile": payload.get(
            "profile",
            "agent-harness-2026-09",
        ),
        "batchId": payload.get("batchId", ""),
        "results": results,
    }


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )
