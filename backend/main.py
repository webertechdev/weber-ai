import base64
import asyncio
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
import textwrap
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from groq import Groq
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import text
import httpx

from database import Base, DATABASE_SOURCE, SessionLocal, engine
from models import AnalysisRun, ChatMessage, Connector, Conversation, CorporateRole, Invitation, Membership, Report, RoleScope, User, Workspace

load_dotenv()
Base.metadata.create_all(bind=engine)
for statement in (
    "ALTER TABLE users ADD COLUMN email_domain VARCHAR(255)",
    "ALTER TABLE workspaces ADD COLUMN company_website VARCHAR(255)",
    "ALTER TABLE workspaces ADD COLUMN domain_verification_status VARCHAR(30)",
    "ALTER TABLE connectors ADD COLUMN browser_session_id VARCHAR(160)",
    "ALTER TABLE connectors ADD COLUMN browser_context_id VARCHAR(160)",
    "ALTER TABLE connectors ADD COLUMN browser_connect_url VARCHAR(1000)",
    "ALTER TABLE connectors ADD COLUMN browser_live_view_url VARCHAR(1000)",
    "ALTER TABLE connectors ADD COLUMN session_started_at VARCHAR(255)",
):
    try:
        # Each migration gets its own transaction. On Neon/Postgres a duplicate
        # column error otherwise aborts the transaction and prevents later
        # connector columns from being added.
        safe_statement = statement.replace(" ADD COLUMN ", " ADD COLUMN IF NOT EXISTS ") if engine.dialect.name == "postgresql" else statement
        with engine.begin() as schema_db:
            schema_db.execute(text(safe_statement))
    except Exception as exc:
        print(f"Schema migration skipped: {exc}", flush=True)
app = FastAPI(title="Weber AI Corporate Intelligence API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    print(f"Unhandled Weber AI error on {request.method} {request.url.path}: {exc}", flush=True)
    return JSONResponse(status_code=500, content={"detail": "The Weber AI backend could not complete this request. Check the backend storage configuration and deployment logs.", "error_type": exc.__class__.__name__})

groq_api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=groq_api_key) if groq_api_key else None
BROWSERBASE_API_KEY = os.getenv("BROWSERBASE_API_KEY")
BROWSER_WORKER_URL = os.getenv("BROWSER_WORKER_URL", "").strip().rstrip("/")
BROWSER_WORKER_TOKEN = os.getenv("BROWSER_WORKER_TOKEN", "").strip()
TOKEN_SECRET = os.getenv("AUTH_SECRET", "weber-ai-change-this-secret")
bearer = HTTPBearer(auto_error=False)


def now():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return base64.urlsafe_b64encode(salt + digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(stored.encode())
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 260_000), raw[16:])
    except (ValueError, IndexError):
        return False


def issue_token(user_id: int) -> str:
    payload = f"{user_id}:{int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 14}"
    signature = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{signature}".encode()).decode()


def user_from_token(token: str) -> int:
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        user_id, expires, signature = decoded.split(":", 2)
        payload = f"{user_id}:{expires}"
        expected = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(expires) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError
        return int(user_id)
    except (ValueError, TypeError, UnicodeDecodeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session has expired. Please sign in again.")


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Sign in is required")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_from_token(credentials.credentials)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User account not found")
        return user
    finally:
        db.close()


class SignupRequest(BaseModel):
    first_name: str = Field(min_length=2, max_length=80)
    last_name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    company_name: str = Field(min_length=2, max_length=160)
    company_website: str = Field(min_length=4, max_length=255)
    industry: str = Field(min_length=2, max_length=120)
    company_size: str = Field(min_length=1, max_length=80)
    job_title: str = Field(min_length=2, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=12000)
    messages: list[Message] = Field(default_factory=list)
    conversation_id: int
    role_id: int | None = None
    role: str = "ADMIN"
    scopes: list[str] = Field(default_factory=list)


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    department: str = Field(default="General", max_length=120)
    description: str = Field(default="", max_length=1000)
    scopes: list[str] = Field(default_factory=lambda: ["Workspace overview"])


class InvitationRequest(BaseModel):
    email: EmailStr
    role_id: int


class ConnectorRequest(BaseModel):
    website_url: str = Field(min_length=4, max_length=500)
    name: str | None = Field(default=None, max_length=160)


class AnalysisRequest(BaseModel):
    connector_id: int
    request: str = Field(min_length=3, max_length=5000)
    export_format: str = Field(default="text", pattern="^(text|pdf|image|word|excel|csv|powerpoint)$")
    role_id: int | None = None


class AnalysisEditRequest(BaseModel):
    request: str = Field(min_length=3, max_length=5000)
    export_format: str | None = Field(default=None, pattern="^(text|pdf|image|word|excel|csv|powerpoint)$")


def normalized_website(value: str) -> str:
    website = value.strip()
    if not website.startswith(("http://", "https://")):
        website = "https://" + website
    parsed = urlparse(website)
    if not parsed.netloc or "." not in parsed.netloc:
        raise HTTPException(status_code=422, detail="Enter the company website, for example https://company.com")
    return website.rstrip("/")


def website_domain(value: str) -> str:
    return urlparse(normalized_website(value)).netloc.lower().removeprefix("www.").split(":")[0]


def serialize_connector(connector: Connector):
    return {"id": connector.id, "name": connector.name, "website_url": connector.website_url, "connector_type": connector.connector_type, "status": connector.status, "allowed_scope": connector.allowed_scope, "last_authorized_at": connector.last_authorized_at, "last_analysis_at": connector.last_analysis_at, "browser_session_id": connector.browser_session_id, "browser_context_id": connector.browser_context_id, "browser_connect_url": connector.browser_connect_url, "browser_live_view_url": connector.browser_live_view_url, "session_started_at": connector.session_started_at, "created_at": connector.created_at}


def serialize_analysis(run: AnalysisRun):
    return {"id": run.id, "connector_id": run.connector_id, "request": run.request, "export_format": run.export_format, "status": run.status, "unavailable_note": run.unavailable_note, "result_text": run.result_text, "created_at": run.created_at, "completed_at": run.completed_at}


def browserbase_json(method: str, path: str, payload: dict | None = None):
    """Call the managed provider, or fail over to a self-hosted Playwright worker.

    The self-hosted worker intentionally implements the small Browserbase-compatible
    session contract used by Weber AI. It can run on a persistent VM without browser-
    minute quotas. If both providers are configured, Browserbase remains primary and
    a quota/service failure retries the same request against the worker.
    """
    providers = []
    if BROWSERBASE_API_KEY:
        providers.append(("Browserbase", "https://api.browserbase.com", {"X-BB-API-Key": BROWSERBASE_API_KEY}))
    if BROWSER_WORKER_URL:
        worker_headers = {"Authorization": f"Bearer {BROWSER_WORKER_TOKEN}"} if BROWSER_WORKER_TOKEN else {}
        providers.append(("self-hosted browser worker", BROWSER_WORKER_URL, worker_headers))
    if not providers:
        raise HTTPException(status_code=503, detail="No browser provider is configured. Add BROWSERBASE_API_KEY or BROWSER_WORKER_URL to Vercel and redeploy.")

    failures = []
    for provider_name, base_url, auth_headers in providers:
        try:
            headers = {**auth_headers, "Content-Type": "application/json"}
            with httpx.Client(timeout=25) as http:
                response = http.request(method, f"{base_url}{path}", headers=headers, json=payload)
            if response.status_code >= 400:
                provider_note = response.text.replace("\n", " ")[:500]
                failures.append((provider_name, response.status_code, provider_note))
                # A quota, rate, or transient provider failure should use the configured
                # fallback. Validation and authentication errors must remain visible.
                if response.status_code not in {402, 429, 500, 502, 503, 504}:
                    public_status = response.status_code if response.status_code in {401, 403, 404, 409, 422} else 502
                    raise HTTPException(status_code=public_status, detail=f"{provider_name} could not complete the session request ({response.status_code}). {provider_note}")
                continue
            if response.status_code == 204 or not response.content:
                return {}
            return response.json()
        except HTTPException:
            raise
        except Exception as exc:
            failures.append((provider_name, 503, str(exc)))
            if provider_name == providers[-1][0]:
                break

    summary = "; ".join(f"{name}: {note}" for name, _, note in failures)
    browserbase_quota_or_outage = any(name == "Browserbase" and code in {402, 429, 500, 502, 503, 504} for name, code, _ in failures)
    if browserbase_quota_or_outage and BROWSER_WORKER_URL:
        guidance = "Browserbase is unavailable or its browser quota is exceeded, so Weber tried the self-hosted alternative but could not reach it. Keep the local worker and HTTPS tunnel running, then retry Authorize session."
    elif browserbase_quota_or_outage:
        guidance = "Browserbase is unavailable or its browser quota is exceeded. Configure BROWSER_WORKER_URL and BROWSER_WORKER_TOKEN for the self-hosted Playwright alternative, then retry Authorize session."
    else:
        guidance = "Check the configured browser provider and retry Authorize session."
    raise HTTPException(status_code=503, detail=f"{guidance} Provider details: {summary[:750]}")


def _safe_agent_target(text: str) -> bool:
    blocked = ("delete", "remove", "destroy", "logout", "log out", "password", "change password", "payment", "pay now", "send", "submit", "settings", "admin", "user management")
    return not any(word in (text or "").lower() for word in blocked)


def _scope_allows_agent_target(text: str, role_scopes: list[str]) -> bool:
    if not role_scopes or any(scope.lower() in {"admin", "all company data", "all data"} for scope in role_scopes):
        return True
    target = (text or "").lower()
    scope_text = " ".join(role_scopes).lower()
    aliases = {"sales": "revenue margin sales orders", "revenue": "revenue margin sales orders", "profit": "revenue margin sales orders", "forecast": "forecast forecasting", "inventory": "inventory stock products", "customer": "customers customer", "report": "reports executive reporting"}
    return any(keyword in target and any(scope_word in scope_text for scope_word in aliases[keyword].split()) for keyword in aliases)


async def _page_snapshot(page):
    text = (await page.locator("body").inner_text(timeout=5000)).strip()
    tables = await page.locator("table").evaluate_all("tables => tables.slice(0, 20).map(table => Array.from(table.querySelectorAll('tr')).slice(0, 80).map(row => Array.from(row.querySelectorAll('th,td')).map(cell => cell.innerText.trim())))")
    controls = await page.locator("a,button,[role='button'],input,select").evaluate_all("els => els.slice(0, 80).map((el, i) => { el.setAttribute('data-weber-agent-id', String(i)); return {id:String(i), tag:el.tagName.toLowerCase(), text:(el.innerText || el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.value || '').trim().slice(0,120), href:el.href || ''}; }).filter(x => x.text || x.href)")
    return {"url": page.url, "title": await page.title(), "text": text[:18000], "tables": tables, "controls": controls}


async def _choose_authenticated_page(context, target_url: str, attempts: int = 6):
    target_host = urlparse(target_url).netloc.lower()
    best = None
    for _ in range(attempts):
        candidates = []
        for candidate in context.pages:
            try:
                text = (await candidate.locator("body").inner_text(timeout=4000)).strip()
                table_count = await candidate.locator("table").count()
                host_match = urlparse(candidate.url).netloc.lower() == target_host if urlparse(candidate.url).netloc else False
                lower_text = text.lower()
                signal_score = sum(1500 for signal in ("today's sales", "today’s sales", "today's profit", "today’s profit", "recent sales", "stock value", "sales", "profit") if signal in lower_text)
                candidates.append(((10000 if host_match else 0) + signal_score + len(text) + table_count * 1000, candidate, text, table_count))
            except Exception:
                continue
        if candidates:
            best = max(candidates, key=lambda item: item[0])
            if best[2] or best[3]:
                await best[1].bring_to_front()
                return best[1]
        await asyncio.sleep(1.5)
    if best:
        await best[1].bring_to_front()
        return best[1]
    return context.pages[0] if context.pages else await context.new_page()


async def _run_governed_agent(page, request: str, role_scopes: list[str]):
    """Let the model choose bounded browser actions, never unrestricted clicks."""
    evidence = []
    actions = []
    max_steps = 8
    for step in range(max_steps):
        snapshot = await _page_snapshot(page)
        evidence.append(snapshot)
        if not snapshot["text"] and not snapshot["tables"]:
            action = {"action": "wait", "reason": "The authenticated page is still rendering"}
        elif client is None:
            action = {"action": "scroll", "amount": 850, "reason": "Read the next visible portion"} if step < max_steps - 1 else {"action": "finish", "reason": "Bounded evidence collection complete"}
        else:
            planner_prompt = {
                "request": request,
                "role_scopes": role_scopes,
                "step": step + 1,
                "max_steps": max_steps,
                "page": snapshot,
                "allowed_actions": ["scroll", "click", "wait", "finish"],
                "policy": "Use only same-site visible controls. Never click destructive, account, password, payment, logout, admin, settings, edit, delete, remove, or submit controls. Finish when the visible evidence answers the request. Return JSON only with action, reason, and optional target_id/amount."
            }
            completion = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), temperature=0, max_tokens=240, messages=[
                {"role": "system", "content": "You are Weber's browser-action planner. Choose one safe, reversible action from the supplied visible page. Do not invent element ids. Return strict JSON only."},
                {"role": "user", "content": json.dumps(planner_prompt, ensure_ascii=False)[:22000]}
            ])
            raw = completion.choices[0].message.content or "{}"
            try:
                raw = raw[raw.find("{"):raw.rfind("}") + 1]
                action = json.loads(raw)
            except Exception:
                action = {"action": "finish", "reason": "The action planner returned an invalid command"}
        action_name = str(action.get("action", "finish")).lower()
        reason = str(action.get("reason", ""))[:240]
        if action_name == "finish":
            actions.append({"step": step + 1, "action": "finish", "reason": reason or "Evidence is sufficient"})
            break
        if action_name == "scroll":
            amount = max(300, min(int(action.get("amount", 850)), 1200))
            await page.mouse.wheel(0, amount)
            await page.wait_for_timeout(650)
            actions.append({"step": step + 1, "action": "scroll", "amount": amount, "reason": reason})
            continue
        if action_name == "wait":
            await page.wait_for_timeout(1200)
            actions.append({"step": step + 1, "action": "wait", "reason": reason})
            continue
        if action_name == "click":
            target_id = str(action.get("target_id", ""))
            candidate = next((item for item in snapshot["controls"] if item["id"] == target_id), None)
            if not candidate or not _safe_agent_target(candidate.get("text", "")) or not _safe_agent_target(candidate.get("href", "")) or not _scope_allows_agent_target(candidate.get("text", "") + " " + candidate.get("href", ""), role_scopes):
                actions.append({"step": step + 1, "action": "blocked_click", "target_id": target_id, "reason": "Target was missing or outside Weber's safe action policy"})
                continue
            href = candidate.get("href", "")
            if href and urlparse(href).netloc and urlparse(href).netloc != urlparse(page.url).netloc:
                actions.append({"step": step + 1, "action": "blocked_navigation", "reason": "External navigation is not allowed"})
                continue
            await page.locator(f"[data-weber-agent-id='{target_id}']").click(timeout=5000)
            await page.wait_for_timeout(900)
            actions.append({"step": step + 1, "action": "click", "target": candidate.get("text", "")[:120], "reason": reason})
            continue
        actions.append({"step": step + 1, "action": "blocked_action", "reason": "Unsupported action"})
    return evidence, actions


async def inspect_browser_session(connect_url: str, target_url: str, navigate: bool = False, request: str = "", role_scopes: list[str] | None = None):
    from playwright.async_api import async_playwright
    async with async_playwright() as playwright:
        worker_headers = {"Authorization": f"Bearer {BROWSER_WORKER_TOKEN}"} if BROWSER_WORKER_URL and connect_url.startswith(BROWSER_WORKER_URL) and BROWSER_WORKER_TOKEN else None
        browser = await playwright.chromium.connect_over_cdp(connect_url, headers=worker_headers)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        pages = context.pages or [await context.new_page()]
        page = pages[0]
        if navigate:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
        # Give the authenticated SPA time to render its dashboard after Live View
        # login. Refresh context.pages because the portal may open a new tab after
        # the initial about:blank page was created.
        await page.wait_for_timeout(2500)
        pages = context.pages or pages
        # Live View may leave an about:blank tab first and render the logged-in
        # portal in another tab later. Re-discover the best same-site page.
        page = await _choose_authenticated_page(context, target_url)
        visible_text = (await page.locator("body").inner_text(timeout=5000)).strip()
        tables = await page.locator("table").evaluate_all("tables => tables.slice(0, 30).map(table => Array.from(table.querySelectorAll('tr')).map(row => Array.from(row.querySelectorAll('th,td')).map(cell => cell.innerText.trim())))")
        if not visible_text and not tables and urlparse(target_url).netloc:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(3000)
            page = await _choose_authenticated_page(context, target_url, attempts=3)
            visible_text = (await page.locator("body").inner_text(timeout=5000)).strip()
            tables = await page.locator("table").evaluate_all("tables => tables.slice(0, 30).map(table => Array.from(table.querySelectorAll('tr')).map(row => Array.from(row.querySelectorAll('th,td')).map(cell => cell.innerText.trim())))")
        password_fields = await page.locator('input[type="password"]:visible').count()
        # Agentic evidence pass: move through the visible page in bounded steps and
        # collect DOM text/tables from each viewport. This is safer and more reliable
        # than relying on one screenshot, while remaining inside the user-authorized tab.
        evidence_texts = [visible_text] if visible_text else []
        evidence_tables = list(tables)
        agent_evidence, agent_actions = ([], [])
        if password_fields == 0:
            await page.evaluate("window.scrollTo(0, 0)")
            agent_evidence, agent_actions = await _run_governed_agent(page, request, role_scopes or [])
            for snapshot in agent_evidence:
                if snapshot.get("text"): evidence_texts.append(snapshot["text"])
                for table in snapshot.get("tables", []):
                    if table not in evidence_tables: evidence_tables.append(table)
        # Keep only new lines/rows. Browser body.inner_text often returns the whole
        # document at every scroll position; sending those repeats can exceed the
        # provider context and TPM limits even when the portal itself is small.
        unique_lines = []
        seen_lines = set()
        for text_block in evidence_texts:
            for raw_line in text_block.splitlines():
                line = " ".join(raw_line.split()).strip()
                if line and line not in seen_lines:
                    seen_lines.add(line)
                    unique_lines.append(line)
        compact_tables = []
        seen_rows = set()
        for table in evidence_tables:
            compact_table = []
            for row in table[:80]:
                normalized = tuple(" ".join(str(cell).split()).strip() for cell in row)
                if normalized and normalized not in seen_rows:
                    seen_rows.add(normalized)
                    compact_table.append(list(normalized))
            if compact_table:
                compact_tables.append(compact_table)
        visible_text = "\n".join(unique_lines)[:30000]
        tables = compact_tables[:20]
        screenshot = await page.screenshot(type="png")
        current_url = page.url
        # Playwright disconnects from Browserbase here; keepAlive lets the remote session survive.
        return {"current_url": current_url, "password_fields": password_fields, "visible_text": visible_text, "tables": tables, "screenshot_bytes": len(screenshot), "agent_steps": len(evidence_texts), "agent_actions": agent_actions, "evidence_chars": len(visible_text)}


def process_analysis(run_id: int):
    """Process a queued analysis after the API has returned the initial response."""
    db = SessionLocal()
    try:
        run = db.query(AnalysisRun).filter(AnalysisRun.id == run_id).first()
        if not run:
            return
        connector = db.query(Connector).filter(Connector.id == run.connector_id).first()
        analysis_role = db.query(CorporateRole).filter(CorporateRole.id == run.role_id).first()
        role_scopes = [scope.label for scope in analysis_role.scopes] if analysis_role else []
        if not connector or connector.status != "authorized" or not connector.browser_session_id:
            run.status = "unavailable"
            run.unavailable_note = "The authorized browser session is no longer available. Authorize the connector again and retry this analysis."
            run.completed_at = now()
            db.commit()
            return
        run.status = "processing"
        db.commit()
        evidence = None
        session_error = None
        # The login Live View may still be active. Reuse it first; creating a
        # second session against the same context returns Browserbase 409.
        if connector.browser_connect_url:
            try:
                evidence = asyncio.run(inspect_browser_session(connector.browser_connect_url, connector.website_url, navigate=False, request=run.request, role_scopes=role_scopes))
            except Exception as exc:
                session_error = exc
        if evidence is None and connector.browser_context_id:
            analysis_session = browserbase_json("POST", "/v1/sessions", {"timeout": 900, "browserSettings": {"context": {"id": connector.browser_context_id, "persist": False}}, "region": "us-east-1", "userMetadata": {"analysis_id": str(run.id), "connector_id": str(connector.id)}})
            connect_url = (analysis_session or {}).get("connectUrl") or (analysis_session or {}).get("connect_url") or (analysis_session or {}).get("wsUrl")
            if not connect_url:
                raise RuntimeError("Browserbase did not return a connection URL for the authorized context")
            evidence = asyncio.run(inspect_browser_session(connect_url, connector.website_url, navigate=True, request=run.request, role_scopes=role_scopes))
        if evidence is None:
            debug = browserbase_json("GET", f"/v1/sessions/{connector.browser_session_id}/debug")
            connect_url = connector.browser_connect_url or debug.get("wsUrl")
            if not connect_url:
                raise RuntimeError(f"The authorized Browserbase session is unavailable: {session_error or 'session ended'}")
            evidence = asyncio.run(inspect_browser_session(connect_url, connector.website_url, navigate=False, request=run.request, role_scopes=role_scopes))
        if evidence["password_fields"] > 0:
            run.status = "unavailable"
            run.unavailable_note = "The portal login page is still visible. Weber AI cannot inspect sales data until the authorized session is logged in."
            run.completed_at = now()
            db.commit()
            return
        if not evidence["visible_text"].strip() and not evidence["tables"]:
            run.status = "unavailable"
            run.unavailable_note = "Weber connected to the browser session, but the logged-in portal page returned no visible text or tables. Keep the portal dashboard open in the authorization tab, wait for it to finish loading, then click Check login and retry."
            run.completed_at = now()
            db.commit()
            return
        evidence_text = json.dumps({"page_url": evidence["current_url"], "agent_steps": evidence.get("agent_steps", 1), "agent_actions": evidence.get("agent_actions", []), "tables": evidence["tables"], "visible_text": evidence["visible_text"]}, ensure_ascii=False)[:24000]
        if client is None:
            result = "The AI provider is not configured, so Weber AI could not generate this report."
        else:
            system_prompt = f"You are Weber Intelligence, a warm and concise corporate analyst. Use only the supplied authorized portal evidence. The active role scopes are: {', '.join(role_scopes) or 'none'}. Never reveal or calculate information outside those scopes. Calculate only from supplied values and never invent numbers. Briefly explain what you found; if the requested period or metric is not visible or is outside the active role scope, say so plainly and recommend the next helpful step. Include observed figures, comparison or trend, limitations, and next actions."
            messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": f"Requested analysis: {run.request}\n\nAuthorized portal evidence:\n{evidence_text}"}]
            try:
                completion = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), temperature=0.2, max_tokens=1800, messages=messages)
            except Exception as provider_error:
                # A second compact attempt prevents a large portal from turning a
                # recoverable context/TPM rejection into a failed report.
                error_text = str(provider_error).lower()
                if "context" not in error_text and "413" not in error_text and "too large" not in error_text and "tokens" not in error_text:
                    raise
                compact_evidence = evidence_text[:10000]
                completion = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), temperature=0.2, max_tokens=1200, messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": f"Requested analysis: {run.request}\n\nCompact authorized portal evidence:\n{compact_evidence}"}])
            result = completion.choices[0].message.content or "No report content was returned from the authorized evidence."
        run.result_text = result
        run.status = "completed"
        run.completed_at = now()
        connector.last_analysis_at = now()
        action_summary = json.dumps(evidence.get("agent_actions", []), ensure_ascii=False)[:1800]
        db.add(Report(workspace_id=run.workspace_id, user_id=run.user_id, analysis_id=run.id, title=run.request[:180], export_format=run.export_format, content=result, source_summary=f"Authorized session: {connector.website_url}; visible page: {evidence['current_url']}; governed agent actions: {action_summary}", created_at=now()))
        db.commit()
    except Exception as exc:
        print(f"Analysis {run_id} failed: {exc}", flush=True)
        run = db.query(AnalysisRun).filter(AnalysisRun.id == run_id).first()
        if run:
            run.status = "failed"
            run.unavailable_note = "Weber AI could not complete this report from the authorized session. Please retry or ask an IT administrator to check the portal connection."
            run.completed_at = now()
            db.commit()
    finally:
        db.close()


def serialize_user(user: User):
    return {"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email, "job_title": user.job_title}


def serialize_role(role: CorporateRole):
    return {"id": role.id, "name": role.name, "department": role.department, "description": role.description, "scopes": [scope.label for scope in role.scopes], "members": len(role.memberships), "active": role.active, "updated": role.updated}


def workspace_for_user(db, user: User):
    membership = db.query(Membership).filter(Membership.user_id == user.id, Membership.status == "active").first()
    if not membership:
        raise HTTPException(status_code=403, detail="You are not a member of an active workspace")
    return membership.workspace, membership.role


def bootstrap_payload(db, user: User):
    workspace, membership_role = workspace_for_user(db, user)
    roles = db.query(CorporateRole).filter(CorporateRole.workspace_id == workspace.id).order_by(CorporateRole.id).all()
    conversation = db.query(Conversation).filter(Conversation.user_id == user.id).order_by(Conversation.id.desc()).first()
    if not conversation:
        conversation = Conversation(title="Workspace briefing", user_id=user.id, workspace_id=workspace.id, role_id=membership_role.id, created_at=now())
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
    return {"user": serialize_user(user), "workspace": {"id": workspace.id, "name": workspace.name, "industry": workspace.industry, "company_size": workspace.company_size, "company_website": workspace.company_website, "domain_verification_status": workspace.domain_verification_status}, "active_role": serialize_role(membership_role), "roles": [serialize_role(role) for role in roles], "conversation_id": conversation.id}


@app.get("/")
def root():
    return {"message": "Weber AI Corporate Intelligence API is running"}


@app.get("/health")
@app.get("/api/health")
def health():
    try:
        with engine.connect():
            database_ok = True
    except Exception as exc:
        print(f"Database health check failed: {exc}", flush=True)
        database_ok = False
    browser_provider = "browserbase+fallback" if BROWSERBASE_API_KEY and BROWSER_WORKER_URL else "browserbase" if BROWSERBASE_API_KEY else "self-hosted" if BROWSER_WORKER_URL else "not-configured"
    return {"status": "ok" if database_ok else "degraded", "release": "browser-settings-context-authorization-fallback", "database": database_ok, "database_source": DATABASE_SOURCE, "ai_provider": bool(groq_api_key), "browser_worker": bool(BROWSERBASE_API_KEY or BROWSER_WORKER_URL), "browser_provider": browser_provider, "auth_secret_configured": bool(os.getenv("AUTH_SECRET"))}


@app.post("/api/auth/signup")
def signup(payload: SignupRequest):
    db = SessionLocal()
    try:
        email = payload.email.lower().strip()
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        normalized_site = normalized_website(payload.company_website)
        site_domain = website_domain(normalized_site)
        email_domain = email.split("@", 1)[1].lower()
        user = User(first_name=payload.first_name.strip(), last_name=payload.last_name.strip(), email=email, email_domain=email_domain, password_hash=hash_password(payload.password), job_title=payload.job_title.strip(), created_at=now())
        workspace = Workspace(name=payload.company_name.strip(), industry=payload.industry.strip(), company_size=payload.company_size, company_website=normalized_site, domain_verification_status="verified" if email_domain == site_domain else "pending", created_at=now())
        db.add_all([user, workspace])
        db.flush()
        admin = CorporateRole(workspace_id=workspace.id, name="ADMIN", department="Executive office", description="Full workspace governance and role administration.", updated="Just now")
        admin.scopes = [RoleScope(label=scope) for scope in ["All company data", "Role management", "Executive reports"]]
        db.add(admin)
        db.flush()
        db.add(Membership(user_id=user.id, workspace_id=workspace.id, role_id=admin.id, status="active"))
        db.commit()
        db.refresh(user)
        return {"access_token": issue_token(user.id), "token_type": "bearer", "bootstrap": bootstrap_payload(db, user)}
    finally:
        db.close()


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
        if not user or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Email or password is incorrect")
        return {"access_token": issue_token(user.id), "token_type": "bearer", "bootstrap": bootstrap_payload(db, user)}
    finally:
        db.close()


@app.post("/api/invitations")
def create_invitation(payload: InvitationRequest, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, membership_role = workspace_for_user(db, user)
        if membership_role.name != "ADMIN":
            raise HTTPException(status_code=403, detail="Only ADMIN can invite employees")
        role = db.query(CorporateRole).filter(CorporateRole.id == payload.role_id, CorporateRole.workspace_id == workspace.id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found in this workspace")
        raw_token = secrets.token_urlsafe(32)
        invitation = Invitation(workspace_id=workspace.id, role_id=role.id, invited_by=user.id, email=payload.email.lower().strip(), token_hash=hashlib.sha256(raw_token.encode()).hexdigest(), expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(), created_at=now())
        db.add(invitation)
        db.commit()
        return {"id": invitation.id, "email": invitation.email, "role": role.name, "expires_at": invitation.expires_at, "invite_token": raw_token, "message": "Send this invitation through your approved company email channel. Weber AI never asks for the employee's other website password."}
    finally:
        db.close()


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return bootstrap_payload(db, user)
    finally:
        db.close()


@app.get("/api/bootstrap")
def bootstrap(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return bootstrap_payload(db, user)
    finally:
        db.close()


@app.get("/api/roles")
def get_roles(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        return [serialize_role(role) for role in db.query(CorporateRole).filter(CorporateRole.workspace_id == workspace.id).order_by(CorporateRole.id).all()]
    finally:
        db.close()


@app.post("/api/roles")
def create_role(payload: RoleCreate, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, membership_role = workspace_for_user(db, user)
        if membership_role.name != "ADMIN":
            raise HTTPException(status_code=403, detail="Only ADMIN can create roles")
        if db.query(CorporateRole).filter(CorporateRole.workspace_id == workspace.id, CorporateRole.name == payload.name.strip()).first():
            raise HTTPException(status_code=409, detail="A role with this name already exists")
        role = CorporateRole(workspace_id=workspace.id, name=payload.name.strip(), department=payload.department.strip(), description=payload.description.strip(), updated="Just now")
        role.scopes = [RoleScope(label=scope.strip()) for scope in payload.scopes if scope.strip()]
        db.add(role)
        db.commit()
        db.refresh(role)
        return serialize_role(role)
    finally:
        db.close()


@app.get("/api/connectors")
def get_connectors(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        return [serialize_connector(item) for item in db.query(Connector).filter(Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).order_by(Connector.id).all()]
    finally:
        db.close()


@app.post("/api/connectors")
def create_connector(payload: ConnectorRequest, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        site = normalized_website(payload.website_url)
        hostname = website_domain(site)
        connector = Connector(workspace_id=workspace.id, created_by=user.id, name=(payload.name or hostname).strip(), website_url=site, created_at=now())
        db.add(connector)
        db.commit()
        db.refresh(connector)
        return serialize_connector(connector)
    finally:
        db.close()


@app.post("/api/connectors/{connector_id}/authorize")
def authorize_connector(connector_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, role = workspace_for_user(db, user)
        connector = db.query(Connector).filter(Connector.id == connector_id, Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).first()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        if connector.browser_session_id:
            try:
                browserbase_json("POST", f"/v1/sessions/{connector.browser_session_id}", {"status": "REQUEST_RELEASE"})
                time.sleep(1.5)
            except HTTPException:
                pass
        if not connector.browser_context_id:
            # Disconnect deliberately clears the old context. Use a unique
            # name so an orphaned Browserbase context can never block a new
            # authorization with a 409 name conflict.
            context_name = f"weber-connector-{connector.id}-{secrets.token_hex(6)}"
            context = browserbase_json("POST", "/v1/contexts", {"name": context_name})
            connector.browser_context_id = context.get("id") or context.get("contextId")
            if not connector.browser_context_id:
                raise HTTPException(status_code=502, detail="Browserbase did not return a persistent context")
        session_payload = {"timeout": 900, "keepAlive": True, "browserSettings": {"context": {"id": connector.browser_context_id, "persist": True}}, "region": "us-east-1", "userMetadata": {"connector_id": str(connector.id), "workspace_id": str(workspace.id), "user_id": str(user.id)}}
        try:
            session = browserbase_json("POST", "/v1/sessions", session_payload)
        except HTTPException as exc:
            # Some free Browserbase projects do not expose keepAlive. A normal
            # 15-minute session still supports the interactive login handoff.
            if exc.status_code != 502:
                raise
            session_payload.pop("keepAlive", None)
            session = browserbase_json("POST", "/v1/sessions", session_payload)
        session_id = session.get("id") or session.get("sessionId")
        connect_url = session.get("connectUrl") or session.get("connect_url") or session.get("wsUrl")
        if not session_id or not connect_url:
            raise HTTPException(status_code=502, detail="Browserbase returned an incomplete browser session")
        debug = browserbase_json("GET", f"/v1/sessions/{session_id}/debug?ttl=900")
        live_view_url = debug.get("debuggerFullscreenUrl") or debug.get("debuggerUrl")
        if not live_view_url:
            raise HTTPException(status_code=502, detail="Browserbase did not return a Live View URL")
        connector.browser_session_id = session_id
        connector.browser_connect_url = connect_url
        connector.browser_live_view_url = live_view_url
        connector.session_started_at = now()
        connector.status = "authorizing"
        db.commit()
        return {"connector": serialize_connector(connector), "authorization_status": "authorizing", "authorization_url": live_view_url, "role": role.name, "message": "The secure Weber AI browser is ready. Sign in inside the secure browser view, then return to Weber AI and click Check login. Your website password stays inside the isolated browser session."}
    finally:
        db.close()


@app.post("/api/connectors/{connector_id}/check-login")
def check_connector_login(connector_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        connector = db.query(Connector).filter(Connector.id == connector_id, Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).first()
        if not connector or not connector.browser_session_id:
            raise HTTPException(status_code=409, detail="Start a secure authorization session first")
        debug = browserbase_json("GET", f"/v1/sessions/{connector.browser_session_id}/debug")
        connect_url = connector.browser_connect_url or debug.get("wsUrl")
        if not connect_url:
            raise HTTPException(status_code=409, detail="The secure browser session has ended. Start authorization again.")
        inspected = asyncio.run(inspect_browser_session(connect_url, connector.website_url))
        if inspected["password_fields"] > 0:
            connector.status = "authorizing"
            db.commit()
            return {"connector": serialize_connector(connector), "authorized": False, "message": "The login page is still visible. Finish signing in inside the Weber AI Live View, then check again."}
        connector.status = "authorized"
        connector.last_authorized_at = now()
        connector.allowed_scope = "Only pages visible in the user-authorized session"
        db.commit()
        return {"connector": serialize_connector(connector), "authorized": True, "message": "The user-authorized browser session is connected. Weber AI can now analyze only the visible session data."}
    finally:
        db.close()


@app.post("/api/connectors/{connector_id}/disconnect")
def disconnect_connector(connector_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        connector = db.query(Connector).filter(Connector.id == connector_id, Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).first()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        if connector.browser_session_id:
            try:
                browserbase_json("POST", f"/v1/sessions/{connector.browser_session_id}", {"status": "REQUEST_RELEASE"})
            except HTTPException:
                pass
        if connector.browser_context_id:
            try:
                browserbase_json("DELETE", f"/v1/contexts/{connector.browser_context_id}")
            except HTTPException:
                pass
        connector.status = "authorization_required"
        connector.browser_session_id = None
        connector.browser_context_id = None
        connector.browser_connect_url = None
        connector.browser_live_view_url = None
        connector.session_started_at = None
        connector.last_authorized_at = None
        db.commit()
        return {"connector": serialize_connector(connector), "message": "Disconnected. The Browserbase session and saved website authorization have been removed."}
    finally:
        db.close()


@app.delete("/api/connectors/{connector_id}")
def delete_connector(connector_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, role = workspace_for_user(db, user)
        if role.name != "ADMIN":
            raise HTTPException(status_code=403, detail="Only ADMIN can delete website connectors")
        connector = db.query(Connector).filter(Connector.id == connector_id, Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).first()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        if connector.browser_session_id:
            try:
                browserbase_json("POST", f"/v1/sessions/{connector.browser_session_id}", {"status": "REQUEST_RELEASE"})
            except HTTPException:
                pass
        if connector.browser_context_id:
            try:
                browserbase_json("DELETE", f"/v1/contexts/{connector.browser_context_id}")
            except HTTPException:
                pass
        connector.revoked_at = now()
        connector.status = "deleted"
        connector.browser_session_id = None
        connector.browser_context_id = None
        connector.browser_connect_url = None
        connector.browser_live_view_url = None
        connector.session_started_at = None
        db.commit()
        return {"deleted": True, "message": "Website connector deleted and its temporary browser session was released."}
    finally:
        db.close()


@app.post("/api/analysis")
def create_analysis(payload: AnalysisRequest, background_tasks: BackgroundTasks, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, role = workspace_for_user(db, user)
        connector = db.query(Connector).filter(Connector.id == payload.connector_id, Connector.workspace_id == workspace.id, Connector.revoked_at.is_(None)).first()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        if connector.status != "authorized":
            raise HTTPException(status_code=409, detail="Authorize the connector in a secure browser session before starting an analysis")
        selected_role = db.query(CorporateRole).filter(CorporateRole.id == (payload.role_id or role.id), CorporateRole.workspace_id == workspace.id).first() or role
        run = AnalysisRun(workspace_id=workspace.id, user_id=user.id, connector_id=connector.id, role_id=selected_role.id, request=payload.request, export_format=payload.export_format, status="queued", unavailable_note="", created_at=now())
        db.add(run)
        db.commit()
        db.refresh(run)
        background_tasks.add_task(process_analysis, run.id)
        return {"analysis": serialize_analysis(run), "next_step": "processing_authorized_session"}
    finally:
        db.close()


@app.get("/api/analysis")
def get_analysis(background_tasks: BackgroundTasks, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        runs = db.query(AnalysisRun).filter(AnalysisRun.workspace_id == workspace.id, AnalysisRun.user_id == user.id, AnalysisRun.status != "deleted").order_by(AnalysisRun.id.desc()).all()
        for run in runs:
            if run.status == "queued":
                run.status = "processing"
                background_tasks.add_task(process_analysis, run.id)
        db.commit()
        return [serialize_analysis(run) for run in runs]
    finally:
        db.close()


@app.put("/api/analysis/{analysis_id}")
def edit_analysis(analysis_id: int, payload: AnalysisEditRequest, background_tasks: BackgroundTasks, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id, AnalysisRun.workspace_id == workspace.id, AnalysisRun.user_id == user.id, AnalysisRun.status != "deleted").first()
        if not run:
            raise HTTPException(status_code=404, detail="Analysis not found")
        if run.status == "processing":
            raise HTTPException(status_code=409, detail="Please wait for the current analysis to finish before editing it")
        run.request = payload.request
        if payload.export_format:
            run.export_format = payload.export_format
        run.status = "queued"; run.result_text = ""; run.unavailable_note = ""; run.completed_at = None
        db.commit(); background_tasks.add_task(process_analysis, run.id)
        return {"analysis": serialize_analysis(run), "message": "I’ve updated your request and started a fresh governed analysis."}
    finally:
        db.close()


@app.delete("/api/analysis/{analysis_id}")
def delete_analysis(analysis_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id, AnalysisRun.workspace_id == workspace.id, AnalysisRun.user_id == user.id, AnalysisRun.status != "deleted").first()
        if not run:
            raise HTTPException(status_code=404, detail="Analysis not found")
        for report in db.query(Report).filter(Report.analysis_id == run.id).all(): db.delete(report)
        run.status = "deleted"; run.result_text = ""; run.unavailable_note = "Deleted by the user."; run.completed_at = now()
        db.commit()
        return {"deleted": True, "message": "The analysis and its saved report were safely removed."}
    finally:
        db.close()


@app.get("/api/reports")
def get_reports(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        return [{"id": report.id, "analysis_id": report.analysis_id, "title": report.title, "export_format": report.export_format, "content": report.content, "source_summary": report.source_summary, "created_at": report.created_at} for report in db.query(Report).filter(Report.workspace_id == workspace.id, Report.user_id == user.id).order_by(Report.id.desc()).all()]
    finally:
        db.close()


@app.get("/api/analysis/{analysis_id}/export")
def export_analysis(analysis_id: int, format: str = "text", include_question: bool = True, include_explanation: bool = True, user: User = Depends(get_current_user)):
    """Render the saved report into the requested downloadable file format."""
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id, AnalysisRun.workspace_id == workspace.id, AnalysisRun.user_id == user.id).first()
        if not run or run.status != "completed":
            raise HTTPException(status_code=404, detail="A completed report is required before exporting")
        role = db.query(CorporateRole).filter(CorporateRole.id == run.role_id, CorporateRole.workspace_id == workspace.id).first()
        connector = db.query(Connector).filter(Connector.id == run.connector_id).first()
        company_name = workspace.name or "Corporate workspace"
        role_name = role.name if role else "Governed analyst"
        content = run.result_text or "No report content was returned."
        report_body = content if include_explanation else "Detailed explanation omitted at the user’s request."
        question_line = run.request if include_question else ""
        requested = format.lower().strip()
        safe_name = "weber-report-" + str(run.id)
        media_type = "text/plain; charset=utf-8"
        extension = "txt"
        output = report_body.encode("utf-8")
        if requested in {"text", "txt", "markdown", "md"}:
            extension = "txt"
        elif requested == "csv":
            buffer = io.StringIO(); writer = csv.writer(buffer)
            writer.writerow([company_name, "Weber AI report"]); writer.writerow(["Role", role_name]); writer.writerow(["Website", connector.website_url if connector else ""])
            if include_question: writer.writerow(["Question", question_line])
            writer.writerow(["Report content"])
            for line in report_body.splitlines(): writer.writerow([line])
            output = buffer.getvalue().encode("utf-8"); media_type, extension = "text/csv; charset=utf-8", "csv"
        elif requested == "pdf":
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            buffer = io.BytesIO(); pdf = canvas.Canvas(buffer, pagesize=A4); width, height = A4
            def page_branding():
                pdf.saveState(); pdf.translate(width / 2, height / 2); pdf.rotate(35); pdf.setFillColorRGB(.92, .92, .92); pdf.setFont("Helvetica-Bold", 44); pdf.drawCentredString(0, 0, company_name.upper()[:28]); pdf.restoreState()
                pdf.setFillColorRGB(.15, .15, .15); pdf.setFont("Helvetica", 8); pdf.drawRightString(width - 42, 24, f"{company_name} · {role_name} · Weber AI")
            page_branding(); y = height - 48
            pdf.setFont("Helvetica-Bold", 15); pdf.drawString(42, y, f"{company_name} — Corporate Intelligence Report"); y -= 20
            pdf.setFont("Helvetica", 9); pdf.drawString(42, y, f"Prepared by Weber AI · Role: {role_name}"); y -= 15
            if connector: pdf.drawString(42, y, f"Source: {connector.website_url}"); y -= 15
            if include_question: pdf.drawString(42, y, question_line[:115]); y -= 22
            for raw_line in report_body.replace("**", "").replace("```", "").splitlines():
                for line in textwrap.wrap(raw_line, width=105) or [""]:
                    if y < 44: pdf.showPage(); page_branding(); y = height - 48; pdf.setFont("Helvetica", 9)
                    pdf.drawString(42, y, line[:130]); y -= 13
            pdf.save(); output = buffer.getvalue(); media_type, extension = "application/pdf", "pdf"
        elif requested in {"word", "docx"}:
            from docx import Document
            document = Document(); document.add_heading(f"{company_name} — Corporate Report", 0); document.add_paragraph(f"Role: {role_name}")
            if connector: document.add_paragraph(f"Source: {connector.website_url}")
            if include_question: document.add_paragraph(question_line)
            for line in report_body.splitlines(): document.add_paragraph(line.replace("**", ""))
            buffer = io.BytesIO(); document.save(buffer); output = buffer.getvalue(); media_type, extension = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"
        elif requested in {"excel", "xlsx"}:
            from openpyxl import Workbook
            workbook = Workbook(); sheet = workbook.active; sheet.title = "Weber Report"
            sheet.append([company_name, "Corporate Report"]); sheet.append(["Role", role_name]); sheet.append(["Website", connector.website_url if connector else ""])
            if include_question: sheet.append(["Question", question_line])
            sheet.append([])
            for line in report_body.splitlines(): sheet.append([line])
            buffer = io.BytesIO(); workbook.save(buffer); output = buffer.getvalue(); media_type, extension = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
        elif requested in {"powerpoint", "ppt", "pptx"}:
            from pptx import Presentation
            presentation = Presentation(); slide = presentation.slides.add_slide(presentation.slide_layouts[1]); slide.shapes.title.text = f"{company_name} — Corporate Report"; slide.placeholders[1].text = f"Role: {role_name}" + (f"\n{question_line}" if include_question else "")
            for chunk in textwrap.wrap(report_body.replace("**", ""), width=850):
                slide = presentation.slides.add_slide(presentation.slide_layouts[1]); slide.shapes.title.text = "Findings"; slide.placeholders[1].text = chunk
            buffer = io.BytesIO(); presentation.save(buffer); output = buffer.getvalue(); media_type, extension = "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"
        elif requested in {"image", "png", "jpg", "jpeg"}:
            from PIL import Image, ImageDraw
            lines = []
            for raw_line in report_body.replace("**", "").splitlines(): lines.extend(textwrap.wrap(raw_line, width=95) or [""])
            image = Image.new("RGB", (1400, max(260, 120 + len(lines) * 24)), "#f8f6f1"); draw = ImageDraw.Draw(image)
            draw.text((60, 40), f"{company_name} — Corporate Report", fill="#171717"); draw.text((60, 80), f"Role: {role_name}", fill="#6f6a62")
            for index, line in enumerate(lines): draw.text((60, 130 + index * 24), line, fill="#2f2b27")
            buffer = io.BytesIO(); image.save(buffer, format="PNG"); output = buffer.getvalue(); media_type, extension = "image/png", "png"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        return StreamingResponse(io.BytesIO(output), media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{safe_name}.{extension}"'})
    finally:
        db.close()


@app.get("/api/conversations")
def get_conversations(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return [{"id": convo.id, "title": convo.title, "created_at": convo.created_at} for convo in db.query(Conversation).filter(Conversation.user_id == user.id).order_by(Conversation.id.desc()).all()]
    finally:
        db.close()


@app.post("/api/conversations")
def create_conversation(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, role = workspace_for_user(db, user)
        conversation = Conversation(title="New workspace chat", user_id=user.id, workspace_id=workspace.id, role_id=role.id, created_at=now())
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
        return {"id": conversation.id, "title": conversation.title}
    finally:
        db.close()


@app.get("/api/messages/{conversation_id}")
def get_messages(conversation_id: int, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        messages = db.query(ChatMessage).join(Conversation).filter(ChatMessage.conversation_id == conversation_id, Conversation.user_id == user.id).order_by(ChatMessage.id).all()
        return [{"role": msg.role, "content": msg.content} for msg in messages]
    finally:
        db.close()


@app.post("/api/stream")
def stream_chat(request: ChatRequest, user: User = Depends(get_current_user)):
    db = SessionLocal()
    workspace, member_role = workspace_for_user(db, user)
    conversation = db.query(Conversation).filter(Conversation.id == request.conversation_id, Conversation.user_id == user.id, Conversation.workspace_id == workspace.id).first()
    if not conversation:
        db.close()
        raise HTTPException(status_code=404, detail="Conversation not found")
    chosen_role = db.query(CorporateRole).filter(CorporateRole.id == (request.role_id or member_role.id), CorporateRole.workspace_id == workspace.id).first() or member_role
    scope_labels = [scope.label for scope in chosen_role.scopes]
    db.close()

    def event_generator():
        stream_db = SessionLocal()
        try:
            stream_db.add(ChatMessage(role="user", content=request.message, conversation_id=conversation.id, created_at=now()))
            stream_db.commit()
            if client is None:
                yield "The AI provider is not configured yet. Add GROQ_API_KEY to the backend environment, then redeploy."
                return
            scope_text = ", ".join(scope_labels) or "No data scopes granted"
            system_prompt = f"""You are Weber Intelligence, a governed corporate AI assistant for {workspace.name}, a {workspace.industry} company. The active user role is {chosen_role.name}. Their permitted information scopes are: {scope_text}. Only answer using information within those scopes. If asked for restricted information, explain that the request is outside this role's boundary and suggest an ADMIN review. Be concise, analytical, and action-oriented. Structure business analysis with a short conclusion, evidence, assumptions, and recommended next actions. Never invent company metrics; say when source data has not been connected."""
            full_messages = [{"role": "system", "content": system_prompt}]
            full_messages.extend({"role": msg.role, "content": msg.content} for msg in request.messages[-10:])
            full_messages.append({"role": "user", "content": request.message})
            stream = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), messages=full_messages, temperature=0.4, stream=True)
            full_response = ""
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    full_response += content
                    yield content
            stream_db.add(ChatMessage(role="assistant", content=full_response, conversation_id=conversation.id, created_at=now()))
            stream_db.commit()
        except Exception as exc:
            yield f"Weber AI could not complete this request: {exc}"
        finally:
            stream_db.close()
    return StreamingResponse(event_generator(), media_type="text/plain")
