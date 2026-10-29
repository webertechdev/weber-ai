import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from groq import Groq
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import text

from database import Base, DATABASE_SOURCE, SessionLocal, engine
from models import AnalysisRun, ChatMessage, Connector, Conversation, CorporateRole, Invitation, Membership, Report, RoleScope, User, Workspace

load_dotenv()
Base.metadata.create_all(bind=engine)
with engine.begin() as schema_db:
    for statement in (
        "ALTER TABLE users ADD COLUMN email_domain VARCHAR(255)",
        "ALTER TABLE workspaces ADD COLUMN company_website VARCHAR(255)",
        "ALTER TABLE workspaces ADD COLUMN domain_verification_status VARCHAR(30)",
    ):
        try:
            schema_db.execute(text(statement))
        except Exception:
            pass
app = FastAPI(title="Weber AI Corporate Intelligence API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    print(f"Unhandled Weber AI error on {request.method} {request.url.path}: {exc}", flush=True)
    return JSONResponse(status_code=500, content={"detail": "The Weber AI backend could not complete this request. Check the backend storage configuration and deployment logs.", "error_type": exc.__class__.__name__})

groq_api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=groq_api_key) if groq_api_key else None
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
    return {"id": connector.id, "name": connector.name, "website_url": connector.website_url, "connector_type": connector.connector_type, "status": connector.status, "allowed_scope": connector.allowed_scope, "last_authorized_at": connector.last_authorized_at, "last_analysis_at": connector.last_analysis_at, "created_at": connector.created_at}


def serialize_analysis(run: AnalysisRun):
    return {"id": run.id, "connector_id": run.connector_id, "request": run.request, "export_format": run.export_format, "status": run.status, "unavailable_note": run.unavailable_note, "result_text": run.result_text, "created_at": run.created_at, "completed_at": run.completed_at}


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
    return {"status": "ok" if database_ok else "degraded", "database": database_ok, "database_source": DATABASE_SOURCE, "ai_provider": bool(groq_api_key), "auth_secret_configured": bool(os.getenv("AUTH_SECRET"))}


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
        # This creates an auditable authorization request. A browser-worker/session bridge must
        # complete the external login and callback before status becomes authorized.
        return {"connector": serialize_connector(connector), "authorization_status": "authorization_required", "authorization_url": connector.website_url, "role": role.name, "message": "Open the website in the secure authorization session, sign in there, review the requested page scope, and approve access. Weber AI must not receive or store this website password."}
    finally:
        db.close()


@app.post("/api/analysis")
def create_analysis(payload: AnalysisRequest, user: User = Depends(get_current_user)):
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
        return {"analysis": serialize_analysis(run), "next_step": "authorize_connector" if connector.status != "authorized" else "browser_worker_required"}
    finally:
        db.close()


@app.get("/api/analysis")
def get_analysis(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        workspace, _ = workspace_for_user(db, user)
        return [serialize_analysis(run) for run in db.query(AnalysisRun).filter(AnalysisRun.workspace_id == workspace.id, AnalysisRun.user_id == user.id).order_by(AnalysisRun.id.desc()).all()]
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
