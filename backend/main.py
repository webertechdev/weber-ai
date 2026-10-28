import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from groq import Groq
from pydantic import BaseModel, Field, EmailStr

from database import Base, SessionLocal, engine
from models import ChatMessage, Conversation, CorporateRole, Membership, RoleScope, User, Workspace

load_dotenv()
Base.metadata.create_all(bind=engine)
app = FastAPI(title="Weber AI Corporate Intelligence API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    print(f"Unhandled Weber AI error on {request.method} {request.url.path}: {exc}", flush=True)
    return JSONResponse(status_code=500, content={"detail": "The Weber AI backend could not complete this request. Check DATABASE_URL, AUTH_SECRET, and deployment logs."})

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
    return {"user": serialize_user(user), "workspace": {"id": workspace.id, "name": workspace.name, "industry": workspace.industry, "company_size": workspace.company_size}, "active_role": serialize_role(membership_role), "roles": [serialize_role(role) for role in roles], "conversation_id": conversation.id}


@app.get("/")
def root():
    return {"message": "Weber AI Corporate Intelligence API is running"}


@app.get("/health")
def health():
    return {"status": "ok", "database": bool(os.getenv("DATABASE_URL")), "ai_provider": bool(groq_api_key)}


@app.post("/api/auth/signup")
def signup(payload: SignupRequest):
    db = SessionLocal()
    try:
        email = payload.email.lower().strip()
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        user = User(first_name=payload.first_name.strip(), last_name=payload.last_name.strip(), email=email, password_hash=hash_password(payload.password), job_title=payload.job_title.strip(), created_at=now())
        workspace = Workspace(name=payload.company_name.strip(), industry=payload.industry.strip(), company_size=payload.company_size, created_at=now())
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
