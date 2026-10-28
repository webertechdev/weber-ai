import os
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from groq import Groq
from pydantic import BaseModel, Field

from database import Base, SessionLocal, engine
from models import ChatMessage, Conversation, CorporateRole, RoleScope

load_dotenv()
Base.metadata.create_all(bind=engine)
app = FastAPI(title="Weber AI Corporate Intelligence API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
groq_api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=groq_api_key) if groq_api_key else None


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    messages: list[Message] = Field(default_factory=list)
    conversation_id: int
    role: str = "ADMIN"
    scopes: list[str] = Field(default_factory=lambda: ["All company data"])


class RoleCreate(BaseModel):
    name: str
    department: str = "General"
    description: str = ""
    scopes: list[str] = Field(default_factory=lambda: ["Workspace overview"])
    members: int = 0


def serialize_role(role: CorporateRole):
    return {"id": role.id, "name": role.name, "department": role.department, "description": role.description, "scopes": [scope.label for scope in role.scopes], "members": role.members, "active": role.active, "updated": role.updated}


@app.get("/")
def root():
    return {"message": "Weber AI Corporate Intelligence API is running"}


@app.get("/api/roles")
def get_roles():
    db = SessionLocal()
    try:
        return [serialize_role(role) for role in db.query(CorporateRole).order_by(CorporateRole.id).all()]
    finally:
        db.close()


@app.post("/api/roles")
def create_role(payload: RoleCreate):
    db = SessionLocal()
    try:
        if db.query(CorporateRole).filter(CorporateRole.name == payload.name).first():
            raise HTTPException(status_code=409, detail="A role with this name already exists")
        role = CorporateRole(name=payload.name, department=payload.department, description=payload.description, members=payload.members, updated="Just now")
        role.scopes = [RoleScope(label=scope) for scope in payload.scopes]
        db.add(role)
        db.commit()
        db.refresh(role)
        return serialize_role(role)
    finally:
        db.close()


@app.patch("/api/roles/{role_id}")
def update_role(role_id: int, active: bool | None = None):
    db = SessionLocal()
    try:
        role = db.query(CorporateRole).filter(CorporateRole.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        if active is not None:
            role.active = active
        role.updated = datetime.now().strftime("%b %d, %Y")
        db.commit()
        db.refresh(role)
        return serialize_role(role)
    finally:
        db.close()


@app.get("/api/messages/{conversation_id}")
def get_messages(conversation_id: int):
    db = SessionLocal()
    try:
        messages = db.query(ChatMessage).filter(ChatMessage.conversation_id == conversation_id).order_by(ChatMessage.id).all()
        return [{"role": msg.role, "content": msg.content} for msg in messages]
    finally:
        db.close()


@app.post("/api/conversations")
def create_conversation():
    db = SessionLocal()
    try:
        conversation = Conversation(title="New Chat")
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
        return {"id": conversation.id, "title": conversation.title}
    finally:
        db.close()


@app.get("/api/conversations")
def get_conversations():
    db = SessionLocal()
    try:
        return [{"id": convo.id, "title": convo.title} for convo in db.query(Conversation).order_by(Conversation.id.desc()).all()]
    finally:
        db.close()


@app.post("/api/stream")
def stream_chat(request: ChatRequest):
    def event_generator():
        db = SessionLocal()
        try:
            if client is None:
                yield "Weber AI is configured, but the GROQ_API_KEY is not set on the backend yet."
                return
            db.add(ChatMessage(role="user", content=request.message, conversation_id=request.conversation_id))
            db.commit()
            scope_text = ", ".join(request.scopes) or "No data scopes granted"
            system_prompt = f"""You are Weber Intelligence, a governed corporate AI assistant. The active user role is {request.role}. Their permitted information scopes are: {scope_text}. Only answer using information within those scopes. If asked for restricted information, explain that the request is outside this role's boundary and suggest an ADMIN review. Be concise, analytical, and action-oriented. Structure business analysis with a short conclusion, evidence, and recommended next actions."""
            full_messages = [{"role": "system", "content": system_prompt}]
            full_messages.extend({"role": msg.role, "content": msg.content} for msg in request.messages[-10:])
            full_messages.append({"role": "user", "content": request.message})
            stream = client.chat.completions.create(model="openai/gpt-oss-20b", messages=full_messages, temperature=0.4, stream=True)
            full_response = ""
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    full_response += content
                    yield content
            db.add(ChatMessage(role="assistant", content=full_response, conversation_id=request.conversation_id))
            db.commit()
        except Exception as exc:
            yield f"Weber AI service error: {exc}"
        finally:
            db.close()
    return StreamingResponse(event_generator(), media_type="text/plain")
