from database import SessionLocal, engine, Base
from models import ChatMessage, Conversation

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from groq import Groq
from dotenv import load_dotenv

import os

# LOAD ENV
load_dotenv()

# CREATE DATABASE TABLES
Base.metadata.create_all(bind=engine)

# FASTAPI
app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GROQ
api_key = os.getenv("GROQ_API_KEY")


client = Groq(api_key=api_key)


# MODELS
class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    messages: list[Message]
    conversation_id: int


# ROOT
@app.get("/")
async def root():
    return {"message": "WEBARE AI Backend Running"}


# GET MESSAGES
@app.get("/api/messages/{conversation_id}")
async def get_messages(conversation_id: int):

    db = SessionLocal()

    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.conversation_id == conversation_id)
        .all()
    )

    db.close()

    return [{"role": msg.role, "content": msg.content} for msg in messages]


# CREATE NEW CONVERSATION
@app.post("/api/conversations")
async def create_conversation():

    db = SessionLocal()

    conversation = Conversation(title="New Chat")

    db.add(conversation)

    db.commit()

    db.refresh(conversation)

    db.close()

    return {"id": conversation.id, "title": conversation.title}


# GET CONVERSATIONS
@app.get("/api/conversations")
async def get_conversations():

    db = SessionLocal()

    conversations = db.query(Conversation).all()

    db.close()

    return [{"id": convo.id, "title": convo.title} for convo in conversations]


# GET OLD MESSAGES
@app.get("/api/messages")
async def get_messages():

    db = SessionLocal()

    messages = db.query(ChatMessage).all()

    db.close()

    return [{"role": msg.role, "content": msg.content} for msg in messages]


# STREAM CHAT
@app.post("/api/stream")
async def stream_chat(request: ChatRequest):

    async def event_generator():

        try:

            db = SessionLocal()

            # SAVE USER MESSAGE
            db.add(
                ChatMessage(
                    role="user",
                    content=request.message,
                    conversation_id=request.conversation_id,
                )
            )
            db.commit()

            # FULL CONVERSATION
            full_messages = [
                {
                    "role": "system",
                    "content": """
You are WEBARE AI.

A modern intelligent AI assistant.

Rules:
- Remember previous messages
- Continue conversations naturally
- Behave like ChatGPT
- Remember names
""",
                }
            ]

            # LAST 10 MESSAGES ONLY
            recent_messages = request.messages[-10:]
            for msg in recent_messages:
                full_messages.append({"role": msg.role, "content": msg.content})

            # CURRENT MESSAGE
            full_messages.append({"role": "user", "content": request.message})

            # AI STREAM
            stream = client.chat.completions.create(
                model="openai/gpt-oss-20b",
                messages=full_messages,
                temperature=0.7,
                stream=True,
            )

            full_response = ""

            for chunk in stream:

                content = chunk.choices[0].delta.content

                if content:

                    full_response += content

                    yield content

            # SAVE AI RESPONSE
            db.add(
                ChatMessage(
                    role="assistant",
                    content=full_response,
                    conversation_id=request.conversation_id,
                )
            )

            db.commit()

            db.close()

        except Exception as e:

            yield f"Error: {str(e)}"

    return StreamingResponse(event_generator(), media_type="text/plain")
