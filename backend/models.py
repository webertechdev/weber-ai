from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from database import Base


class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, default="New Chat")
    messages = relationship("ChatMessage", back_populates="conversation", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    role = Column(String)
    content = Column(Text)
    conversation_id = Column(Integer, ForeignKey("conversations.id"))
    conversation = relationship("Conversation", back_populates="messages")


class CorporateRole(Base):
    __tablename__ = "corporate_roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    department = Column(String, default="General")
    description = Column(Text, default="")
    members = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    updated = Column(String, default="Just now")
    scopes = relationship("RoleScope", back_populates="role", cascade="all, delete-orphan")


class RoleScope(Base):
    __tablename__ = "role_scopes"
    id = Column(Integer, primary_key=True, index=True)
    label = Column(String, nullable=False)
    role_id = Column(Integer, ForeignKey("corporate_roles.id"), nullable=False)
    role = relationship("CorporateRole", back_populates="scopes")
