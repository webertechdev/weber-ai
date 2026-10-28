from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(80), nullable=False)
    last_name = Column(String(80), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    job_title = Column(String(120), default="Workspace administrator")
    email_domain = Column(String(255), default="")
    created_at = Column(String, nullable=False)
    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="user", cascade="all, delete-orphan")


class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False)
    industry = Column(String(120), default="Corporate")
    company_size = Column(String(80), default="1-10")
    company_website = Column(String(255), nullable=False, default="")
    domain_verification_status = Column(String(30), default="pending")
    created_at = Column(String, nullable=False)
    memberships = relationship("Membership", back_populates="workspace", cascade="all, delete-orphan")
    roles = relationship("CorporateRole", back_populates="workspace", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="workspace", cascade="all, delete-orphan")


class Membership(Base):
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("corporate_roles.id"), nullable=False)
    status = Column(String(20), default="active")
    user = relationship("User", back_populates="memberships")
    workspace = relationship("Workspace", back_populates="memberships")
    role = relationship("CorporateRole", back_populates="memberships")
    __table_args__ = (UniqueConstraint("user_id", "workspace_id", name="uq_user_workspace"),)


class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, default="New Chat")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("corporate_roles.id"), nullable=True)
    created_at = Column(String, nullable=False)
    user = relationship("User", back_populates="conversations")
    workspace = relationship("Workspace", back_populates="conversations")
    messages = relationship("ChatMessage", back_populates="conversation", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    role = Column(String)
    content = Column(Text)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    created_at = Column(String, nullable=False)
    conversation = relationship("Conversation", back_populates="messages")


class CorporateRole(Base):
    __tablename__ = "corporate_roles"
    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False)
    name = Column(String, nullable=False)
    department = Column(String, default="General")
    description = Column(Text, default="")
    members = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    updated = Column(String, default="Just now")
    workspace = relationship("Workspace", back_populates="roles")
    scopes = relationship("RoleScope", back_populates="role", cascade="all, delete-orphan")
    memberships = relationship("Membership", back_populates="role")
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_workspace_role_name"),)


class RoleScope(Base):
    __tablename__ = "role_scopes"
    id = Column(Integer, primary_key=True, index=True)
    label = Column(String, nullable=False)
    role_id = Column(Integer, ForeignKey("corporate_roles.id"), nullable=False)
    role = relationship("CorporateRole", back_populates="scopes")


class Invitation(Base):
    __tablename__ = "invitations"
    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("corporate_roles.id"), nullable=False)
    invited_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    token_hash = Column(String(255), unique=True, nullable=False)
    status = Column(String(20), default="pending")
    expires_at = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
