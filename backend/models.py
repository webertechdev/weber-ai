from sqlalchemy import Column, Integer, String, Text
from database import Base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class Conversation(Base):

    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String)

    messages = relationship("ChatMessage", back_populates="conversation")


class ChatMessage(Base):

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)

    role = Column(String)

    content = Column(String)

    conversation_id = Column(Integer, ForeignKey("conversations.id"))

    conversation = relationship("Conversation", back_populates="messages")
