from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, Float, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # OAuth fields
    oauth_provider = Column(String, nullable=True)
    oauth_provider_user_id = Column(String, nullable=True)
    profile_picture = Column(String, nullable=True)
    
    verification_tokens = relationship("VerificationToken", back_populates="user")

class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    user = relationship("User", back_populates="verification_tokens")

class Topic(Base):
    __tablename__ = "topics"
   
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    slug = Column(String, unique=True, index=True)
    description = Column(Text)
    icon_name = Column(String)  # Store icon name as string (e.g., "Layers", "ListTree")
    color = Column(String)
   
    problems = relationship("Problem", back_populates="topic")

class Problem(Base):
    __tablename__ = "problems"
   
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    difficulty = Column(String)  # "easy", "medium", "hard"
    link = Column(String)
    description = Column(Text, nullable=True)
    question = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)
    topic_id = Column(Integer, ForeignKey("topics.id"))
   
    topic = relationship("Topic", back_populates="problems")

# Create DB Engine
engine = create_engine("sqlite:///leetcode_problems.db")
Base.metadata.create_all(bind=engine)