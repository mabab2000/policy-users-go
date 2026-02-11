from sqlalchemy import Boolean, Column, String, Text, DateTime, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

# Association table for many-to-many relationship between users and projects
users_projects = Table(
    'users_projects',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('project_id', UUID(as_uuid=True), ForeignKey('projects.id'), primary_key=True)
)

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone = Column(String(64))
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Many-to-many relationship with projects
    projects = relationship("Project", secondary=users_projects, back_populates="users")

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_name = Column(String(255), nullable=False)
    organization = Column(String(255))
    description = Column(Text)
    scorp = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Many-to-many relationship with users
    users = relationship("User", secondary=users_projects, back_populates="projects")

class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    code = Column(String(32), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    problem_statement = Column(Text, nullable=False)
    target_population = Column(Text, nullable=False)
    objectives = Column(Text)  # newline-separated
    alignment_vision_2050 = Column(Boolean, default=False)
    alignment_nst = Column(Boolean, default=False)
    responsible_ministry = Column(String(255))
    priority_level = Column(String(64))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())