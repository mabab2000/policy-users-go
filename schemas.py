from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
import uuid

# User schemas
class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    phone: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Project schemas
class ProjectBase(BaseModel):
    project_name: str
    organization: Optional[str] = None
    description: Optional[str] = None
    scorp: Optional[str] = None

class ProjectCreate(ProjectBase):
    user_id: Optional[str] = None

class ProjectResponse(ProjectBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ProjectSummary(BaseModel):
    project_id: str
    project_name: str
    organization: Optional[str] = None

# Policy schemas
class PolicyBase(BaseModel):
    title: str
    description: str
    problem_statement: str
    target_population: str
    objectives: Optional[str] = None
    alignment_vision_2050: bool
    alignment_nst: bool
    responsible_ministry: Optional[str] = None
    priority_level: Optional[str] = None

class PolicyCreate(PolicyBase):
    pass

class PolicyResponse(PolicyBase):
    id: str
    code: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class PolicySummary(BaseModel):
    policy_id: str
    title: str
    code: str
    responsible_ministry: Optional[str] = None
    priority_level: Optional[str] = None
    created_at: datetime

# Auth schemas
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    token: str
    user_id: str
    project_ids: List[str]

# User with projects response
class UserWithProjects(UserResponse):
    projects: List[ProjectSummary]


# Implementation schemas
class ImplementationBase(BaseModel):
    program_name: str
    description: Optional[str] = None
    status: Optional[str] = None
    budget: Optional[str] = None
    timeline: Optional[str] = None
    lead: Optional[str] = None
    progress: Optional[str] = None
    policy_id: Optional[str] = None
    type: Optional[str] = None

class ImplementationCreate(ImplementationBase):
    pass

class ImplementationResponse(ImplementationBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ImplementationSummary(BaseModel):
    id: str
    program_name: str
    status: Optional[str] = None
    progress: Optional[str] = None