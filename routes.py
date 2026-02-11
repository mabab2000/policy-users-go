from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from typing import List
import uuid
from datetime import datetime

from database import get_db
from models import User, Project, Policy, users_projects
from schemas import (
    UserCreate, UserResponse, UserWithProjects, ProjectSummary,
    ProjectCreate, ProjectResponse,
    PolicyCreate, PolicyResponse, PolicySummary,
    LoginRequest, LoginResponse
)
from auth import get_password_hash, verify_password, create_access_token, require_auth_matching_param

router = APIRouter()

@router.post("/users", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Create new user
    db_user = User(
        full_name=user.full_name,
        email=user.email,
        phone=user.phone,
        password=hashed_password
    )
    
    try:
        # set timestamps so response includes them immediately
        now = datetime.utcnow()
        db_user.created_at = now
        db_user.updated_at = now

        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    except Exception as e:
        db.rollback()
        # return error details for debugging
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
    # Convert SQLAlchemy model to Pydantic for JSON serialization
    user_out = UserResponse.model_validate(db_user)
    return {"message": "user created", "user": user_out}

@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    # Create new project
    db_project = Project(
        project_name=project.project_name,
        organization=project.organization,
        description=project.description,
        scorp=project.scorp
    )
    
    try:
        db.add(db_project)
        db.flush()  # Flush to get the ID
        
        # If user_id provided, validate and create link
        if project.user_id:
            try:
                user_uuid = uuid.UUID(project.user_id)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid user_id"
                )

            user_id_str = str(user_uuid)

            # Ensure user exists
            user = db.query(User).filter(User.id == user_id_str).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User not found"
                )
            
            # Create relationship
            db.execute(
                users_projects.insert().values(
                    user_id=user_id_str,
                    project_id=db_project.id
                )
            )
        
        db.commit()
        db.refresh(db_project)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create project"
        )
    
    return db_project

@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(policy: PolicyCreate, db: Session = Depends(get_db)):
    # Generate policy code based on existing count
    count = db.query(Policy).count()
    seq = count + 1
    code = f"POL-{datetime.now().year}-{seq:03d}"
    
    # Create new policy
    db_policy = Policy(
        title=policy.title,
        code=code,
        description=policy.description,
        problem_statement=policy.problem_statement,
        target_population=policy.target_population,
        objectives=policy.objectives,
        alignment_vision_2050=policy.alignment_vision_2050,
        alignment_nst=policy.alignment_nst,
        responsible_ministry=policy.responsible_ministry,
        priority_level=policy.priority_level
    )
    
    try:
        db.add(db_policy)
        db.commit()
        db.refresh(db_policy)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create policy"
        )
    
    return db_policy

@router.get("/policies", response_model=dict)
def list_policies(db: Session = Depends(get_db)):
    # Use raw SQL to avoid prepared statement issues with pgbouncer
    result = db.execute(text("""
        SELECT id, title, code, responsible_ministry, priority_level, created_at 
        FROM policies 
        ORDER BY created_at desc
    """))
    
    policies = []
    for row in result:
        policies.append(PolicySummary(
            policy_id=str(row[0]),
            title=row[1],
            code=row[2],
            responsible_ministry=row[3],
            priority_level=row[4],
            created_at=row[5]
        ))
    
    return {"policies": policies}

@router.get("/policies/{id}", response_model=dict)
def get_policy(id: str, db: Session = Depends(get_db)):
    try:
        policy_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid policy id"
        )

    policy = db.query(Policy).filter(Policy.id == str(policy_uuid)).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    # Convert SQLAlchemy model to dict for serialization, ensure UUIDs are strings
    policy_data = {
        "id": str(policy.id),
        "title": policy.title,
        "code": policy.code,
        "description": policy.description,
        "problem_statement": policy.problem_statement,
        "target_population": policy.target_population,
        "objectives": policy.objectives,
        "alignment_vision_2050": policy.alignment_vision_2050,
        "alignment_nst": policy.alignment_nst,
        "responsible_ministry": policy.responsible_ministry,
        "priority_level": policy.priority_level,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }

    return {"policy": PolicyResponse.model_validate(policy_data).model_dump()}

@router.post("/login", response_model=LoginResponse)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    # Find user by email
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not verify_password(login_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    # Get user's project IDs
    result = db.execute(
        text("SELECT project_id FROM users_projects WHERE user_id = :user_id"),
        {"user_id": user.id}
    )
    project_ids = [row[0] for row in result]
    
    return LoginResponse(
        token=f"Bearer {access_token}",
        user_id=user.id,
        project_ids=project_ids
    )

@router.get("/users/{id}", response_model=dict)
def get_user(id: str, db: Session = Depends(get_db), _: str = Depends(require_auth_matching_param)):
    try:
        user_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user id"
        )

    user = db.query(User).filter(User.id == str(user_uuid)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get user's projects
    result = db.execute(text("""
        SELECT p.id, p.project_name, p.organization 
        FROM projects p
        JOIN users_projects up ON p.id = up.project_id
        WHERE up.user_id = :user_id
    """), {"user_id": str(user_uuid)})
    
    projects = []
    for row in result:
        projects.append(ProjectSummary(
            project_id=row[0],
            project_name=row[1],
            organization=row[2]
        ))
    
    # Convert SQLAlchemy model to dict for serialization
    return {"user": UserResponse.model_validate(user).model_dump(), "projects": projects}

@router.get("/users/{id}/projects", response_model=dict)
def get_user_projects(id: str, db: Session = Depends(get_db)):
    try:
        user_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user id"
        )

    user_id_str = str(user_uuid)

    # Get user's projects
    result = db.execute(text("""
        SELECT p.id, p.project_name, p.organization, p.description, p.scorp, p.created_at, p.updated_at
        FROM projects p
        JOIN users_projects up ON p.id = up.project_id
        WHERE up.user_id = :user_id
    """), {"user_id": user_id_str})
    
    projects = []
    for row in result:
        projects.append(ProjectResponse(
            id=row[0],
            project_name=row[1],
            organization=row[2],
            description=row[3],
            scorp=row[4],
            created_at=row[5],
            updated_at=row[6]
        ))
    
    return {"projects": projects}