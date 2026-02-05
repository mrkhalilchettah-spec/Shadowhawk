"""
ShadowHawk Platform - Authentication API Routes

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import List
import logging

from ...domain.models.user import User, Role
from ...infrastructure.security.auth import AuthService

logger = logging.getLogger(__name__)

router = APIRouter()

auth_service = AuthService(
    secret_key="your-secret-key-change-in-production",
    algorithm="HS256"
)


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str | None
    roles: List[str]
    is_active: bool


@router.post("/register", response_model=UserResponse)
async def register(request: RegisterRequest):
    """
    Register a new user.
    """
    try:
        hashed_password = auth_service.hash_password(request.password)
        
        user = User(
            username=request.username,
            email=request.email,
            hashed_password=hashed_password,
            full_name=request.full_name,
            roles=[Role.VIEWER]
        )
        
        logger.info(f"User registered: {user.username}")
        
        return UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            roles=[role.value for role in user.roles],
            is_active=user.is_active
        )
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Login and receive JWT tokens.
    """
    user = User(
        username=request.username,
        email=f"{request.username}@example.com",
        hashed_password=auth_service.hash_password(request.password),
        roles=[Role.ANALYST]
    )
    
    if auth_service.authenticate_user(request.username, request.password, user):
        tokens = auth_service.generate_token_pair(user)
        
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"]
        )
    else:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user():
    """
    Get current authenticated user information.
    """
    user = User(
        username="demo_user",
        email="demo@example.com",
        hashed_password="",
        roles=[Role.ANALYST]
    )
    
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        roles=[role.value for role in user.roles],
        is_active=user.is_active
    )
