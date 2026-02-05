"""
ShadowHawk Platform - Authentication Service

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
from jose import JWTError, jwt
from passlib.context import CryptContext

from ...domain.models.user import User

logger = logging.getLogger(__name__)


class AuthService:
    """
    Authentication service for JWT-based authentication.
    """
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7
    ):
        """
        Initialize authentication service.
        
        Args:
            secret_key: Secret key for JWT signing
            algorithm: JWT algorithm
            access_token_expire_minutes: Access token expiration time
            refresh_token_expire_days: Refresh token expiration time
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against a hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def create_access_token(
        self,
        user: User,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT access token.
        
        Args:
            user: User to create token for
            expires_delta: Optional custom expiration time
            
        Returns:
            JWT access token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": [role.value for role in user.roles],
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Created access token for user: {user.username}")
        
        return encoded_jwt
    
    def create_refresh_token(self, user: User) -> str:
        """
        Create a JWT refresh token.
        
        Args:
            user: User to create token for
            
        Returns:
            JWT refresh token
        """
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode = {
            "sub": str(user.id),
            "username": user.username,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Created refresh token for user: {user.username}")
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None
    
    def authenticate_user(
        self,
        username: str,
        password: str,
        user: Optional[User]
    ) -> bool:
        """
        Authenticate a user.
        
        Args:
            username: Username
            password: Password
            user: User object from database
            
        Returns:
            True if authenticated, False otherwise
        """
        if not user:
            logger.warning(f"Authentication failed: User not found - {username}")
            return False
        
        if not user.is_active:
            logger.warning(f"Authentication failed: User inactive - {username}")
            return False
        
        if not self.verify_password(password, user.hashed_password):
            logger.warning(f"Authentication failed: Invalid password - {username}")
            user.record_failed_login()
            return False
        
        user.record_login()
        logger.info(f"User authenticated successfully: {username}")
        return True
    
    def generate_token_pair(self, user: User) -> Dict[str, str]:
        """
        Generate access and refresh token pair.
        
        Args:
            user: User to generate tokens for
            
        Returns:
            Dictionary with access_token and refresh_token
        """
        return {
            "access_token": self.create_access_token(user),
            "refresh_token": self.create_refresh_token(user),
            "token_type": "bearer"
        }
