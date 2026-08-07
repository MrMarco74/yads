from datetime import datetime, timedelta
from typing import Optional, Union, Any
import jwt
from passlib.context import CryptContext
from yads.config import settings

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Token Handling
def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"sub": str(subject), "exp": expire}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# API Key Handling
import secrets
import hashlib

def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256."""
    return hashlib.sha256(key.encode()).hexdigest()

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (plain_key, prefix, hash)
    The plain_key should be shown to the user ONLY ONCE.
    """
    key = f"yads_{secrets.token_urlsafe(32)}"
    prefix = key[:12] # e.g. 'yads_ABC123'
    key_hash = hash_api_key(key)
    return key, prefix, key_hash
