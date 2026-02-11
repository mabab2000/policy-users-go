from datetime import datetime, timedelta
from typing import Optional
import os
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Password hashing
# Use bcrypt_sha256 first to support passwords longer than bcrypt's 72-byte limit
pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")

# bcrypt has a 72-byte password limit. Truncate UTF-8 strings safely to that limit
TRUNCATE_LIMIT = 72

def _truncate_password(password: str) -> str:
    """Return a UTF-8-safe truncation of `password` so its encoded length <= 72 bytes.
    This preserves character boundaries and avoids splitting multi-byte characters.
    """
    b = password.encode("utf-8")
    if len(b) <= TRUNCATE_LIMIT:
        return password
    out = bytearray()
    for ch in password:
        chb = ch.encode("utf-8")
        if len(out) + len(chb) > TRUNCATE_LIMIT:
            break
        out.extend(chb)
    return out.decode("utf-8", errors="ignore")

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Truncate input to bcrypt limit to avoid ValueError from passlib/bcrypt
    safe = _truncate_password(plain_password)
    return pwd_context.verify(safe, hashed_password)

def get_password_hash(password: str) -> str:
    # Truncate before hashing so stored hashes match verification behavior
    safe = _truncate_password(password)
    return pwd_context.hash(safe)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow()
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token claims"
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def require_auth_matching_param(id: str, credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Validates that the token subject matches the path parameter user ID"""
    user_id = verify_token(credentials)
    if user_id != id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden"
        )
    return user_id