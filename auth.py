from datetime import datetime, timedelta
from typing import Optional
import os
import warnings

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# -------------------------------
# Bcrypt version fix for passlib
# -------------------------------
try:
    import bcrypt as _bcrypt
    if not hasattr(_bcrypt, "__about__"):
        class _About: pass
        ver = getattr(_bcrypt, "__version__", None)
        if ver is None:
            try:
                import importlib.metadata as _im
                ver = _im.version("bcrypt")
            except Exception:
                ver = "0"
        _about = _About()
        _about.__version__ = ver
        _bcrypt.__about__ = _about
    
    # Monkey-patch bcrypt.hashpw to auto-truncate passwords to 72 bytes
    # This prevents ValueError during passlib's backend initialization
    _original_hashpw = _bcrypt.hashpw
    
    def _safe_hashpw(password, salt):
        """Wrapper that truncates password to 72 bytes before hashing"""
        if isinstance(password, str):
            password = password.encode("utf-8")
        if len(password) > 72:
            password = password[:72]
        return _original_hashpw(password, salt)
    
    _bcrypt.hashpw = _safe_hashpw
    
except Exception:
    pass  # Let passlib handle missing bcrypt

# -------------------------------
# Password hashing (bcrypt_sha256 to bypass 72-byte limit)
# -------------------------------
TRUNCATE_LIMIT = 72  # bytes

def _truncate_password(password: str) -> str:
    """Truncate UTF-8 password safely to <= 72 bytes for bcrypt"""
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

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    pwd_context = CryptContext(
        schemes=["bcrypt_sha256", "bcrypt"],  # support old and new users
        deprecated="auto",
        bcrypt__default_rounds=12,           # secure rounds
    )

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe = _truncate_password(plain_password)
    return pwd_context.verify(safe, hashed_password)

def get_password_hash(password: str) -> str:
    safe = _truncate_password(password)
    return pwd_context.hash(safe)

# -------------------------------
# JWT Settings
# -------------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow()
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")
        return user_id
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def require_auth_matching_param(id: str, credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Validates that the token subject matches the path parameter user ID"""
    user_id = verify_token(credentials)
    if user_id != id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user_id
