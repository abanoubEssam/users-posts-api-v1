from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, Any
from jose import jwt

ACCESS_TOKEN_EXPIRE_DAYS = 14  # 14 DAYS
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = 'JWT_SECRET_KEY'  # should be kept secret
JWT_REFRESH_SECRET_KEY = 'JWT_REFRESH_SECRET_KEY'  # should be kept secret

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + timedelta(days=expires_delta)
    else:
        expires_delta = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + timedelta(days=expires_delta)
    else:
        expires_delta = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=ALGORITHM)
        print(decoded_token)
        print(decoded_token["exp"])
        print(datetime.utcnow().timestamp())
        return decoded_token if decoded_token["exp"] >= datetime.utcnow().timestamp() else None
    except:
        return {}
