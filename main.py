from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from typing import Union, Annotated

from deps import JWTBearer
from utils import *

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


class PostBase(BaseModel):
    title: str
    content: str
    user_id: int


class UserBase(BaseModel):
    email: str
    password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


@app.post('/users', dependencies=[Depends(JWTBearer())], status_code=status.HTTP_201_CREATED)
async def create_user(user: UserBase, db: db_dependency):
    db_user = models.User(**user.dict())
    db.add(db_user)
    db.commit()
    return user


@app.post('/signup', summary="Create new user")
async def create_user(user: UserBase, db: db_dependency):
    # querying database to check if user already exist
    check_user = db.query(models.User).filter(models.User.email == user.email).first()
    if check_user:
        raise HTTPException(status_code=409, detail="email taken")
    db_user = models.User(**user.dict())
    db_user.password = get_hashed_password(db_user.password)
    db.add(db_user)
    db.commit()
    return db_user


@app.post('/login', summary="Login user")
async def login(user: UserBase, db: db_dependency):
    # querying database to check if user already exist
    check_user = db.query(models.User).filter(models.User.email == user.email).first()
    print(check_user)
    if check_user is None:
        raise HTTPException(status_code=403, detail="not allowed")
    if not verify_password(user.password, check_user.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Incorrect email or password",
        )

    return {
        "user": check_user,
        "access_token": create_access_token(check_user.email, 14),
        "refresh_token": create_refresh_token(check_user.email, 7)
    }
