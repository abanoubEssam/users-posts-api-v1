from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from typing import Union, Annotated
from fastapi.security import OAuth2PasswordBearer

from deps import JWTBearer
from utils import *

app = FastAPI()
models.Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class PostBase(BaseModel):
    title: str
    content: str
    user_id: int


class UserBase(BaseModel):
    email: str
    password: str
    role: str


class UserLoginDto(BaseModel):
    email: str
    password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        print("Closing Db")
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


# @app.on_event("startup")
# async def startup_event():
#     print("Server StartUp")


# @app.post('/users', dependencies=[Depends(JWTBearer())], status_code=status.HTTP_201_CREATED)
@app.post('/users', dependencies=[Depends(JWTBearer())], status_code=status.HTTP_201_CREATED)
async def create_user(token: Annotated[str, Depends(oauth2_scheme)], user: UserBase, db: db_dependency):
    print("token: " + str(token))
    current_user = decode_jwt(token)
    print(current_user)
    check_user = db.query(models.User).filter(models.User.email == user.email).first()
    if check_user:
        raise HTTPException(status_code=409, detail="email taken")
    db_user = models.User(**user.dict())
    db_user.password = get_hashed_password(db_user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    user_res = jsonable_encoder(db_user)
    # create conversation for user
    conversationData = {
        "user_id": db_user.id,
    }
    db_conversation = models.Conversation(**conversationData)
    db.add(db_conversation)
    db.commit()
    db.refresh(db_conversation)

    return user_res


@app.post('/login', summary="Login user")
async def login(user: UserLoginDto, db: db_dependency):
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

    print("check_user: " + str(check_user.id))
    token_subject = {
        "id": str(check_user.id),
        "email": check_user.email,
    }
    return {
        "user": check_user,
        "access_token": create_access_token(token_subject, 14),
        "refresh_token": create_refresh_token(token_subject, 7)
    }


@app.get('/conversations', dependencies=[Depends(JWTBearer())], status_code=status.HTTP_201_CREATED)
async def find_conversations(token: Annotated[str, Depends(oauth2_scheme)], db: db_dependency):
    current_user = decode_jwt(token)
    print(current_user)
    check_user = db.query(models.User).filter(models.User.email == current_user['email']).first()
    if check_user is None:
        raise HTTPException(status_code=403, detail="not allowed")
    conversations_list = []
    for e in db.query(models.Conversation).filter(models.Conversation.user_id == check_user.id):
        conversations_list.append(e)
    return conversations_list
