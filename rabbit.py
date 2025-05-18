
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse


from sqlalchemy.orm import sessionmaker, Session
from jwt.exceptions import InvalidTokenError
from app.database import engine, Base, User
from passlib.context import CryptContext
from app.models import AddUser, Login, TokenData, Token
from datetime import datetime, timedelta
from typing import Dict, Annotated


import pike
import json
import jwt
import os


import uvicorn


# app/logger.py

import logging
import sys

def get_logger(name: str = "app"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Or INFO in production

    # Avoid duplicate handlers
    if not logger.hasHandlers():
        # Console handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

auth_logger = get_logger("fast_api_auth.log")

app = FastAPI(title="RabbitMQ")

# create database table 
Base.metadata.create_all(bind=engine)

local_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# create an instance of the database
def get_db():
    db = local_session()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def hello() -> Dict[str, str]: 
    return {"msg": "hello world"}


# create hash for initialization for password and verify it
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_plain_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def authenticate_user(username: str, plain_password: str, db: Session = Depends(get_db)):
    get_user = db.query(User).filter(User.user_name == username).first()
    
    if get_user is None:
        return False

    if not verify_password(plain_password=plain_password, hashed_password=get_user.password_hash):
        return False

    return get_user


def create_access_token(data: dict, expire_delta: timedelta | None = None):
    to_encode = data.copy()
    if expire_delta:
        expire = datetime.now() + expire_delta
    else:
        """put our own default time delta"""
        expire = datetime.now() + timedelta(minutes=15)
    
    print("[before] update:", to_encode)
    to_encode.update(
        {"exp" : expire}
    )
    print("[AFTER] update:", to_encode)
    encoded_jwt = jwt.encode(to_encode, ssl_encryption, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth_2_scheme), db: Session = Depends(get_db)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    
    try:
        payload = jwt.decode(token, ssl_encryption, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credential_exception
        
        token_data = TokenData(username=username)
        
    except InvalidTokenError: 
        raise credential_exception
    
    get_user = db.query(User).filter(User.user_name == token_data.username).first()
    if get_user is None:
        raise credential_exception
    
    return get_user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.status == "not_active":
        raise HTTPException(status_code=400, detail="User is inactive")
    return current_user



ssl_encryption = os.getenv("OPENSSL_kEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # time in minute
auth_logger.info(msg=ssl_encryption)


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> Token:
    user = authenticate_user(
        username=form_data.username, plain_password=form_data.password, db=db
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.user_name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=AddUser)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]











# @app.post(path="/token", response_model=Token)
# async def login_from_access_token(from_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     user = authenticate_user(db=db, username=from_data.username, plain_password=from_data.password)
    
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"}  # SECURITY FIX: Corrected header name
#             )
    
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(data={"sub": user.user_name}, expire_delta=access_token_expires)
#     return {"access_token": access_token, "token_type": "bearer"}


# @app.post("/sign_up", response_model=AddUser)
# def sign_up(response: AddUser, db: Session = Depends(get_db)) -> JSONResponse:
#     create_user = User(
#         user_name=response.user,
#         email=response.email,
#         # initialize the hash password
#         password=hash_plain_password(plain_password=response.password),
#     )
#     db.add(create_user)
#     db.commit()
    
#     return JSONResponse(
#         status_code=201,
#         content={
#             "user": create_user.user_name,
#             "email": create_user.email,
#             "password": create_user.password,
#             "verify_password": verify_password(plain_password=response.password, hashed_password=create_user.password),
#             "message": "User has been created successfully."
#         }
#     )




if __name__ == "__main__":
    uvicorn.run(app=app, port=8000, host="0.0.0.0")










