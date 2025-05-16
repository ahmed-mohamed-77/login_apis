
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse


from sqlalchemy.orm import sessionmaker, Session
from jwt.exceptions import InvalidTokenError
from app.database import engine, Base, User
from passlib.context import CryptContext
from app.models import AddUser, Login
from typing import Dict

import pike
import json
import jwt

import uvicorn


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

@app.post("/sign_up", response_model=AddUser)
def sign_up(response: AddUser, db: Session = Depends(get_db)) -> JSONResponse:
    create_user = User(
        user_name=response.user,
        email=response.email,
        # initialize the hash password
        password=pwd_context.hash(response.password),
    )
    db.add(create_user)
    db.commit()
    
    return JSONResponse(
        status_code=201,
        content={
            "user": create_user.user_name,
            "email": create_user.email,
            "password": create_user.password,
            "verify_password": pwd_context.verify(secret=response.password, hash=create_user.password),
            "message": "User has been created successfully."
        }
    )


@app.post("/login", response_model=Login)
async def log_in(response: Login, db: Session=Depends(get_db)):
    get_user = db.query(User).filter(
            User.email == response.email
    ).first()
    
    if not get_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Assuming hashed password is stored in `password_hash`
    if not pwd_context.verify(response.password, get_user.password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    return JSONResponse(
        status_code=200,
        content={
            "message": "Login successful",
            "user": get_user.user_name,
            "email": get_user.email
        }
    )



if __name__ == "__main__":
    uvicorn.run(app=app, port=8000, host="0.0.0.0")










