from pydantic import BaseModel


class AddUser(BaseModel):
    user: str
    email: str
    password: str

    class Config:
        from_attributes  = True


class Login(BaseModel):
    email: str
    password: str

    class Config:
        from_attributes  = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserInDB(BaseModel):
    hash_password: str
