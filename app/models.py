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