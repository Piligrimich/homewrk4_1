from datetime import datetime

from pydantic import BaseModel, EmailStr

__all__ = (
    "UserCreate",
    "UserLogin",
)


class UserBase(BaseModel):
    username: str
    password: str


class UserCreate(UserBase):
    email: EmailStr


class UserLogin(UserBase):
    ...
