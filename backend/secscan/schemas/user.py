"""
Pydantic模型 - 用户
"""

from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from secscan.models.user import UserRole, UserStatus

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class UserCreate(UserBase):
    password: str
    role: UserRole = UserRole.USER

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None

class UserPasswordUpdate(BaseModel):
    old_password: str
    new_password: str

class UserInDB(UserBase):
    id: int
    role: UserRole
    status: UserStatus
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[int] = None
