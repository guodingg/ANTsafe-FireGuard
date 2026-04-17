"""
用户模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from secscan.database import Base
import enum

class UserRole(str, enum.Enum):
    ADMIN = "admin"           # 管理员
    OPERATOR = "operator"     # 操作员
    AUDITOR = "auditor"       # 审计员
    USER = "user"             # 普通用户

class UserStatus(str, enum.Enum):
    ACTIVE = "active"         # 正常
    DISABLED = "disabled"     # 禁用
    LOCKED = "locked"          # 锁定

class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True)
    phone = Column(String(32))
    password_hash = Column(String(256), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE)
    last_login = Column(DateTime)
    login_ip = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<User {self.username}>"
