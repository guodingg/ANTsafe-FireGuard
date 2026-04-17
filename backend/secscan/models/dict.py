"""
自定义字典模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum
from secscan.database import Base
import enum

class DictType(str, enum.Enum):
    SUBDOMAIN = "subdomain"       # 子域名典
    PORT = "port"                 # 端口字典
    PATH = "path"                 # 路径字典
    USER_AGENT = "user_agent"     # UA字典
    CUSTOM = "custom"             # 自定义

class WordDict(Base):
    """字典表"""
    __tablename__ = "word_dicts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    type = Column(Enum(DictType), nullable=False)
    
    # 字典内容
    content = Column(Text)  # 逗号/换行分隔的词列表
    count = Column(Integer, default=0)  # 词条数量
    
    # 来源
    source = Column(String(32), default="custom")  # custom/system/ai
    
    # 配置
    is_default = Column(Boolean, default=False)  # 是否默认字典
    is_active = Column(Boolean, default=True)     # 是否启用
    
    description = Column(String(512))
    created_by = Column(Integer)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<WordDict {self.name} ({self.type})>"
