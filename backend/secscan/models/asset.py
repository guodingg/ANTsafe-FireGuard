"""
资产模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime, ForeignKey, Enum
from secscan.database import Base
import enum

class AssetStatus(str, enum.Enum):
    ALIVE = "alive"           # 存活
    DOWN = "down"             # 离线
    UNKNOWN = "unknown"       # 未知

class Asset(Base):
    """资产表"""
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    ip = Column(String(64), nullable=False, index=True)
    hostname = Column(String(256))
    port = Column(Integer)
    protocol = Column(String(32))
    service = Column(String(128))
    product = Column(String(256))
    version = Column(String(128))
    os = Column(String(128))
    banner = Column(Text)
    
    # Web指纹
    is_web = Column(Boolean, default=False)
    web_title = Column(String(256))
    web_fingerprint = Column(JSON)
    
    status = Column(Enum(AssetStatus), default=AssetStatus.ALIVE)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Asset {self.ip}:{self.port}>"
