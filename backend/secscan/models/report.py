"""
报告和日志模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, BigInteger, DateTime, ForeignKey, Enum
from secscan.database import Base
import enum

class ReportType(str, enum.Enum):
    MARKDOWN = "markdown"
    WORD = "word"
    EXCEL = "excel"
    PDF = "pdf"
    HTML = "html"

class Report(Base):
    """报告表"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    name = Column(String(256), nullable=False)
    type = Column(Enum(ReportType), default=ReportType.MARKDOWN)
    content = Column(Text)
    file_path = Column(String(512))
    file_size = Column(BigInteger)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Report {self.name}>"


class AuditLog(Base):
    """审计日志表"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    action = Column(String(64), nullable=False)
    module = Column(String(64), nullable=False)
    resource = Column(String(128))
    
    method = Column(String(16))
    path = Column(String(512))
    ip = Column(String(64))
    user_agent = Column(Text)
    request_id = Column(String(64))
    
    duration = Column(Integer)  # 毫秒
    status_code = Column(Integer)
    error = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<AuditLog {self.action} by user_id={self.user_id}>"
