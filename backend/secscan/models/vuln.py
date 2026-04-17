"""
漏洞模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime, ForeignKey, Float, Enum
from secscan.database import Base
import enum

class Severity(str, enum.Enum):
    CRITICAL = "critical"     # 严重
    HIGH = "high"            # 高危
    MEDIUM = "medium"        # 中危
    LOW = "low"              # 低危
    INFO = "info"            # 信息

class VulnStatus(str, enum.Enum):
    UNVERIFIED = "unverified"   # 待验证
    VERIFIED = "verified"       # 已验证
    FALSE_POSITIVE = "false_positive"  # 误报
    FIXED = "fixed"             # 已修复

class Vulnerability(Base):
    """漏洞表"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    poc_id = Column(Integer, ForeignKey("pocs.id"))
    
    name = Column(String(256), nullable=False)
    cve = Column(String(32))  # CVE编号
    cwe = Column(String(32)) # CWE编号
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Float)
    
    description = Column(Text)
    payload = Column(Text)
    request = Column(Text)
    response = Column(Text)
    remediation = Column(Text)
    
    status = Column(Enum(VulnStatus), default=VulnStatus.UNVERIFIED)
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    ai_analyzed = Column(Boolean, default=False)
    ai_analysis = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Vulnerability {self.name}>"


class POC(Base):
    """POC表"""
    __tablename__ = "pocs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    name = Column(String(256), nullable=False)
    name_cn = Column(String(256))
    source = Column(String(32), nullable=False)  # nuclei/msf/goby/xray/custom
    source_id = Column(String(128))
    
    severity = Column(Enum(Severity))
    cvss = Column(Float)
    cve = Column(String(32))
    cwe = Column(String(32))
    category = Column(String(64))
    tags = Column(JSON, default=[])
    
    protocol = Column(String(32))  # http/tcp/smb/dns/ftp
    template = Column(Text)  # YAML for Nuclei
    
    ai_generated = Column(Boolean, default=False)
    ai_prompt = Column(Text)
    
    use_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<POC {self.name}>"
