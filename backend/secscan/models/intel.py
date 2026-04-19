"""
漏洞情报数据库模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime, Float, Index, Enum as SAEnum
from secscan.database import Base
import enum


class IntelSource(str, enum.Enum):
    CISA_KEV = "cisa_kev"          # CISA 已知被利用漏洞目录
    GITHUB_ADVISORY = "github_advisory"  # GitHub 安全公告
    NVD_RSS = "nvd_rss"            # NVD RSS源
    NVD_API = "nvd_api"            # NVD API (需要key)
    OSCS = "oscs"                  # OSCS开源安全情报


class IntelSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IntelVuln(Base):
    """漏洞情报表"""
    __tablename__ = "intel_vulns"

    id = Column(Integer, primary_key=True, index=True)
    
    # 基础信息
    cve_id = Column(String(32), unique=True, index=True, nullable=False)
    vulnerability_name = Column(String(512))
    
    # 来源信息
    source = Column(String(32), nullable=False)  # cisa_kev, github_advisory, nvd_rss
    source_url = Column(String(512))
    original_severity = Column(String(32))  # 原始来源的评级
    
    # 危害评级
    severity = Column(String(16), nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    
    # 产品信息
    vendor = Column(String(256))
    product = Column(String(256), index=True)
    product_version = Column(String(128))  # 受影响版本
    
    # 漏洞详情
    description = Column(Text)
    cwe_ids = Column(JSON, default=[])  # ["CWE-20", "CWE-94"]
    
    # 利用状态
    is_known_exploited = Column(Boolean, default=False)
    is_ransomware_related = Column(String(32))  # Unknown / Yes / No
    
    # POC状态
    is_poc_public = Column(Boolean, default=False)
    poc_reference = Column(String(512))
    
    # RCE能力
    is_rce = Column(Boolean, default=False)
    
    # 时间
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    last_fetched = Column(DateTime, default=datetime.utcnow)
    
    # 关联
    tags = Column(JSON, default=[])  # ["remote-code-execution", "privilege-escalation"]
    references = Column(JSON, default=[])  # [{title, url}]
    
    # 修复信息
    remediation = Column(Text)
    remediation_url = Column(String(512))
    due_date = Column(DateTime, nullable=True)  # CISA修复期限
    
    # 状态
    is_active = Column(Boolean, default=True)  # 是否仍有效
    is_fresh = Column(Boolean, default=True)   # 是否新收录
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 索引
    __table_args__ = (
        Index('ix_intel_vulns_severity_published', 'severity', 'published_date'),
        Index('ix_intel_vulns_product_severity', 'product', 'severity'),
        Index('ix_intel_vulns_is_known_exploited', 'is_known_exploited'),
        Index('ix_intel_vulns_is_rce', 'is_rce'),
        Index('ix_intel_vulns_last_fetched', 'last_fetched'),
    )

    def __repr__(self):
        return f"<IntelVuln {self.cve_id} [{self.severity}]>"


class IntelFetchLog(Base):
    """情报获取日志"""
    __tablename__ = "intel_fetch_logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(32), nullable=False)
    fetch_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String(16))  # success, failed, partial
    items_fetched = Column(Integer, default=0)
    new_items = Column(Integer, default=0)
    errors = Column(Text)
    duration_ms = Column(Integer)

    def __repr__(self):
        return f"<IntelFetchLog {self.source} {self.fetch_time}>"
