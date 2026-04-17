"""
Pydantic模型 - 扫描任务
"""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from secscan.models.scan import TaskType, TaskStatus

class ScanTaskBase(BaseModel):
    name: str
    target: str
    scan_type: TaskType
    options: Dict[str, Any] = {}

class ScanTaskCreate(ScanTaskBase):
    pass

class ScanTaskUpdate(BaseModel):
    name: Optional[str] = None
    options: Optional[Dict[str, Any]] = None
    status: Optional[TaskStatus] = None

class ScanTaskInDB(ScanTaskBase):
    id: int
    user_id: int
    status: TaskStatus
    progress: int
    total_hosts: int
    scanned_hosts: int
    found_vulns: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class ScanTaskProgress(BaseModel):
    task_id: int
    progress: int
    status: TaskStatus
    scanned_hosts: int
    found_vulns: int
    message: Optional[str] = None

class ScanResultSummary(BaseModel):
    total_hosts: int
    alive_hosts: int
    vulnerabilities: Dict[str, int]  # {"critical": 5, "high": 10, ...}
    assets_by_service: Dict[str, int]
