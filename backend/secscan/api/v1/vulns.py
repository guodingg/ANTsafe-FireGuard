"""
漏洞API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.vuln import Vulnerability, VulnStatus
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/vulns", tags=["漏洞管理"])

@router.get("/")
async def list_vulns(
    skip: int = 0,
    limit: int = 100,
    task_id: int = None,
    severity: str = None,
    status: VulnStatus = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """漏洞列表"""
    query = select(Vulnerability).order_by(Vulnerability.created_at.desc())
    
    if task_id:
        query = query.where(Vulnerability.task_id == task_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()
    
    return vulns

@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取漏洞详情"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    return vuln

@router.put("/{vuln_id}/verify")
async def verify_vuln(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """验证漏洞"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    vuln.verified = True
    vuln.status = VulnStatus.VERIFIED
    await db.commit()
    
    return {"message": "漏洞已验证"}

@router.put("/{vuln_id}/fix")
async def fix_vuln(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """标记漏洞已修复"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    vuln.status = VulnStatus.FIXED
    vuln.verified = False
    await db.commit()
    
    return {"message": "漏洞已修复"}

@router.put("/{vuln_id}/false-positive")
async def mark_false_positive(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """标记为误报"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    vuln.is_false_positive = True
    vuln.status = VulnStatus.FALSE_POSITIVE
    await db.commit()
    
    return {"message": "已标记为误报"}
