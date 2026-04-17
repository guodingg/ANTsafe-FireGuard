"""
POC API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.vuln import POC
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/pocs", tags=["POC管理"])

@router.get("/")
async def list_pocs(
    skip: int = 0,
    limit: int = 100,
    source: str = None,
    severity: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """POC列表"""
    query = select(POC).order_by(POC.use_count.desc())
    
    if source:
        query = query.where(POC.source == source)
    if severity:
        query = query.where(POC.severity == severity)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    pocs = result.scalars().all()
    
    return pocs

@router.get("/{poc_id}")
async def get_poc(
    poc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取POC详情"""
    result = await db.execute(select(POC).where(POC.id == poc_id))
    poc = result.scalar_one_or_none()
    
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")
    
    return poc

@router.get("/templates/{source}")
async def get_poc_templates(
    source: str,
    current_user: User = Depends(get_current_user)
):
    """获取POC模板列表"""
    # TODO: 从Nuclei/Goby等获取模板
    return {"templates": [], "count": 0}
