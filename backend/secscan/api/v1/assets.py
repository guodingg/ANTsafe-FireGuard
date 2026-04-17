"""
资产API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.asset import Asset, AssetStatus
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/assets", tags=["资产管理"])

@router.get("/")
async def list_assets(
    skip: int = 0,
    limit: int = 100,
    task_id: int = None,
    status: AssetStatus = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """资产列表"""
    query = select(Asset).order_by(Asset.created_at.desc())
    
    if task_id:
        query = query.where(Asset.task_id == task_id)
    if status:
        query = query.where(Asset.status == status)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    assets = result.scalars().all()
    
    return assets

@router.get("/{asset_id}")
async def get_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取资产详情"""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    
    return asset

@router.get("/stats/summary")
async def get_asset_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """资产统计"""
    from sqlalchemy import func
    
    # 总资产数
    total_result = await db.execute(select(func.count(Asset.id)))
    total = total_result.scalar()
    
    # 存活资产
    alive_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == AssetStatus.ALIVE)
    )
    alive = alive_result.scalar()
    
    # 服务分布
    service_result = await db.execute(
        select(Asset.service, func.count(Asset.id))
        .group_by(Asset.service)
        .order_by(func.count(Asset.id).desc())
        .limit(10)
    )
    services = [{"name": r[0], "count": r[1]} for r in service_result.all()]
    
    return {"total": total, "alive": alive, "services": services}
