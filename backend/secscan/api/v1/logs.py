"""
日志API
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime, timedelta

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.report import AuditLog
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/logs", tags=["日志审计"])

@router.get("/")
async def list_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: int = None,
    module: str = None,
    action: str = None,
    start_date: datetime = None,
    end_date: datetime = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """日志列表"""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if module:
        query = query.where(AuditLog.module == module)
    if action:
        query = query.where(AuditLog.action.like(f"%{action}%"))
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs

@router.get("/stats")
async def get_log_stats(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """日志统计"""
    from sqlalchemy import func
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # 按模块统计
    module_result = await db.execute(
        select(AuditLog.module, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start_date)
        .group_by(AuditLog.module)
    )
    by_module = [{"module": r[0], "count": r[1]} for r in module_result.all()]
    
    # 按操作统计
    action_result = await db.execute(
        select(AuditLog.action, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start_date)
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
    )
    by_action = [{"action": r[0], "count": r[1]} for r in action_result.all()]
    
    return {"by_module": by_module, "by_action": by_action}
