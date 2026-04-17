"""
报告API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.report import Report, ReportType
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/reports", tags=["报告管理"])

@router.get("/")
async def list_reports(
    skip: int = 0,
    limit: int = 100,
    task_id: int = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """报告列表"""
    query = select(Report).order_by(Report.created_at.desc())
    
    if task_id:
        query = query.where(Report.task_id == task_id)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()
    
    return reports

@router.get("/{report_id}")
async def get_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取报告详情"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    
    return report

@router.post("/generate")
async def generate_report(
    task_id: int,
    report_type: ReportType = ReportType.MARKDOWN,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """生成报告"""
    # TODO: 实现报告生成逻辑
    return {"message": "报告生成中", "task_id": task_id}

@router.delete("/{report_id}")
async def delete_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """删除报告"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    
    await db.delete(report)
    await db.commit()
    
    return {"message": "报告已删除"}
