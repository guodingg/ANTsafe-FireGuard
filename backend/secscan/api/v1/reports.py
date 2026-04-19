"""
报告API - 支持多种格式导出
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
import io

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.report import Report, ReportType
from secscan.models.scan import ScanTask
from secscan.api.v1.auth import get_current_user
from secscan.services.report_generator import ReportGenerator

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
    
    return [
        {
            "id": r.id,
            "name": r.name,
            "type": r.type.value,
            "file_size": r.file_size,
            "task_id": r.task_id,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in reports
    ]

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
    
    return {
        "id": report.id,
        "name": report.name,
        "type": report.type.value,
        "content": report.content,
        "file_size": report.file_size,
        "task_id": report.task_id,
        "created_at": report.created_at.isoformat() if report.created_at else None
    }

@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """下载报告"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    
    # 根据类型设置媒体类型
    media_types = {
        "markdown": "text/markdown",
        "html": "text/html",
        "pdf": "application/pdf",
        "word": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }
    
    # 文件扩展名
    extensions = {
        "markdown": ".md",
        "html": ".html",
        "pdf": ".pdf",
        "word": ".docx",
        "excel": ".xlsx"
    }
    
    media_type = media_types.get(report.type.value, "application/octet-stream")
    extension = extensions.get(report.type.value, "")
    
    filename = f"{report.name}{extension}"
    
    # 对于PDF/Word/Excel，内容是bytes
    if isinstance(report.content, bytes):
        content = report.content
    else:
        content = report.content.encode('utf-8')
    
    # URL编码文件名，避免中文编码问题
    from urllib.parse import quote
    encoded_filename = quote(filename)
    
    return StreamingResponse(
        io.BytesIO(content),
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"
        }
    )

@router.post("/generate")
async def generate_report(
    task_id: int,
    report_type: str = "markdown",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """生成报告"""
    # 验证任务存在
    task_result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = task_result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != "completed":
        raise HTTPException(status_code=400, detail="任务未完成，无法生成报告")
    
    # 解析报告类型
    try:
        report_type_enum = ReportType(report_type.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"不支持的报告格式: {report_type}")
    
    try:
        # 生成报告
        report = await ReportGenerator.generate_report(
            task_id=task_id,
            user_id=current_user.id,
            report_type=report_type_enum
        )
        
        return {
            "id": report.id,
            "name": report.name,
            "type": report.type.value,
            "file_size": report.file_size,
            "message": "报告生成成功"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"报告生成失败: {str(e)}")

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
    
    # 检查权限
    if report.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="权限不足")
    
    await db.delete(report)
    await db.commit()
    
    return {"message": "报告已删除"}

@router.get("/types/list")
async def list_report_types():
    """获取支持的报告类型列表"""
    return {
        "types": [
            {"value": "markdown", "label": "Markdown", "description": "纯文本格式，适合导入其他系统"},
            {"value": "html", "label": "HTML", "description": "网页格式，适合在线查看"},
            {"value": "pdf", "label": "PDF", "description": "Adobe PDF格式，适合打印和分享"},
            {"value": "word", "label": "Word", "description": "Microsoft Word格式，适合编辑"},
            {"value": "excel", "label": "Excel", "description": "Microsoft Excel格式，适合数据分析"}
        ]
    }
