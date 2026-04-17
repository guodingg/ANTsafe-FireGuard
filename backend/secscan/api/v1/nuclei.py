"""
Nuclei API - 漏洞库管理
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel
from typing import List, Optional

from secscan.models.user import User
from secscan.api.v1.auth import get_current_user
from secscan.services.nuclei_service import NucleiService

router = APIRouter(prefix="/nuclei", tags=["Nuclei漏洞库"])

class TemplateUpdateResponse(BaseModel):
    success: bool
    message: str
    templates_count: int
    templates_dir: str

@router.get("/templates")
async def get_templates():
    """获取模板库概览"""
    templates = NucleiService.get_templates()
    return templates

@router.post("/templates/update")
async def update_templates(background_tasks: BackgroundTasks):
    """更新Nuclei模板库（后台执行）"""
    # 在后台执行更新
    result = await NucleiService.update_templates()
    return result

@router.get("/templates/search")
async def search_templates(
    keyword: str = Query(None, description="搜索关键词"),
    severity: str = Query(None, description="严重性过滤"),
    category: str = Query(None, description="分类过滤"),
    tags: str = Query(None, description="标签过滤，逗号分隔"),
    limit: int = Query(100, ge=1, le=500)
):
    """搜索模板"""
    tag_list = tags.split(",") if tags else None
    
    results = await NucleiService.search_templates(
        keyword=keyword,
        severity=severity,
        category=category,
        tags=tag_list,
        limit=limit
    )
    
    return {"results": results, "count": len(results)}

@router.get("/templates/{template_id}")
async def get_template_detail(template_id: str):
    """获取模板详情"""
    template = NucleiService.get_template_detail(template_id)
    
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")
    
    return template

@router.get("/categories")
async def get_categories():
    """获取所有分类"""
    templates = NucleiService.get_templates()
    categories = templates.get("templates_by_category", {})
    return {"categories": categories}
