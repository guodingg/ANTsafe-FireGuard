"""
Xray POC API
"""

from fastapi import APIRouter, Depends, BackgroundTasks, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
import zipfile
import io

from secscan.models.user import User
from secscan.api.v1.auth import get_current_user
from secscan.services.xray_service import XrayService

router = APIRouter(prefix="/xray", tags=["Xray POC"])

class XrayUpdateResponse(BaseModel):
    success: bool
    message: str
    total: int
    downloaded: int
    failed: int
    categories: Dict[str, int]

@router.get("/stats")
async def get_xray_stats(
    current_user: User = Depends(get_current_user)
):
    """获取Xray POC统计"""
    stats = XrayService.get_stats()
    return stats

@router.get("/list")
async def list_xray_pocs(
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    """获取Xray POC列表"""
    pocs = XrayService._get_local_pocs()
    
    # 按类别过滤
    if category:
        filtered = []
        for p in pocs:
            cat = XrayService._guess_category(p['name'])
            if cat == category:
                filtered.append(p)
        pocs = filtered
    
    total = len(pocs)
    pocs = pocs[skip:skip+limit]
    
    return {
        "pocs": pocs,
        "total": total,
        "skip": skip,
        "limit": limit
    }

@router.post("/update")
async def update_xray_pocs(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """在线更新Xray POC"""
    result = await XrayService.update_all_pocs()
    
    return {
        "success": result['success'],
        "message": f"更新完成: 下载{result['downloaded']}个, 失败{result['failed']}个",
        "total": result['total'],
        "downloaded": result['downloaded'],
        "failed": result['failed'],
        "categories": result['categories'],
        "errors": result['errors'][:10] if result['errors'] else []
    }

@router.post("/update/offline")
async def update_xray_offline(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """离线更新Xray POC"""
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="只支持ZIP格式")
    
    content = await file.read()
    
    result = await XrayService.import_from_zip(content)
    
    if result['success']:
        return {
            "success": True,
            "message": f"离线更新成功: 导入{result['imported']}个POC",
            "imported": result['imported'],
            "failed": result['failed'],
            "errors": result['errors']
        }
    else:
        raise HTTPException(status_code=500, detail=result['errors'][0] if result['errors'] else "更新失败")

@router.get("/categories")
async def get_xray_categories(
    current_user: User = Depends(get_current_user)
):
    """获取POC分类统计"""
    stats = XrayService.get_stats()
    return {
        "categories": stats['categories'],
        "total": stats['total']
    }
