"""
规则库管理API
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
import yaml
import zipfile
import io
from pathlib import Path
from datetime import datetime

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.vuln import POC
from secscan.api.v1.auth import get_current_user
from secscan.services.nuclei_service import NucleiService

router = APIRouter(prefix="/rules", tags=["规则库管理"])

# 规则统计
class RuleStats(BaseModel):
    nuclei_templates: int = 0
    nuclei_categories: dict = {}
    pocs: int = 0
    pocs_by_source: dict = {}
    custom_rules: int = 0
    last_update: Optional[str] = None
    disk_usage: int = 0

@router.get("/stats")
async def get_rule_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取规则库统计信息"""
    stats = {
        "nuclei_templates": 0,
        "nuclei_categories": {},
        "pocs": 0,
        "pocs_by_source": {},
        "custom_rules": 0,
        "last_update": None,
        "disk_usage": 0
    }
    
    # Nuclei模板统计
    template_dir = Path(NucleiService.get_template_dir())
    if template_dir.exists():
        templates = list(template_dir.rglob("*.yaml"))
        stats["nuclei_templates"] = len(templates)
        
        # 分类统计
        categories = {}
        for t in templates[:500]:
            try:
                with open(t, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'info' in data:
                        cat = data['info'].get('category', 'other')
                        categories[cat] = categories.get(cat, 0) + 1
            except:
                pass
        stats["nuclei_categories"] = categories
        
        # 磁盘使用
        total_size = sum(f.stat().st_size for f in template_dir.rglob('*') if f.is_file())
        stats["disk_usage"] = total_size
    
    # POC统计
    poc_result = await db.execute(select(func.count(POC.id)))
    stats["pocs"] = poc_result.scalar() or 0
    
    # POC按来源统计
    source_result = await db.execute(
        select(POC.source, func.count(POC.id)).group_by(POC.source)
    )
    pocs_by_source = {}
    for row in source_result:
        pocs_by_source[row[0]] = row[1]
    stats["pocs_by_source"] = pocs_by_source
    stats["custom_rules"] = pocs_by_source.get('custom', 0)
    
    return stats

@router.post("/update/online")
async def update_rules_online(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """在线更新规则库（后台执行）"""
    # 这里调用Nuclei更新
    result = await NucleiService.update_templates()
    
    return {
        "success": True,
        "message": "规则库更新任务已启动",
        "details": result
    }

@router.get("/check")
async def check_rule_updates(
    current_user: User = Depends(get_current_user)
):
    """检查规则更新"""
    template_dir = Path(NucleiService.get_template_dir())
    
    info = {
        "local_templates": 0,
        "local_pocs": 0,
        "last_check": datetime.utcnow().isoformat(),
        "update_available": False,
        "message": "请前往蚂蚁安全官网下载最新离线包"
    }
    
    if template_dir.exists():
        info["local_templates"] = len(list(template_dir.rglob("*.yaml")))
    
    return info

@router.post("/update/offline")
async def update_rules_offline(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    离线更新规则库
    支持上传ZIP压缩包（包含Nuclei模板和POC）
    """
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="只支持ZIP格式")
    
    content = await file.read()
    
    result = {
        "success": True,
        "message": "更新成功",
        "details": {
            "nuclei_templates": 0,
            "new_categories": [],
            "pocs": 0,
            "errors": []
        }
    }
    
    try:
        zip_buffer = io.BytesIO(content)
        
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            file_list = zf.namelist()
            
            # 统计Nuclei模板
            yaml_files = [f for f in file_list if f.endswith(('.yaml', '.yml')) and 'nuclei' in f.lower()]
            result["details"]["nuclei_templates"] = len(yaml_files)
            
            # 提取类别信息
            categories = set()
            for yaml_file in yaml_files[:50]:
                try:
                    file_content = zf.read(yaml_file)
                    data = yaml.safe_load(file_content)
                    if data and 'info' in data:
                        cat = data['info'].get('category', 'other')
                        categories.add(cat)
                except:
                    pass
            result["details"]["new_categories"] = list(categories)
            
            # 导入POC
            imported_pocs = 0
            for yaml_file in yaml_files:
                try:
                    file_content = zf.read(yaml_file)
                    poc_data = yaml.safe_load(file_content)
                    
                    if not poc_data or 'info' not in poc_data:
                        continue
                    
                    info = poc_data.get('info', {})
                    
                    # 检查是否已存在
                    existing = await db.execute(
                        select(POC).where(POC.source_id == info.get('name', yaml_file))
                    )
                    if existing.scalar_one_or_none():
                        continue
                    
                    poc = POC(
                        name=info.get('name', yaml_file),
                        name_cn=info.get('name', ''),
                        source='custom',
                        source_id=info.get('name', yaml_file),
                        severity=info.get('severity', 'medium'),
                        cve=info.get('cve-id', ''),
                        cwe=info.get('cwe-id', ''),
                        category=info.get('category', ''),
                        tags=info.get('tags', []),
                        protocol=poc_data.get('network', ''),
                        template=file_content.decode('utf-8'),
                        ai_generated=False
                    )
                    
                    db.add(poc)
                    imported_pocs += 1
                    
                except Exception as e:
                    result["details"]["errors"].append(f"{yaml_file}: {str(e)}")
            
            result["details"]["pocs"] = imported_pocs
            await db.commit()
        
        # 更新Nuclei模板
        template_dir = Path(NucleiService.get_template_dir())
        temp_dir = template_dir.parent / "nuclei-templates-temp"
        
        if temp_dir.exists():
            import shutil
            if template_dir.exists():
                shutil.rmtree(template_dir)
            shutil.move(str(temp_dir), str(template_dir))
        
        return result
        
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的ZIP文件")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新失败: {str(e)}")
