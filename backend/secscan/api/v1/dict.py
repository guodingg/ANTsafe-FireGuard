"""
自定义字典API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel
import io

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.dict import WordDict, DictType
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/dicts", tags=["自定义字典"])

class DictCreate(BaseModel):
    name: str
    type: DictType
    content: str
    description: Optional[str] = None
    is_default: bool = False

class DictUpdate(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None

@router.get("/")
async def list_dicts(
    dict_type: DictType = None,
    source: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """字典列表"""
    query = select(WordDict).order_by(WordDict.created_at.desc())
    
    if dict_type:
        query = query.where(WordDict.type == dict_type)
    if source:
        query = query.where(WordDict.source == source)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    dicts = result.scalars().all()
    
    return [
        {
            "id": d.id,
            "name": d.name,
            "type": d.type.value,
            "count": d.count,
            "source": d.source,
            "is_default": d.is_default,
            "is_active": d.is_active,
            "description": d.description,
            "created_at": d.created_at.isoformat() if d.created_at else None
        }
        for d in dicts
    ]

@router.get("/{dict_id}")
async def get_dict(
    dict_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取字典详情"""
    result = await db.execute(select(WordDict).where(WordDict.id == dict_id))
    word_dict = result.scalar_one_or_none()
    
    if not word_dict:
        raise HTTPException(status_code=404, detail="字典不存在")
    
    return {
        "id": word_dict.id,
        "name": word_dict.name,
        "type": word_dict.type.value,
        "content": word_dict.content,
        "count": word_dict.count,
        "source": word_dict.source,
        "is_default": word_dict.is_default,
        "is_active": word_dict.is_active,
        "description": word_dict.description,
        "created_at": word_dict.created_at.isoformat() if word_dict.created_at else None
    }

@router.get("/{dict_id}/words")
async def get_dict_words(
    dict_id: int,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取字典词列表"""
    result = await db.execute(select(WordDict).where(WordDict.id == dict_id))
    word_dict = result.scalar_one_or_none()
    
    if not word_dict:
        raise HTTPException(status_code=404, detail="字典不存在")
    
    # 解析词列表
    words = []
    if word_dict.content:
        # 支持逗号、换行、分号分隔
        for separator in [',', '\n', ';']:
            if separator in word_dict.content:
                words = [w.strip() for w in word_dict.content.split(separator) if w.strip()]
                break
        else:
            words = [word_dict.content.strip()] if word_dict.content.strip() else []
    
    total = len(words)
    paginated_words = words[offset:offset+limit]
    
    return {
        "words": paginated_words,
        "total": total,
        "offset": offset,
        "limit": limit
    }

@router.post("/")
async def create_dict(
    data: DictCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """创建字典"""
    # 计算词条数量
    word_count = len([w for w in data.content.replace(',', '\n').split('\n') if w.strip()])
    
    # 如果设为默认，取消其他默认
    if data.is_default:
        await db.execute(
            select(WordDict)
            .where(WordDict.type == data.type, WordDict.is_default == True)
            .update({"is_default": False})
        )
    
    word_dict = WordDict(
        name=data.name,
        type=data.type,
        content=data.content,
        count=word_count,
        source="custom",
        is_default=data.is_default,
        description=data.description,
        created_by=current_user.id
    )
    
    db.add(word_dict)
    await db.commit()
    await db.refresh(word_dict)
    
    return {
        "id": word_dict.id,
        "name": word_dict.name,
        "count": word_dict.count,
        "message": "字典创建成功"
    }

@router.put("/{dict_id}")
async def update_dict(
    dict_id: int,
    data: DictUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """更新字典"""
    result = await db.execute(select(WordDict).where(WordDict.id == dict_id))
    word_dict = result.scalar_one_or_none()
    
    if not word_dict:
        raise HTTPException(status_code=404, detail="字典不存在")
    
    if word_dict.source == "system":
        raise HTTPException(status_code=400, detail="系统字典不可修改")
    
    # 更新字段
    if data.name is not None:
        word_dict.name = data.name
    if data.content is not None:
        word_dict.content = data.content
        word_dict.count = len([w for w in data.content.replace(',', '\n').split('\n') if w.strip()])
    if data.description is not None:
        word_dict.description = data.description
    if data.is_default is not None:
        if data.is_default:
            await db.execute(
                select(WordDict)
                .where(WordDict.type == word_dict.type, WordDict.is_default == True)
                .update({"is_default": False})
            )
        word_dict.is_default = data.is_default
    if data.is_active is not None:
        word_dict.is_active = data.is_active
    
    await db.commit()
    
    return {"message": "字典更新成功"}

@router.delete("/{dict_id}")
async def delete_dict(
    dict_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """删除字典"""
    result = await db.execute(select(WordDict).where(WordDict.id == dict_id))
    word_dict = result.scalar_one_or_none()
    
    if not word_dict:
        raise HTTPException(status_code=404, detail="字典不存在")
    
    if word_dict.source == "system":
        raise HTTPException(status_code=400, detail="系统字典不可删除")
    
    await db.delete(word_dict)
    await db.commit()
    
    return {"message": "字典已删除"}

@router.post("/import/txt")
async def import_dict_txt(
    file: UploadFile = File(...),
    dict_type: DictType = DictType.CUSTOM,
    name: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """从文本文件导入字典"""
    if not file.filename.endswith('.txt'):
        raise HTTPException(status_code=400, detail="只支持TXT格式")
    
    content = await file.read()
    text = content.decode('utf-8')
    
    # 统计词条
    words = [w.strip() for w in text.replace(',', '\n').split('\n') if w.strip()]
    word_count = len(words)
    
    word_dict = WordDict(
        name=name or file.filename.replace('.txt', ''),
        type=dict_type,
        content=text,
        count=word_count,
        source="custom",
        description=f"从 {file.filename} 导入",
        created_by=current_user.id
    )
    
    db.add(word_dict)
    await db.commit()
    await db.refresh(word_dict)
    
    return {
        "id": word_dict.id,
        "name": word_dict.name,
        "count": word_dict.count,
        "message": f"导入成功，共 {word_dict.count} 个词条"
    }

@router.post("/preset")
async def create_preset_dicts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """创建预设字典"""
    presets = [
        {
            "name": "常用子域名",
            "type": DictType.SUBDOMAIN,
            "content": "www,mail,ftp,admin,blog,dev,test,api,backup,staging,shop,shopify,crm,erp,oa,wiki,git,jenkins,docker,k8s,kubernetes",
            "description": "常用子域名列表"
        },
        {
            "name": "常见端口",
            "type": DictType.PORT,
            "content": "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017",
            "description": "常见服务端口"
        },
        {
            "name": "Web敏感路径",
            "type": DictType.PATH,
            "content": "admin,login,wp-admin,phpmyadmin,admin.php,login.php,backup,backup.zip,.git/config,.env,swagger,api-docs,console",
            "description": "Web敏感路径"
        },
        {
            "name": "常用User-Agent",
            "type": DictType.USER_AGENT,
            "content": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36,Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15,curl/7.68.0,python-requests/2.25.1",
            "description": "常用User-Agent"
        }
    ]
    
    created = []
    for preset in presets:
        word_dict = WordDict(
            name=preset["name"],
            type=preset["type"],
            content=preset["content"],
            count=len(preset["content"].split(',')),
            source="system",
            is_default=True,
            description=preset["description"],
            created_by=current_user.id
        )
        db.add(word_dict)
        created.append(preset["name"])
    
    await db.commit()
    
    return {
        "message": "预设字典创建成功",
        "created": created
    }
