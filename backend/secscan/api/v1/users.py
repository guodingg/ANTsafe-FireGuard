"""
用户管理API
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List

from secscan.database import get_db
from secscan.models.user import User, UserRole, UserStatus
from secscan.schemas.user import UserCreate, UserUpdate, UserInDB, UserPasswordUpdate
from secscan.core.auth import hash_password, verify_password
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/users", tags=["用户管理"])

def require_admin(current_user: User = Depends(get_current_user)):
    """要求管理员权限"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return current_user

@router.get("/", response_model=List[UserInDB])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """用户列表"""
    result = await db.execute(
        select(User).offset(skip).limit(limit).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    return users

@router.get("/{user_id}", response_model=UserInDB)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取用户详情"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    return user

@router.post("/", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """创建用户"""
    # 检查用户名是否存在
    result = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 创建用户
    user = User(
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone,
        password_hash=hash_password(user_data.password),
        role=user_data.role
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return user

@router.put("/{user_id}", response_model=UserInDB)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """更新用户"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 更新字段
    update_data = user_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    
    await db.commit()
    await db.refresh(user)
    
    return user

@router.put("/{user_id}/password")
async def change_password(
    user_id: int,
    data: UserPasswordUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """修改密码"""
    # 只有管理员或本人可以修改
    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="权限不足")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 验证旧密码（如果不是管理员）
    if current_user.role != UserRole.ADMIN:
        if not verify_password(data.old_password, user.password_hash):
            raise HTTPException(status_code=400, detail="旧密码错误")
    
    # 设置新密码
    user.password_hash = hash_password(data.new_password)
    await db.commit()
    
    return {"message": "密码修改成功"}

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """删除用户"""
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    await db.delete(user)
    await db.commit()
    
    return {"message": "用户已删除"}
