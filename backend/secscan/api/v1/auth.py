"""
认证API
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from secscan.database import get_db
from secscan.models.user import User
from secscan.schemas.user import UserLogin, Token, UserInDB
from secscan.core.auth import verify_password, create_access_token, hash_password

router = APIRouter(prefix="/auth", tags=["认证"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """获取当前用户"""
    from secscan.core.auth import decode_access_token
    
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据"
        )
    
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据"
        )
    
    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在"
        )
    
    return user

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """用户登录"""
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    
    # 更新登录信息
    user.last_login = datetime.utcnow()
    await db.commit()
    
    # 创建token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login/json", response_model=Token)
async def login_json(
    data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """JSON格式登录"""
    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    
    # 更新登录信息
    user.last_login = datetime.utcnow()
    await db.commit()
    
    # 创建token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserInDB)
async def get_me(current_user: User = Depends(get_current_user)):
    """获取当前用户信息"""
    return current_user

@router.post("/logout")
async def logout():
    """登出（前端删除token即可）"""
    return {"message": "登出成功"}
