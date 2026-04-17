"""
数据库初始化脚本
"""

import asyncio
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from secscan.database import init_db, async_session_maker
from secscan.models.user import User, UserRole, UserStatus
from secscan.core.auth import hash_password

async def create_admin_user():
    """创建默认管理员用户"""
    async with async_session_maker() as session:
        from sqlalchemy import select
        
        # 检查是否已存在admin用户
        result = await session.execute(
            select(User).where(User.username == "admin")
        )
        existing_admin = result.scalar_one_or_none()
        
        if not existing_admin:
            admin = User(
                username="admin",
                email="admin@mayisafe.cn",
                password_hash=hash_password("admin123"),
                role=UserRole.ADMIN,
                status=UserStatus.ACTIVE
            )
            session.add(admin)
            await session.commit()
            print("✓ 管理员用户已创建: admin / admin123")
        else:
            print("ℹ 管理员用户已存在")

async def main():
    print("正在初始化数据库...")
    
    # 创建表
    await init_db()
    print("✓ 数据库表已创建")
    
    # 创建管理员用户
    await create_admin_user()
    
    print("\n数据库初始化完成!")

if __name__ == "__main__":
    asyncio.run(main())
