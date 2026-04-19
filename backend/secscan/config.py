"""
SecScan AI - 蚂蚁安全风险评估系统
配置文件
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    """应用配置"""
    
    # 应用信息
    APP_NAME: str = "蚂蚁安全风险评估系统"
    APP_NAME_EN: str = "ANTsafe System"
    VERSION: str = "1.0.0"
    COPYRIGHT: str = "© 2024 蚂蚁安全 www.mayisafe.cn"
    
    # 服务器配置
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # 数据库配置
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/secscan.db"
    
    # JWT配置
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7天
    
    # Redis配置
    REDIS_URL: str = "redis://localhost:6379"
    
    # AI配置
    AI_PROVIDER: str = "kimi"
    AI_API_KEY: str = ""
    AI_MODEL: str = "moonshot-v1-8k"
    AI_TIMEOUT: int = 30
    
    # 扫描配置
    MAX_CONCURRENT_TASKS: int = 5
    SCAN_TIMEOUT: int = 3600  # 1小时
    
    # CORS配置
    CORS_ORIGINS: list = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
