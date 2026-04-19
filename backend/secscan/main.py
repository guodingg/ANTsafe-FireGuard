"""
SecScan AI - 蚂蚁安全风险评估系统
FastAPI应用入口
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from starlette.middleware.base import BaseHTTPMiddleware
import time
import uuid

from secscan.config import settings
from secscan.database import init_db, async_session_maker
from secscan.api.v1 import (
    auth_router, users_router, scan_router,
    assets_router, vulns_router, pocs_router,
    reports_router, logs_router, ai_router,
    dashboard_router, nuclei_router,
    assistant_router, dict_router, rules_router,
    xray_router, vuln_intel_router
)
from secscan.models.report import AuditLog
from secscan.models.intel import IntelVuln, IntelFetchLog  # noqa: F401 - 确保模型被注册
from sqlalchemy import delete, func
from datetime import datetime, timedelta

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期"""
    # 启动时
    print(f"\n{'='*50}")
    print(f"  {settings.APP_NAME}")
    print(f"  {settings.APP_NAME_EN} v{settings.VERSION}")
    print(f"  {settings.COPYRIGHT}")
    print(f"{'='*50}\n")
    
    # 初始化数据库
    await init_db()
    
    # 启动时后台刷新漏洞情报（不影响API响应）
    import asyncio
    async def startup_intel_refresh():
        try:
            from secscan.services.vuln_intel import get_vuln_intel_service
            service = get_vuln_intel_service()
            # 只在距上次刷新超过30分钟时才刷新
            should_refresh = True
            for src in ["cisa_kev", "github_advisory", "nvd_rss"]:
                last = service.last_fetch_time.get(src)
                if last and (datetime.utcnow() - last).total_seconds() < 1800:
                    should_refresh = False
                    break
            if should_refresh:
                print("[Startup] 后台刷新漏洞情报...")
                asyncio.create_task(service.fetch_all_sources(force=True))
        except Exception as e:
            print(f"[Startup] 漏洞情报刷新失败: {e}")
    
    asyncio.create_task(startup_intel_refresh())
    
    # 清理30天前的日志
    try:
        async with async_session_maker() as db:
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            result = await db.execute(
                delete(AuditLog).where(AuditLog.created_at < cutoff_date)
            )
            await db.commit()
            if result.rowcount > 0:
                print(f"[Cleanup] 已清理 {result.rowcount} 条超过30天的日志")
    except Exception as e:
        print(f"[Cleanup] 清理日志失败: {e}")
    
    yield
    
    # 关闭时
    print("\n正在关闭服务...")

# 创建应用
app = FastAPI(
    title=settings.APP_NAME,
    description="蚂蚁安全风险评估系统 API",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 请求日志中间件 - 仅记录关键用户操作
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    path = request.url.path
    parts = [p for p in path.split("/") if p]
    
    # 判断是否需要记录
    should_log = False
    module = "system"
    action = ""
    
    # 只有 /api/v1 路径才考虑记录
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
        module = parts[2]
        
        # 关键操作 - 用户行为
        if path.endswith("/login"):
            should_log = True
            action = "用户登录"
        elif path.endswith("/logout"):
            should_log = True
            action = "用户登出"
        elif path.endswith("/register"):
            should_log = True
            action = "用户注册"
        elif "/start" in path and request.method == "POST":
            should_log = True
            action = "启动扫描"
        elif "/pause" in path:
            should_log = True
            action = "暂停扫描"
        elif "/resume" in path:
            should_log = True
            action = "恢复扫描"
        elif "/stop" in path or "/cancel" in path:
            should_log = True
            action = "停止扫描"
        elif path.endswith("/tasks") and request.method == "POST":
            should_log = True
            action = "创建任务"
        elif path.endswith("/delete") or request.method == "DELETE":
            should_log = True
            action = "删除资源"
        elif request.method == "POST":
            should_log = True
            action = "创建资源"
        elif request.method == "PUT" or request.method == "PATCH":
            should_log = True
            action = "更新配置"
        
        # 系统错误 - 所有请求都记录
        response = await call_next(request)
        duration = int((time.time() - start_time) * 1000)
        
        if response.status_code >= 400:
            should_log = True
            if not action:
                action = f"系统错误({response.status_code})"
        
        if should_log:
            # 获取用户ID
            user_id = None
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                try:
                    from jose import jwt
                    token = auth_header[7:]
                    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                    user_id = payload.get("sub")
                    if user_id:
                        user_id = int(user_id)
                except:
                    pass
            
            # 保存日志
            try:
                async with async_session_maker() as db:
                    client_ip = request.client.host if request.client else "unknown"
                    
                    audit_log = AuditLog(
                        user_id=user_id,
                        action=action,
                        module=module,
                        resource=path,
                        method=request.method,
                        path=str(request.url),
                        ip=client_ip,
                        user_agent=request.headers.get("user-agent", ""),
                        request_id=request_id,
                        duration=duration,
                        status_code=response.status_code,
                        error=f"HTTP {response.status_code}" if response.status_code >= 400 else None
                    )
                    db.add(audit_log)
                    await db.commit()
            except Exception as e:
                print(f"[AuditLog] Failed: {e}")
    else:
        response = await call_next(request)
    
    return response

# 注册路由
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(vulns_router, prefix="/api/v1")
app.include_router(pocs_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(nuclei_router, prefix="/api/v1")
app.include_router(assistant_router, prefix="/api/v1")
app.include_router(dict_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(xray_router, prefix="/api/v1")
app.include_router(vuln_intel_router, prefix="/api/v1")

@app.get("/")
async def root():
    """根路径"""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": "/docs"
    }

@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "healthy"}

# 全局异常处理
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "服务器内部错误",
            "message": str(exc) if settings.DEBUG else "请联系管理员"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "secscan.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
