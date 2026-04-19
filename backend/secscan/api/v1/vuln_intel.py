"""
漏洞情报API v3
"""

from fastapi import APIRouter, Query, BackgroundTasks
from typing import List, Optional, Dict
from pydantic import BaseModel

from secscan.services.vuln_intel import get_vuln_intel_service

router = APIRouter(prefix="/vuln-intel", tags=["漏洞情报"])


class IntelReference(BaseModel):
    title: str
    url: str


class VulnIntelResponse(BaseModel):
    id: int
    cve_id: str
    vulnerability_name: str
    source: str
    source_url: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    vendor: str
    product: str
    product_version: str
    description: str
    cwe_ids: List[str]
    is_known_exploited: bool
    is_ransomware_related: str
    is_poc_public: bool
    is_rce: bool
    published_date: Optional[str]
    last_modified: Optional[str]
    last_fetched: Optional[str]
    tags: List[str]
    references: List[Dict]
    remediation: str
    remediation_url: str
    due_date: Optional[str]


class VulnIntelListResponse(BaseModel):
    total: int
    items: List[VulnIntelResponse]
    stats: dict
    sources: List[str] = []  # 兼容前端


class IntelStatsResponse(BaseModel):
    total: int
    by_source: dict
    by_severity: dict


class FetchResult(BaseModel):
    source: str
    fetched: int
    new: int
    errors: List[str]


class VulnIntelListAPIRoute(BaseModel):
    """兼容旧版API"""
    total: int
    items: List[dict]
    sources: List[str]


@router.get("/", response_model=VulnIntelListResponse)
async def get_vuln_intel(
    severity: Optional[str] = Query(None, description="最低严重性: critical, high, medium"),
    keyword: Optional[str] = Query(None, description="关键词"),
    keywords: Optional[str] = Query(None, description="多个关键词逗号分隔"),
    source: Optional[str] = Query(None, description="来源: cisa_kev, github_advisory, nvd_rss"),
    sources: Optional[str] = Query(None, description="多个来源逗号分隔"),
    is_known_exploited: Optional[bool] = Query(None, description="是否已知被利用"),
    is_rce: Optional[bool] = Query(None, description="是否RCE漏洞"),
    is_poc_public: Optional[bool] = Query(None, description="是否POC公开"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """
    获取漏洞情报列表

    数据来源：
    - **CISA KEV** - 美国政府已知被利用漏洞目录（最权威）
    - **GitHub Advisory** - 全球开源项目安全公告
    - **NVD** - 美国国家漏洞数据库
    """
    service = get_vuln_intel_service()

    # 处理关键词
    kw_list = []
    if keyword:
        kw_list.append(keyword)
    if keywords:
        kw_list.extend([k.strip() for k in keywords.split(",") if k.strip()])

    # 处理来源
    src_list = None
    if source:
        src_list = [s.strip() for s in source.split(",") if s.strip()]

    result = await service.get_intel_list(
        min_severity=severity or "high",
        keywords=kw_list if kw_list else None,
        sources=src_list,
        is_known_exploited=is_known_exploited,
        is_rce=is_rce,
        is_poc_public=is_poc_public,
        limit=limit,
        offset=offset
    )

    # 添加 sources 字段（从 stats.by_source 获取）
    result["sources"] = list(result["stats"].get("by_source", {}).keys())
    return VulnIntelListResponse(**result)


@router.get("/legacy", response_model=VulnIntelListAPIRoute)
async def get_vuln_intel_legacy(
    severity: Optional[str] = Query("high"),
    keyword: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200)
):
    """旧版API兼容"""
    service = get_vuln_intel_service()

    kw_list = [keyword] if keyword else None
    src_list = [source] if source else None

    result = await service.get_intel_list(
        min_severity=severity,
        keywords=kw_list,
        sources=src_list,
        limit=limit
    )

    # 兼容旧格式
    return VulnIntelListAPIRoute(
        total=result["total"],
        items=result["items"],
        sources=list(result["stats"].get("by_source", {}).keys())
    )


@router.post("/refresh")
async def refresh_vuln_intel(background_tasks: BackgroundTasks):
    """
    手动触发情报刷新（后台运行）

    从所有来源（CISA KEV、GitHub Advisory、NVD）获取最新漏洞情报。
    """
    service = get_vuln_intel_service()

    async def do_fetch():
        return await service.fetch_all_sources(force=True)

    result = await do_fetch()

    return {
        "message": "情报刷新完成",
        "results": result,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/latest")
async def get_latest_vulns(
    limit: int = Query(10, ge=1, le=50),
    min_severity: str = Query("high")
):
    """获取最新漏洞（高危及以上）"""
    service = get_vuln_intel_service()
    result = await service.get_intel_list(
        min_severity=min_severity,
        limit=limit
    )

    items = result["items"][:limit]

    return {
        "total": len(items),
        "items": [
            {
                "cve_id": item["cve_id"],
                "vulnerability_name": item["vulnerability_name"],
                "severity": item["severity"],
                "cvss_score": item["cvss_score"],
                "product": item["product"],
                "vendor": item["vendor"],
                "source": item["source"],
                "is_known_exploited": item["is_known_exploited"],
                "is_rce": item["is_rce"],
                "is_poc_public": item["is_poc_public"],
                "published_date": item["published_date"],
                "due_date": item["due_date"],
                "remediation_url": item["remediation_url"],
            }
            for item in items
        ]
    }


@router.get("/stats", response_model=IntelStatsResponse)
async def get_stats():
    """获取漏洞统计"""
    service = get_vuln_intel_service()
    stats = await service.get_stats()
    return IntelStatsResponse(**stats)


@router.get("/sources")
async def get_sources():
    """获取情报来源列表"""
    service = get_vuln_intel_service()
    sources = await service.get_sources()
    return {"sources": sources}


@router.get("/cve/{cve_id}")
async def get_cve_detail(cve_id: str):
    """获取指定CVE详情"""
    service = get_vuln_intel_service()
    result = await service.get_intel_list(
        keywords=[cve_id],
        limit=1
    )
    if result["items"]:
        return result["items"][0]
    return {"error": "CVE not found"}


@router.post("/cleanup")
async def cleanup_expired(days: int = Query(90, ge=30, le=365)):
    """清理过期数据"""
    service = get_vuln_intel_service()
    count = await service.mark_expired(days)
    return {"message": f"已标记 {count} 条过期数据", "days": days}


from datetime import datetime
