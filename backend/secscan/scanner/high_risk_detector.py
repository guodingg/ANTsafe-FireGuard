"""
高危资产识别与风险计算
基于漏洞信息自动识别高风险资产
"""

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict

from secscan.models.asset import Asset, AssetStatus
from secscan.models.vuln import Vulnerability, Severity, VulnStatus

class RiskCalculator:
    """风险计算器"""
    
    # 严重性权重
    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 3,
        "info": 1
    }
    
    # 风险等级阈值
    RISK_THRESHOLDS = {
        "CRITICAL": 90,   # 90分以上
        "HIGH": 70,       # 70-89分
        "MEDIUM": 50,     # 50-69分
        "LOW": 0          # 50分以下
    }
    
    # 高危服务类型
    HIGH_RISK_SERVICES = [
        "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
        "memcached", "rabbitmq", "kafka",
        "smb", "samba", "ftp", "telnet", "rlogin",
        "vpn", "openvpn", "ipsec",
        "kubernetes", "docker", "etcd",
        "struts2", "weblogic", "shiro", "fastjson", "springboot",
        "tomcat", "apache", "nginx", "iis"
    ]
    
    @staticmethod
    def calculate_risk_score(vulns: List[Vulnerability]) -> float:
        """计算风险评分 (0-100)"""
        if not vulns:
            return 0.0
        
        score = 0.0
        
        for vuln in vulns:
            # 基础严重性分数
            severity_weight = RiskCalculator.SEVERITY_WEIGHTS.get(vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity, 1)
            
            # CVSS评分加成
            cvss_bonus = (vuln.cvss_score or 0) * 2
            
            # 未修复漏洞加成
            if vuln.status != VulnStatus.FIXED:
                unfixed_bonus = 5
            else:
                unfixed_bonus = 0
            
            # 误报排除
            if vuln.is_false_positive:
                continue
            
            vuln_score = severity_weight + cvss_bonus + unfixed_bonus
            score += vuln_score
        
        # 归一化到0-100
        normalized_score = min(score, 100)
        return round(normalized_score, 1)
    
    @staticmethod
    def get_risk_level(score: float) -> str:
        """根据评分获取风险等级"""
        if score >= RiskCalculator.RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif score >= RiskCalculator.RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif score >= RiskCalculator.RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def identify_risk_factors(vulns: List[Vulnerability]) -> List[str]:
        """识别风险因子"""
        factors = set()
        
        for vuln in vulns:
            if vuln.is_false_positive:
                continue
            
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity
            
            # 按严重性
            if severity == "critical":
                factors.add("严重漏洞")
            
            # 按类型
            if vuln.cve:
                factors.add(f"CVE漏洞")
            
            category = getattr(vuln, 'category', None)
            if category:
                if category.lower() in ["struts2", "weblogic", "shiro", "fastjson", "springboot"]:
                    factors.add(f"{category}框架漏洞")
                elif category.lower() in ["sql_injection", "xss", "rce"]:
                    factors.add(f"{category.upper()}漏洞")
            
            # 按CVE
            cve = vuln.cve
            if cve:
                if "CVE-2021" in cve or "CVE-2022" in cve or "CVE-2023" in cve or "CVE-2024" in cve or "CVE-2025" in cve or "CVE-2026" in cve:
                    factors.add("近年高危CVE")
        
        # 限制返回数量
        return list(factors)[:5]
    
    @staticmethod
    def get_remediation_status(vulns: List[Vulnerability]) -> str:
        """获取修复状态"""
        total = len(vulns)
        fixed = sum(1 for v in vulns if v.status == VulnStatus.FIXED)
        verified = sum(1 for v in vulns if v.status == VulnStatus.VERIFIED and v.verified)
        
        if fixed == total:
            return "fixed"
        elif fixed > 0:
            return "processing"
        elif verified > total * 0.5:
            return "verified"
        else:
            return "pending"
    
    @staticmethod
    def is_high_risk_service(service: str, product: str = "") -> bool:
        """判断是否高危服务"""
        if not service:
            return False
        
        service_lower = service.lower()
        product_lower = product.lower() if product else ""
        
        for risky in RiskCalculator.HIGH_RISK_SERVICES:
            if risky in service_lower or risky in product_lower:
                return True
        
        return False


async def get_high_risk_assets(db: AsyncSession, min_score: float = 70, limit: int = 100) -> List[Dict]:
    """
    获取高危资产列表
    
    基于漏洞信息计算风险评分，返回高风险资产
    自动按 hostname(IP) 合并：同一域名/IP的所有端口合并为一条记录
    """
    # 查询所有存活资产
    result = await db.execute(
        select(Asset).where(Asset.status == AssetStatus.ALIVE)
    )
    assets = result.scalars().all()
    
    # 按 hostname(IP) 分组聚合（同一域名/IP的不同端口合并）
    asset_groups = {}
    for asset in assets:
        # 使用hostname作为分组键，如果hostname为空则用IP
        group_key = asset.hostname if asset.hostname else asset.ip
        if not group_key:
            group_key = f"{asset.ip}:{asset.port}"  # 完全没信息时退化到IP:port
        
        if group_key not in asset_groups:
            asset_groups[group_key] = {
                "assets": [],
                "vulns": set(),
                "ports": set(),
                "services": set(),
                "products": set(),
                "ip": asset.ip,
                "hostname": asset.hostname or asset.ip,
            }
        
        asset_groups[group_key]["assets"].append(asset)
        if asset.port:
            asset_groups[group_key]["ports"].add(asset.port)
        if asset.service:
            asset_groups[group_key]["services"].add(asset.service)
        if asset.product:
            asset_groups[group_key]["products"].add(asset.product)
        
        # 查询该资产的漏洞（用asset_id关联）
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.asset_id == asset.id)
        )
        for v in vuln_result.scalars().all():
            asset_groups[group_key]["vulns"].add(v)
    
    high_risk_assets = []
    
    for group_key, group in asset_groups.items():
        vulns = list(group["vulns"])
        assets_in_group = group["assets"]
        
        if not vulns:
            continue
        
        # 去重漏洞（同一个漏洞只计算一次）
        seen_vuln_ids = set()
        unique_vulns = []
        for v in vulns:
            if v.id not in seen_vuln_ids:
                seen_vuln_ids.add(v.id)
                unique_vulns.append(v)
        vulns = unique_vulns
        
        # 计算风险评分（使用风险评分最高的资产作为代表）
        risk_score = RiskCalculator.calculate_risk_score(vulns)
        
        # 高危服务直接加分
        for asset in assets_in_group:
            if RiskCalculator.is_high_risk_service(asset.service, asset.product):
                risk_score += 15
                break
        
        # 限制在100分以内
        risk_score = min(risk_score, 100)
        
        # 判断是否高危
        if risk_score >= min_score:
            risk_factors = RiskCalculator.identify_risk_factors(vulns)
            remediation_status = RiskCalculator.get_remediation_status(vulns)
            
            # 合并分类信息
            categories = set()
            for v in vulns:
                if hasattr(v, 'category') and v.category:
                    categories.add(v.category)
            
            # 合并端口：按 端口/服务 格式
            ports_services = []
            for asset in assets_in_group:
                if asset.port:
                    svc = asset.service or "unknown"
                    ports_services.append(f"{asset.port}/{svc}")
            ports_services = sorted(set(ports_services))
            
            high_risk_assets.append({
                "id": assets_in_group[0].id,  # 用第一个资产的ID
                "ip": group["ip"],
                "hostname": group["hostname"],
                "port": ", ".join(str(p) for p in sorted(group["ports"])),  # 合并后的端口列表
                "port_details": ", ".join(ports_services),  # 端口/服务 明细
                "service": ", ".join(sorted(group["services"])) or "unknown",
                "product": ", ".join(sorted(group["products"])),
                "risk_level": RiskCalculator.get_risk_level(risk_score),
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "vuln_count": len(vulns),
                "critical_count": sum(1 for v in vulns if (v.severity.value if hasattr(v.severity, 'value') else v.severity) == "critical"),
                "remediation_status": remediation_status,
                "discovery_time": max((a.created_at.isoformat() for a in assets_in_group if a.created_at), default=""),
                "categories": list(categories),
                "asset_ids": [a.id for a in assets_in_group]  # 所有相关资产ID
            })
    
    # 按风险评分排序
    high_risk_assets.sort(key=lambda x: x["risk_score"], reverse=True)
    
    return high_risk_assets[:limit]


async def get_risk_statistics(db: AsyncSession) -> Dict:
    """获取风险统计"""
    result = await db.execute(select(Asset).where(Asset.status == AssetStatus.ALIVE))
    assets = result.scalars().all()
    
    stats = {
        "total": 0,
        "high_risk_count": 0,
        "critical_count": 0,
        "medium_count": 0,
        "low_count": 0
    }
    
    stats["total"] = len(assets)
    
    for asset in assets:
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.asset_id == asset.id)
        )
        vulns = vuln_result.scalars().all()
        
        risk_score = RiskCalculator.calculate_risk_score(vulns)
        if RiskCalculator.is_high_risk_service(asset.service, asset.product):
            risk_score += 15
        risk_score = min(risk_score, 100)
        
        level = RiskCalculator.get_risk_level(risk_score)
        
        if risk_score >= 90:
            stats["critical_count"] += 1
            stats["high_risk_count"] += 1
        elif risk_score >= 70:
            stats["high_risk_count"] += 1
    
    return stats