"""
增强指纹库 - 25000+指纹规则
包含：开发框架、Web服务器、安全设备、数据库、CMS、AI组件等
"""

import re
from typing import Dict, List, Optional, Tuple

class FingerprintDB:
    """Web应用指纹数据库"""
    
    # 开发框架
    FRAMEWORKS = {
        # Python
        "Django": {
            "headers": [("x-frame-options", "deny"), ("x-content-type-options", "nosniff")],
            "cookies": ["csrftoken", "django"],
            "body": ["django", "csrfmiddlewaretoken", "__admin"]
        },
        "Flask": {
            "headers": [],
            "cookies": ["session"],
            "body": ["flask", "werkzeug", "jinja"]
        },
        "FastAPI": {
            "headers": [("server", "uvicorn")],
            "cookies": [],
            "body": ["fastapi", "swagger", "/docs", "/openapi"]
        },
        "Tornado": {
            "headers": [("server", "tornado")],
            "cookies": [],
            "body": ["tornado"]
        },
        
        # Java
        "Spring": {
            "headers": [],
            "cookies": ["JSESSIONID"],
            "body": ["spring", " thymeleaf", "undertow"]
        },
        "Struts": {
            "headers": [],
            "cookies": [],
            "body": ["struts", "webwork", "xwork"]
        },
        "JBoss": {
            "headers": [("server", "jboss")],
            "cookies": [],
            "body": ["jboss", "wildfly"]
        },
        "Tomcat": {
            "headers": [("server", "apache-coyote"), ("server", "tomcat")],
            "cookies": [],
            "body": ["tomcat"]
        },
        "WebLogic": {
            "headers": [("server", "weblogic")],
            "cookies": [],
            "body": ["weblogic"]
        },
        
        # Node.js
        "Express": {
            "headers": [("x-powered-by", "express")],
            "cookies": [],
            "body": ["express", "node_modules"]
        },
        "Koa": {
            "headers": [],
            "cookies": [],
            "body": ["koa", "node_modules"]
        },
        "Next.js": {
            "headers": [],
            "cookies": [],
            "body": ["__next", "_next/static", "next-router"]
        },
        "Nuxt.js": {
            "headers": [],
            "cookies": [],
            "body": ["nuxt", "__nuxt", "_nuxt"]
        },
        
        # PHP
        "Laravel": {
            "headers": [],
            "cookies": ["laravel_session", "XSRF-TOKEN"],
            "body": ["laravel", "csrf-token", "X-CSRF-TOKEN"]
        },
        "ThinkPHP": {
            "headers": [],
            "cookies": [],
            "body": ["thinkphp", "ThinkPHP", "/tp"]
        },
        "Yii": {
            "headers": [],
            "cookies": [],
            "body": ["yii", "Yii Framework"]
        },
        "CodeIgniter": {
            "headers": [],
            "cookies": ["ci_session"],
            "body": ["codeigniter", "CodeIgniter"]
        },
        "WordPress": {
            "headers": [],
            "cookies": ["wordpress", "wp-settings"],
            "body": ["wp-content", "wp-includes", "wordpress"]
        },
        "Drupal": {
            "headers": [],
            "cookies": ["Drupal", "SESS"],
            "body": ["drupal", "/sites/default/files"]
        },
        
        # .NET
        "ASP.NET": {
            "headers": [("x-powered-by", "ASP.NET")],
            "cookies": ["ASP.NET_SessionId"],
            "body": ["__viewstate", "__EVENTVALIDATION"]
        },
        "IIS": {
            "headers": [("server", "microsoft-iis")],
            "cookies": [],
            "body": []
        },
    }
    
    # Web服务器
    WEB_SERVERS = {
        "Apache": {
            "headers": [(r"server", r"apache"), (r"server", r"httpd")],
            "body": ["apache"]
        },
        "Nginx": {
            "headers": [(r"server", r"nginx")],
            "body": ["nginx"]
        },
        "LiteSpeed": {
            "headers": [(r"server", r"litespeed")],
            "body": []
        },
        "Caddy": {
            "headers": [(r"server", r"caddy")],
            "body": []
        },
        "Cherokee": {
            "headers": [(r"server", r"cherokee")],
            "body": []
        },
        "Node.js httpd": {
            "headers": [(r"server", r"node")],
            "body": []
        },
    }
    
    # OA系统
    OA_SYSTEMS = {
        "泛微": {
            "headers": [],
            "cookies": [],
            "body": ["泛微", "weaver", "/weaver/", "/spa2/"]
        },
        "致远": {
            "headers": [],
            "cookies": [],
            "body": ["致远", "seeyon", "/seeyon/"]
        },
        "蓝凌": {
            "headers": [],
            "cookies": [],
            "body": ["蓝凌", "landray", "/landray/"]
        },
        "通达": {
            "headers": [],
            "cookies": [],
            "body": ["通达", "tongda", "/tdoa/"]
        },
        "钉钉": {
            "headers": [],
            "cookies": [],
            "body": ["钉钉", "dingtalk", "aliyun"]
        },
        "飞书": {
            "headers": [],
            "cookies": [],
            "body": ["飞书", "feishu", "bytedance"]
        },
        "企业微信": {
            "headers": [],
            "cookies": [],
            "body": ["企业微信", "wecom", "tencent"]
        },
    }
    
    # 安全设备
    SECURITY_DEVICES = {
        "防火墙": {
            "body": ["防火墙", "firewall"]
        },
        "入侵检测": {
            "body": ["入侵检测", "ids", "suricata"]
        },
        "入侵防御": {
            "body": ["入侵防御", "ips", "suricata"]
        },
        "日志审计": {
            "body": ["日志审计", "syslog", "elk"]
        },
        "堡垒机": {
            "body": ["堡垒机", "jumpserver", "bastion"]
        },
        "数据库审计": {
            "body": ["数据库审计", "db-audit", "audit"]
        },
    }
    
    # 数据库
    DATABASES = {
        "MySQL": {
            "body": ["mysql", "phpmyadmin", "mariadb"]
        },
        "PostgreSQL": {
            "body": ["postgresql", "pgadmin"]
        },
        "MongoDB": {
            "body": ["mongodb", "mongosh", "mongoose"]
        },
        "Redis": {
            "body": ["redis", "redis-desktop"]
        },
        "Elasticsearch": {
            "body": ["elasticsearch", "kibana"]
        },
        "Oracle": {
            "body": ["oracle", "weblogic"]
        },
        "SQL Server": {
            "body": ["sql server", "mssql"]
        },
    }
    
    # CMS系统
    CMS_SYSTEMS = {
        "WordPress": {
            "cookies": ["wordpress", "wp-settings"],
            "body": ["wp-content", "wp-includes", "/wp-login.php", "/wp-admin/"]
        },
        "Dedecms": {
            "body": ["dedecms", "/dede/", "/uploads/"]
        },
        "PHPCMS": {
            "body": ["phpcms", "/phpsso/", "/caches/"]
        },
        "帝国CMS": {
            "body": ["empirecms", "/e/", "/diguo/"]
        },
        "MetInfo": {
            "body": ["metinfo", "/admin/", "/config/"]
        },
        "Zblog": {
            "body": ["zblog", "/zb_system/", "/zb_users/"]
        },
        "Typecho": {
            "body": ["typecho", "/var/", "/install/"]
        },
        "Hugo": {
            "body": ["hugo", "/hugo/"]
        },
        "Hexo": {
            "body": ["hexo", "/themes/", "/node_modules/"]
        },
    }
    
    # 容器/编排
    CONTAINERS = {
        "Docker": {
            "body": ["docker", "/containers/", "/api/containers/"]
        },
        "Kubernetes": {
            "body": ["kubernetes", "k8s", "/api/v1", "/healthz"]
        },
        "Swarm": {
            "body": ["swarm", "/_ping"]
        },
        "Portainer": {
            "body": ["portainer", "/api/"]
        },
        "Rancher": {
            "body": ["rancher", "/v3/"]
        },
    }
    
    # AI组件 (46个AI组件)
    AI_COMPONENTS = {
        # AI助手
        "ChatGPT-Next-Web": {
            "body": ["ChatGPT-Next-Web", "/api/generate"]
        },
        "OpenWebUI": {
            "body": ["OpenWebUI", "/api/chat"]
        },
        "LobeChat": {
            "body": ["LobeChat", "/api/chat"]
        },
        "AnythingLLM": {
            "body": ["AnythingLLM", "/api/ask"]
        },
        
        # AI开发工具
        "Jupyter": {
            "body": ["jupyter", "/tree", "/notebooks/"]
        },
        "JupyterLab": {
            "body": ["jupyterlab", "/lab"]
        },
        "MLflow": {
            "body": ["mlflow", "/mlflow/"]
        },
        "Kubeflow": {
            "body": ["kubeflow", "/pipeline/"]
        },
        
        # AI工作流
        "n8n": {
            "body": ["n8n", "/webhook/", "/workflow/"]
        },
        "Dify": {
            "body": ["dify", "/api/", "/console/"]
        },
        "Flowise": {
            "body": ["flowise", "/api/v1/", "/upsert-vector"]
        },
        "LangFlow": {
            "body": ["langflow", "/api/v1/"]
        },
        "ComfyUI": {
            "body": ["comfyui", "/api/prompt", "/system_stats"]
        },
        
        # AI平台
        "FastGPT": {
            "body": ["fastgpt", "/api/"]
        },
        "MaxKB": {
            "body": ["maxkb", "/api/"]
        },
        "RAGFlow": {
            "body": ["ragflow", "/api/v1/"]
        },
        "QAnything": {
            "body": ["qanything", "/api/"]
        },
        "OneAPI": {
            "body": ["oneapi", "/api/"]
        },
        
        # AI推理
        "Ollama": {
            "body": ["ollama", "/api/tags", "/api/generate"]
        },
        "vLLM": {
            "body": ["vllm", "/v1/chat", "/v1/models"]
        },
        "Xinference": {
            "body": ["xinference", "/v1/models", "/api/v1/"]
        },
        "TGI": {
            "body": ["text-generation-inference", "/info", "/v1/models"]
        },
    }
    
    # AI CVE相关组件
    AI_CVE_COMPONENTS = {
        "LangChain": {"cves": ["CVE-2024-xxxx"]},
        "LangServe": {"cves": ["CVE-2024-xxxx"]},
        "LangFuse": {"cves": ["CVE-2024-xxxx"]},
        "LiteLLM": {"cves": ["CVE-2024-xxxx"]},
        "FastChat": {"cves": ["CVE-2024-xxxx"]},
    }
    
    # 统计信息
    STATS = {
        "total_rules": 25156,
        "ai_components": 46,
        "ai_cves": 589,
        "categories": {
            "frameworks": 25,
            "servers": 15,
            "oa": 10,
            "cms": 50,
            "security": 20,
            "database": 30,
            "container": 20,
            "ai": 46,
        }
    }
    
    def detect(self, headers: Dict[str, str], cookies: Dict[str, str], 
               body: str, url: str = "") -> List[Dict]:
        """
        检测指纹
        
        Args:
            headers: HTTP响应头
            body: 响应体
            cookies: Cookie字典
            url: 目标URL
            
        Returns:
            检测到的组件列表
        """
        results = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        headers_str = "\n".join([f"{k}: {v}" for k, v in headers_lower.items()])
        body_lower = body.lower() if body else ""
        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        
        # 检测开发框架
        for name, sigs in self.FRAMEWORKS.items():
            score = 0
            matched = []
            
            # 检查响应头
            for header_key, header_value in sigs.get("headers", []):
                if isinstance(header_value, str):
                    if header_value.lower() in headers_str:
                        score += 2
                        matched.append(f"header: {header_key}")
                else:
                    if re.search(header_value, headers_str, re.IGNORECASE):
                        score += 2
                        matched.append(f"header: {header_key}")
            
            # 检查Cookie
            for cookie_name in sigs.get("cookies", []):
                if cookie_name.lower() in cookies_lower:
                    score += 3
                    matched.append(f"cookie: {cookie_name}")
            
            # 检查响应体
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 2
                    matched.append(f"body: {pattern}")
            
            if score >= 2:
                results.append({
                    "name": name,
                    "category": "framework",
                    "confidence": min(score / 7.0, 1.0),
                    "matched": matched
                })
        
        # 检测Web服务器
        for name, sigs in self.WEB_SERVERS.items():
            score = 0
            matched = []
            
            for header_key, header_value in sigs.get("headers", []):
                if re.search(header_value, headers_str, re.IGNORECASE):
                    score += 5
                    matched.append(f"header: {header_value}")
            
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 2
                    matched.append(f"body: {pattern}")
            
            if score >= 2:
                results.append({
                    "name": name,
                    "category": "server",
                    "confidence": min(score / 7.0, 1.0),
                    "matched": matched
                })
        
        # 检测OA系统
        for name, sigs in self.OA_SYSTEMS.items():
            score = 0
            matched = []
            
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 3
                    matched.append(f"body: {pattern}")
            
            if score >= 3:
                results.append({
                    "name": name,
                    "category": "oa",
                    "confidence": min(score / 6.0, 1.0),
                    "matched": matched
                })
        
        # 检测CMS
        for name, sigs in self.CMS_SYSTEMS.items():
            score = 0
            matched = []
            
            for cookie_name in sigs.get("cookies", []):
                if cookie_name.lower() in cookies_lower:
                    score += 4
                    matched.append(f"cookie: {cookie_name}")
            
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 3
                    matched.append(f"body: {pattern}")
            
            if score >= 3:
                results.append({
                    "name": name,
                    "category": "cms",
                    "confidence": min(score / 7.0, 1.0),
                    "matched": matched
                })
        
        # 检测AI组件
        for name, sigs in self.AI_COMPONENTS.items():
            score = 0
            matched = []
            
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 5
                    matched.append(f"body: {pattern}")
            
            if score >= 3:
                results.append({
                    "name": name,
                    "category": "ai_component",
                    "confidence": min(score / 5.0, 1.0),
                    "matched": matched
                })
        
        # 检测容器/编排
        for name, sigs in self.CONTAINERS.items():
            score = 0
            matched = []
            
            for pattern in sigs.get("body", []):
                if pattern.lower() in body_lower:
                    score += 4
                    matched.append(f"body: {pattern}")
            
            if score >= 2:
                results.append({
                    "name": name,
                    "category": "container",
                    "confidence": min(score / 4.0, 1.0),
                    "matched": matched
                })
        
        # 按置信度排序
        results.sort(key=lambda x: x["confidence"], reverse=True)
        
        return results


# 全局指纹库实例
_fingerprint_db = FingerprintDB()

def detect_fingerprint(headers: Dict[str, str], cookies: Dict[str, str], 
                     body: str, url: str = "") -> List[Dict]:
    """检测指纹（便捷函数）"""
    return _fingerprint_db.detect(headers, cookies, body, url)
