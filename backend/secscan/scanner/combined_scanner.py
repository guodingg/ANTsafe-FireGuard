"""
组合漏洞扫描器 - 同时调用 Web、Nuclei、Xray 三大扫描引擎
增强版：支持页面爬取、目录扫描、组件识别
集成FLUX优秀功能：WAF检测、Bypass Payload、指纹识别、断点续扫、云安全、K8s/容器安全
"""

import asyncio
import httpx
import yaml
import json
import re
from pathlib import Path
from typing import AsyncGenerator, List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime

from secscan.scanner.base import ScannerBase, HostResult
from secscan.scanner.waf_detector import detect_waf, get_bypass_headers
from secscan.scanner.bypass_payloads import get_bypass_payloads
from secscan.scanner.fingerprint_db import detect_fingerprint
from secscan.scanner.rate_limiter import get_rate_limiter
from secscan.scanner.differential_tester import get_differential_tester
from secscan.scanner.js_analyzer import get_js_extractor

# 漏洞详情知识库
VULN_INFO = {
    "rce": {
        "name": "远程代码执行",
        "severity": "critical",
        "description": "攻击者可以在服务器上执行任意操作系统命令，可能导致服务器完全沦陷",
        "remediation": [
            "1. 输入验证: 对所有用户输入进行严格的白名单校验，禁止危险字符如 | ; & $ < > ` ",
            "2. 参数化执行: 使用安全的API(如Python的subprocess.run的列表参数)替代字符串拼接执行命令",
            "3. 最小权限原则: Web应用进程使用低权限账户运行，禁止使用root/admin权限",
            "4. 路径限制: 使用chroot或容器隔离，确保攻击者无法访问系统关键目录",
            "5. 安全配置: 禁用危险函数(shell_exec, exec, passthru, proc_open等)或使用disable_functions限制"
        ]
    },
    "sqli": {
        "name": "SQL注入",
        "severity": "high",
        "description": "攻击者可以通过构造恶意SQL语句获取数据库数据，甚至完全控制服务器",
        "remediation": [
            "1. 参数化查询: 使用Prepared Statements(如Java的PreparedStatement, Python的sqlite3.execute)",
            "2. ORM框架: 优先使用SQLAlchemy、Django ORM等ORM框架，避免直接拼接SQL",
            "3. 输入验证: 对用户输入进行严格类型校验和格式验证",
            "4. 最小权限: 数据库账户仅授予必要的表操作权限，禁止DDL和DCL操作",
            "5. 敏感加密: 对密码、密钥等敏感字段使用bcrypt/AES加密存储",
            "6. WAF防护: 部署Web应用防火墙(如ModSecurity)检测SQL注入特征"
        ]
    },
    "xxe": {
        "name": "XML外部实体注入",
        "severity": "high",
        "description": "允许加载外部实体，可能导致敏感文件读取、内网探测甚至RCE",
        "remediation": [
            "1. 禁用外部实体: 在解析XML时设置DTDProcessing=DTD_DISABLED或feature_external_entities=false",
            "2. 安全解析器: 使用安全的XML解析库(如Python的defusedxml, Java的Woodstox)",
            "3. 输入验证: 对XML输入进行严格校验，拒绝包含<!DOCTYPE>和<!ENTITY>的请求",
            "4. 内容安全策略: 配置CSP响应头限制XML解析器的能力",
            "5. 定期审计: 使用SAST工具扫描代码中的XML解析操作"
        ]
    },
    "ssrf": {
        "name": "服务器端请求伪造",
        "severity": "high",
        "description": "服务器被诱导向内部系统发起请求，可访问内网敏感资源",
        "remediation": [
            "1. URL白名单: 仅允许访问预定义的安全URL列表，拒绝任何重定向",
            "2. 协议限制: 仅允许HTTP/HTTPS，禁止file://, dict://, gopher://等危险协议",
            "3. 内网隔离: 使用VPC/防火墙隔离内部服务，限制SSRF可以访问的IP范围",
            "4. 输入验证: 对用户提供的URL进行完整解析和校验，禁止跳转",
            "5. 日志监控: 记录所有SSRF测试请求，设置异常告警"
        ]
    },
    "lfi": {
        "name": "本地文件包含",
        "severity": "high",
        "description": "攻击者可以包含服务器本地文件，可能导致代码执行和敏感数据泄露",
        "remediation": [
            "1. 路径白名单: 仅允许包含预定义的文件路径，使用绝对路径而非用户输入拼接",
            "2. 路径规范化: realpath()解析后验证是否在允许的目录内",
            "3. 危险字符过滤: 禁止用户输入包含 ../ 或 %2e%2e 等路径遍历字符",
            "4. 安全配置: PHP配置中设置open_basedir限制可访问目录",
            "5. 关闭远程包含: disableallow_url_include=On, allow_url_fopen=Off"
        ]
    },
    "xss": {
        "name": "跨站脚本攻击",
        "severity": "medium",
        "description": "攻击者可以在页面注入恶意JavaScript脚本，窃取用户Cookie或会话",
        "remediation": [
            "1. 输出编码: 对所有用户输入进行HTML实体编码(> < & \" ' 等)",
            "2. Content-Security-Policy: 配置严格的CSP头限制脚本来源，如script-src 'self'",
            "3. HttpOnly Cookie: 对Session Cookie设置HttpOnly标志防止JavaScript读取",
            "4. X-Content-Type-Options: 设置X-Content-Type-Options: nosniff防止MIME嗅探",
            "5. 输入验证: 白名单校验输入格式，拒绝危险字符如<script>, <iframe>, onerror=",
            "6. 前端框架: 使用React/Vue等框架的自动转义功能"
        ]
    },
    "upload": {
        "name": "任意文件上传",
        "severity": "critical",
        "description": "攻击者可以上传恶意文件(如WebShell)到服务器，获取服务器权限",
        "remediation": [
            "1. 文件类型白名单: 仅允许上传预定义的安全文件类型，如jpg,png,doc,pdf，禁止.exe,.php,.jsp,.asp",
            "2. MIME验证: 服务端检查Content-Type和文件内容(魔数)，不仅依赖文件扩展名",
            "3. 存储隔离: 上传文件存储在Web根目录之外，或使用独立的文件服务器",
            "4. 权限控制: 上传目录禁止执行权限，设置为644，存放目录设置为755",
            "5. 文件名随机化: 重命名上传文件为随机字符串，保留原始扩展名",
            "6. 图片处理: 对图片进行重新编码处理，破坏恶意代码(如ImageMagick)"
        ]
    },
    "unauth": {
        "name": "未授权访问",
        "severity": "high",
        "description": "无需身份认证即可访问敏感功能，可能导致数据泄露或权限提升",
        "remediation": [
            "1. 强制认证: 对所有敏感接口启用身份认证，使用OAuth2/JWT等标准协议",
            "2. 权限校验: 每个接口都要验证用户权限，即使前端已做校验",
            "3. 会话管理: 使用安全的会话机制，定期刷新Session ID，设置合理的超时时间",
            "4. API安全: 使用API网关统一鉴权，避免遗漏个别接口",
            "5. 安全头: 配置X-Auth-Token等自定义认证头，避免使用标准头被猜测"
        ]
    },
    "info-leak": {
        "name": "信息泄露",
        "severity": "medium",
        "description": "系统配置或敏感信息被暴露，可能被攻击者利用进行进一步攻击",
        "remediation": [
            "1. 错误处理: 自定义错误页面，禁止在生产环境显示详细错误栈",
            "2. 配置审计: 定期扫描代码库，确保敏感配置(如密码、密钥)不上传至Git",
            "3. 响应头清理: 移除X-Powered-By, Server等暴露服务器信息的响应头",
            "4. 目录遍历禁止: 配置Web服务器禁止访问敏感目录如/.git, /.svn, /config",
            "5. 版本管理: 及时更新软件版本，修复已知的信息泄露CVE"
        ]
    },
    "file-read": {
        "name": "任意文件读取",
        "severity": "high",
        "description": "攻击者可以读取服务器任意文件，可能泄露密钥、配置、源代码等敏感信息",
        "remediation": [
            "1. 路径校验: 使用realpath()规范化路径后验证是否在允许范围内",
            "2. 白名单机制: 仅允许读取预定义的公开文件目录，禁止读取/etc/passwd等系统文件",
            "3. 权限控制: Web应用使用低权限账户，确保无法读取敏感文件",
            "4. 敏感文件保护: 将敏感配置文件(.env, config.php)放在Web根目录之外",
            "5. 日志监控: 记录异常的文件读取行为，设置告警"
        ]
    },
    "csrf": {
        "name": "跨站请求伪造",
        "severity": "medium",
        "description": "攻击者可以伪造用户请求执行敏感操作",
        "remediation": [
            "1. CSRF Token: 在表单中添加随机CSRF Token并验证",
            "2. SameSite Cookie: 设置Cookie的SameSite属性为Strict或Lax",
            "3. 验证码: 对敏感操作(如转账、密码修改)要求二次验证码",
            "4. Referer检查: 验证请求来源Referer头是否来自可信域名",
            "5. 自定义头: 使用自定义请求头如X-Requested-With: XMLHttpRequest"
        ]
    },
    "redirect": {
        "name": "开放重定向",
        "severity": "medium",
        "description": "应用存在未验证的重定向，可能被用于钓鱼攻击",
        "remediation": [
            "1. URL白名单: 仅允许重定向到预定义的可信域名列表",
            "2. 相对路径: 优先使用相对路径重定向，避免使用用户输入的完整URL",
            "3. 警告页面: 对需要外部重定向显示警告页面，让用户确认",
            "4. 跳转限制: 使用rel=noopener noreferrer属性打开外部链接"
        ]
    },
    "idor": {
        "name": "越权访问",
        "severity": "high",
        "description": "攻击者可以通过修改ID参数访问他人资源",
        "remediation": [
            "1. 权限验证: 每个数据访问都要验证当前用户是否有权访问该资源",
            "2. 间接引用: 使用随机ID或加密ID替代自增数字ID",
            "3. 对象级校验: 查询时同时验证用户ID和资源所属ID",
            "4. 审计日志: 记录所有资源访问日志，发现异常访问模式"
        ]
    }
}

# 常见敏感目录和路径
COMMON_PATHS = [
    # 管理后台
    "/admin", "/admin/", "/admin/login", "/administrator", "/manage", "/management",
    "/wp-admin", "/wp-login", "/wp-admin/admin-ajax.php",
    "/administrator/index.php", "/admin/cms.php",
    # 数据库管理
    "/phpmyadmin", "/phpMyAdmin", "/adminer", "/dbadmin", "/mysql", "/sqlweb",
    "/websql", "/panama", "/managment",
    # API端点
    "/api", "/api/v1", "/api/v2", "/api-docs", "/swagger", "/swagger-ui",
    "/api/swagger.json", "/api-docs.yaml", "/graphql", "/graphiql",
    # 配置文件
    "/config", "/configuration", "/settings", "/configs", "/conf",
    "/web.config", "/config.php", "/settings.py", "/.env", "/.git/config",
    "/database.yml", "/db.yml", "/credentials", "/secrets",
    # 备份文件
    "/backup", "/backups", "/bak", "/old", "/dump", "/database.sql",
    "/backup.sql", "/db.sql", "/data.sql", "/dump.sql",
    # 敏感文件
    "/readme", "/README", "/readme.md", "/changelog", "/license",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.htaccess", "/.git", "/.gitignore", "/.env.bak",
    # 上传相关
    "/upload", "/uploads", "/uploadify", "/file", "/files",
    "/images", "/img", "/p_w_upload", "/attachments",
    # 调试页面
    "/debug", "/debugger", "/test", "/demo", "/exploit", "/hackbar",
    "/webmin", "/cgi-bin", "//cgi-bin/login",
    # 用户相关
    "/user", "/users", "/login", "/register", "/signup", "/signin",
    "/profile", "/account", "/reset", "/forgot", "/password",
    # 监控/状态
    "/status", "/health", "/info", "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/monitor", "/metrics",
    # 框架特定
    "/struts", "/struts2", "/struts", "/.do", "/.action",
    "/api/jsonrpc", "/jsonrpc", "/xmlrpc",
]

# 常见组件指纹
COMPONENT_SIGNATURES = {
    "Apache": ["Apache", "apache", "X-Server"],
    "Nginx": ["nginx", "Nginx"],
    "IIS": ["IIS", "Microsoft-IIS"],
    "Tomcat": ["Tomcat", "tomcat", "JSESSIONID"],
    "JBoss": ["jboss", "JBoss", "JSESSION"],
    "WebLogic": ["WebLogic", "weblogic"],
    "Spring": ["Spring", "spring", "_SPRING_"],
    "Django": ["csrftoken", "django"],
    "Flask": ["flask", "werkzeug"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "WordPress": ["wp-content", "wordpress", "wp-includes"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap", "twitter-bootstrap"],
    "React": ["react", "_react"],
    "Vue": ["vue", "__vue"],
    "Angular": ["ng-app", "angular"],
    "Node.js": ["express", "connect"],
    "PHP": [".php", "PHPSESSID"],
    "ASP.NET": ["ASP.NET", "__VIEWSTATE"],
    "Python": ["python", "Django", "Flask"],
}

# 中间件端口
MIDDLEWARE_PORTS = {
    8080: ["Tomcat", "JBoss", "Jetty"],
    8443: ["HTTPS Alternate"],
    7001: ["WebLogic"],
    9090: ["WebSphere"],
    5000: ["Flask/Django Dev"],
    3000: ["Node.js Dev"],
    27017: ["MongoDB"],
    6379: ["Redis"],
    5432: ["PostgreSQL"],
    3306: ["MySQL"],
    1433: ["SQL Server"],
    9200: ["Elasticsearch"],
}

def parse_poc_name(poc_name: str) -> Dict[str, str]:
    """解析POC名称，提取漏洞类型和CVE"""
    result = {
        "name": poc_name,
        "type": "unknown",
        "cve": "",
        "description": "",
        "remediation": []
    }
    
    cve_match = re.search(r'cve-(\d{4})-(\d+)', poc_name.lower())
    if cve_match:
        result["cve"] = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
    
    for key, info in VULN_INFO.items():
        if key in poc_name.lower():
            result["type"] = key
            result["name"] = f"{info['name']} ({result['cve'] or poc_name.replace('poc-yaml-', '')})"
            result["description"] = info["description"]
            result["remediation"] = info["remediation"]
            break
    
    if result["type"] == "unknown":
        friendly_name = poc_name.replace("poc-yaml-", "").replace("-", " ").title()
        result["name"] = result["cve"] or friendly_name
    
    return result


class CombinedVulnScanner(ScannerBase):
    """组合漏洞扫描器 - 集成Web扫描、Nuclei、Xray"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.task_id = task_id
        self.options = options or {}
        
        self.timeout = self.options.get("timeout", 30)
        self.user_agent = self.options.get("user_agent", "ANTsafe Security Scanner/2.0")
        self.max_pages = self.options.get("max_pages", 50)  # 最多爬取页面数
        self.max_depth = self.options.get("max_depth", 3)   # 最大爬取深度
        
        # FLUX增强功能
        self.enable_waf_detection = self.options.get("enable_waf_detection", True)
        self.enable_bypass = self.options.get("enable_bypass", True)
        self.enable_cloud_security = self.options.get("enable_cloud_security", True)
        self.enable_js_analysis = self.options.get("enable_js_analysis", True)
        self.enable_differential_test = self.options.get("enable_differential_test", True)
        
        # 初始化各个扫描器
        self._init_web_scanner()
        self._init_nuclei_scanner()
        self._init_xray_scanner()
        
        # FLUX增强组件
        if self.enable_waf_detection:
            self.waf_detector = None  # 动态初始化
        if self.enable_differential_test:
            self.differential_tester = get_differential_tester(timeout=self.timeout)
        if self.enable_js_analysis:
            self.js_extractor = get_js_extractor()
        
        # 已访问的URL
        self.visited_urls: Set[str] = set()
        self.discovered_paths: List[str] = []
        self.detected_components: List[Dict] = []
        
        # WAF检测结果
        self.detected_wafs: List[Dict] = []
        self.detected_fingerprints: List[Dict] = []
        
        print(f"[CombinedScanner] 初始化完成: Web + Nuclei + Xray (FLUX增强版)")
    
    def _init_web_scanner(self):
        """初始化Web漏洞检测规则"""
        self.web_checks = [
            {
                "name": "SQL注入",
                "severity": "high",
                "patterns": ["' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT"],
                "error_indicators": ["sql syntax", "mysql", "postgresql", "sqlite", "oracle", "microsoft sql", "incorrect syntax", "warning:", "error in your sql"]
            },
            {
                "name": "XSS跨站脚本",
                "severity": "medium",
                "patterns": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
                "error_indicators": ["<script>", "onerror=", "alert(1)", "<img"]
            },
            {
                "name": "路径遍历",
                "severity": "high",
                "patterns": ["../../../etc/passwd", "....//....//etc/passwd", "..%252f..%252fetc/passwd"],
                "error_indicators": ["root:", "[drivers]", "boot loader"]
            },
            {
                "name": "敏感文件读取",
                "severity": "high",
                "patterns": ["../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\system32\\config\\sam"],
                "error_indicators": ["root:", "[boot loader]", "bootmgr", "microsoft r"]
            }
        ]
    
    def _init_nuclei_scanner(self):
        """Nuclei配置"""
        self.nuclei_path = "/usr/local/bin/nuclei"
        self.nuclei_template_dir = "/app/data/nuclei-templates"
    
    def _init_xray_scanner(self):
        """Xray POC配置"""
        self.xray_poc_dir = Path("/app/xray-pocs")
        self.xray_pocs = self._load_xray_pocs()
    
    def _load_xray_pocs(self) -> List[Dict]:
        """加载Xray POC"""
        pocs = []
        if not self.xray_poc_dir.exists():
            return pocs
        
        for yaml_file in list(self.xray_poc_dir.glob("*.yml")):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    poc_data = yaml.safe_load(f)
                if not poc_data:
                    continue
                
                raw_name = poc_data.get('name', yaml_file.stem)
                parsed = parse_poc_name(raw_name)
                detail = poc_data.get('detail', {})
                rules = poc_data.get('rules', {})
                request_path = "/"
                if rules:
                    first_rule = list(rules.values())[0]
                    request_path = first_rule.get('request', {}).get('path', '/')
                
                pocs.append({
                    'raw_name': raw_name,
                    'name': parsed['name'],
                    'type': parsed['type'],
                    'severity': parsed['type'] if parsed['type'] != 'unknown' else 'medium',
                    'cve': parsed['cve'],
                    'description': parsed['description'] or detail.get('description', ''),
                    'remediation': parsed['remediation'],
                    'request_path': request_path,
                    'rules': rules,
                    'expression': poc_data.get('expression', '')
                })
            except:
                pass
        return pocs
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            normalized = self._normalize_url(target)
            result = urlparse(normalized)
            return all([result.scheme in ["http", "https"], result.netloc])
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """标准化URL"""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target
    
    async def _crawl_page(self, client: httpx.AsyncClient, url: str, depth: int = 0) -> Dict[str, Any]:
        """爬取单个页面，提取链接和表单"""
        if depth > self.max_depth or url in self.visited_urls:
            return {"links": [], "forms": [], "components": []}
        
        self.visited_urls.add(url)
        
        result = {
            "url": url,
            "links": [],
            "forms": [],
            "components": [],
            "inputs": []
        }
        
        try:
            resp = await client.get(url, timeout=self.timeout, follow_redirects=True)
            content_type = resp.headers.get("content-type", "")
            
            # 只解析HTML
            if "text/html" not in content_type:
                return result
            
            html = resp.text
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # 检测组件
            for component, signatures in COMPONENT_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in html.lower() or sig in str(resp.headers):
                        result["components"].append({
                            "name": component,
                            "found_in": "response_headers" if sig in str(resp.headers) else "html"
                        })
            
            # 解析HTML提取链接
            soup = BeautifulSoup(html, 'html.parser')
            
            # 提取所有链接
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == parsed.netloc:
                    path = urlparse(full_url).path
                    if path and path not in self.visited_urls:
                        result["links"].append(path)
            
            # 提取所有表单
            for form in soup.find_all('form'):
                form_info = {
                    "action": urljoin(url, form.get('action', '')),
                    "method": form.get('method', 'get').upper(),
                    "inputs": []
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_info["inputs"].append({
                        "name": inp.get('name', ''),
                        "type": inp.get('type', 'text'),
                        "value": inp.get('value', '')
                    })
                result["forms"].append(form_info)
            
            # 提取input输入框
            for inp in soup.find_all('input'):
                if inp.get('name'):
                    result["inputs"].append({
                        "name": inp.get('name', ''),
                        "type": inp.get('type', 'text'),
                        "url": url
                    })
            
            # 检测中间件版本信息
            server = resp.headers.get("server", "")
            x_powered = resp.headers.get("x-powered-by", "")
            if server:
                result["components"].append({"name": f"Server: {server}", "found_in": "header"})
            if x_powered:
                result["components"].append({"name": f"Powered: {x_powered}", "found_in": "header"})
                
        except Exception as e:
            print(f"[Crawl] Error crawling {url}: {e}")
        
        return result
    
    async def _crawl_target(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """完整爬取目标"""
        pages = []
        to_visit = [(target, 0)]  # (url, depth)
        
        while to_visit and len(pages) < self.max_pages:
            url, depth = to_visit.pop(0)
            
            page_info = await self._crawl_page(client, url, depth)
            pages.append(page_info)
            
            # 添加新发现的链接
            for link in page_info.get("links", [])[:20]:  # 限制每页添加的链接数
                full_url = urljoin(target, link)
                if full_url not in self.visited_urls:
                    parsed = urlparse(full_url)
                    if parsed.netloc == urlparse(target).netloc:
                        to_visit.append((full_url, depth + 1))
            
            # 更新已发现路径
            self.discovered_paths.append(url)
        
        # 去重
        self.discovered_paths = list(set(self.discovered_paths))
        
        return pages
    
    async def _scan_directory(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """目录扫描"""
        vulns = []
        base_url = target.rstrip('/')
        
        for path in COMMON_PATHS[:30]:  # 限制数量
            try:
                url = f"{base_url}{path}"
                resp = await client.get(url, timeout=5, follow_redirects=True)
                
                if resp.status_code == 200:
                    content_lower = resp.text.lower()
                    
                    # 检查是否真的是敏感路径
                    if any(keyword in content_lower for keyword in ['login', 'admin', 'dashboard', 'password', 'username', 'phpmyadmin', 'database']):
                        vulns.append({
                            "name": "敏感路径暴露",
                            "severity": "medium",
                            "source": "directory",
                            "url": url,
                            "path": path,
                            "cve": "",
                            "description": f"发现敏感路径: {path}",
                            "evidence": f"状态码: {resp.status_code}, 响应长度: {len(resp.text)}"
                        })
                        
            except:
                pass
        
        return vulns
    
    async def _scan_web(self, client: httpx.AsyncClient, target: str, pages: List[Dict]) -> List[Dict]:
        """Web漏洞检测"""
        vulns = []
        
        # 在所有发现的页面和路径上测试
        all_urls = [target]
        for p in pages:
            if isinstance(p, dict) and "url" in p:
                all_urls.append(p["url"])
        all_urls.extend(self.discovered_paths)
        all_urls = list(set(all_urls))[:20]  # 去重并限制
        
        for url in all_urls:
            for check in self.web_checks:
                for payload in check["patterns"]:
                    try:
                        # URL参数测试
                        parsed = urlparse(url)
                        if parsed.query:
                            # 测试现有参数
                            params = parse_qs(parsed.query)
                            for param_name in params:
                                test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}={payload}")
                                resp = await client.get(test_url, timeout=self.timeout, follow_redirects=True)
                                content_lower = resp.text.lower()
                                
                                for indicator in check.get("error_indicators", []):
                                    if indicator.lower() in content_lower:
                                        vulns.append({
                                            "name": check["name"],
                                            "severity": check["severity"],
                                            "source": "web",
                                            "payload": payload,
                                            "url": test_url,
                                            "path": parsed.path,
                                            "cve": "",
                                            "description": f"检测到{check['name']}漏洞",
                                            "evidence": f"Payload: {payload}, 命中关键词: {indicator}"
                                        })
                                        break
                        else:
                            # 测试路径注入
                            separator = "&" if "?" in url else "?"
                            test_url = f"{url}{separator}test={payload}"
                            resp = await client.get(test_url, timeout=self.timeout, follow_redirects=True)
                            content_lower = resp.text.lower()
                            
                            for indicator in check.get("error_indicators", []):
                                if indicator.lower() in content_lower:
                                    vulns.append({
                                        "name": check["name"],
                                        "severity": check["severity"],
                                        "source": "web",
                                        "payload": payload,
                                        "url": test_url,
                                        "path": parsed.path,
                                        "cve": "",
                                        "description": f"检测到{check['name']}漏洞",
                                        "evidence": f"Payload: {payload}, 命中关键词: {indicator}"
                                    })
                                    break
                    except:
                        pass
        
        return vulns
    
    async def _scan_nuclei(self, target: str) -> List[Dict]:
        """Nuclei扫描"""
        vulns = []
        
        try:
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-t", self.nuclei_template_dir,
                "-json",
                "-rate-limit", "50",
                "-timeout", "5"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                
                for line in stdout.decode().splitlines():
                    if line.strip().startswith('{'):
                        try:
                            result = json.loads(line)
                            info = result.get('info', {})
                            matched = result.get('matched-at', target)
                            parsed = urlparse(matched)
                            path = parsed.path or "/"
                            
                            vulns.append({
                                "name": info.get('name', 'Nuclei Vuln'),
                                "severity": info.get('severity', 'medium'),
                                "source": "nuclei",
                                "cve": info.get('cve-id', ''),
                                "description": info.get('description', ''),
                                "url": matched,
                                "path": path,
                                "template": result.get('template-id', ''),
                                "evidence": f"Nuclei模板检测"
                            })
                        except:
                            pass
            except asyncio.TimeoutError:
                proc.kill()
        except Exception as e:
            print(f"[CombinedScanner] Nuclei扫描出错: {e}")
        
        return vulns
    
    async def _scan_xray(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Xray POC扫描"""
        vulns = []
        
        for poc in self.xray_pocs[:30]:
            try:
                rules = poc.get('rules', {})
                if not rules:
                    continue
                
                first_rule = list(rules.values())[0]
                request_config = first_rule.get('request', {})
                method = request_config.get('method', 'get').lower()
                path = request_config.get('path', '/')
                
                parsed_target = urlparse(target)
                if path.startswith('/'):
                    full_url = f"{parsed_target.scheme}://{parsed_target.netloc}{path}"
                else:
                    full_url = f"{target.rstrip('/')}/{path}"
                
                headers = {'User-Agent': self.user_agent}
                headers.update(request_config.get('headers', {}))
                body = request_config.get('body')
                
                if method == 'get':
                    resp = await client.get(full_url, headers=headers, timeout=self.timeout, follow_redirects=True)
                elif method == 'post':
                    resp = await client.post(full_url, headers=headers, data=body, timeout=self.timeout, follow_redirects=True)
                else:
                    continue
                
                resp_lower = resp.text.lower()
                vuln_type = poc.get('type', 'unknown')
                is_vuln = False
                evidence = ""
                
                # 检测逻辑
                if 'rce' in vuln_type or 'unauth' in vuln_type:
                    if resp.status_code == 200:
                        is_vuln = True
                        evidence = f"状态码: {resp.status_code}"
                
                elif 'sqli' in vuln_type:
                    sql_errors = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite']
                    for err in sql_errors:
                        if err in resp_lower:
                            is_vuln = True
                            evidence = f"SQL错误: {err}"
                            break
                
                elif 'lfi' in vuln_type or 'file-read' in vuln_type:
                    file_indicators = ['root:', 'boot loader', '/etc/passwd', 'c:\\windows']
                    for ind in file_indicators:
                        if ind in resp_lower:
                            is_vuln = True
                            evidence = "敏感文件内容"
                            break
                
                elif 'xxe' in vuln_type:
                    if '<xml' in resp_lower or 'xxe' in resp_lower:
                        is_vuln = True
                        evidence = "XML响应"
                
                elif 'ssrf' in vuln_type:
                    if any(ip in resp_lower for ip in ['127.0.0.1', 'localhost', '192.168', '10.0.0']):
                        is_vuln = True
                        evidence = "内网地址访问"
                
                elif 'xss' in vuln_type:
                    if '<script' in resp_lower or 'onerror=' in resp_lower:
                        is_vuln = True
                        evidence = "未转义脚本"
                
                if is_vuln:
                    cve = poc.get('cve', '')
                    if not cve:
                        cve_match = re.search(r'cve-\d{4}-\d+', poc.get('raw_name', ''), re.IGNORECASE)
                        if cve_match:
                            cve = cve_match.group(0).upper()
                    
                    vulns.append({
                        "name": poc['name'],
                        "severity": poc['severity'],
                        "source": "xray",
                        "cve": cve,
                        "description": poc.get('description', f"检测到可能的{vuln_type}漏洞"),
                        "url": full_url,
                        "path": path,
                        "evidence": evidence,
                        "remediation": poc.get('remediation', ['及时更新', '输入验证'])
                    })
            except:
                pass
        
        return vulns
    
    # ==================== FLUX增强功能 ====================
    
    async def _flux_waf_detection(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """FLUX WAF指纹识别与绕过"""
        if not self.enable_waf_detection:
            return []
        
        vulns = []
        try:
            resp = await client.get(target, timeout=self.timeout)
            headers = dict(resp.headers)
            
            # WAF检测
            self.detected_wafs = detect_waf(resp.text, headers, resp.status_code)
            
            if self.detected_wafs:
                print(f"[FLUX] 检测到WAF: {[w['name'] for w in self.detected_wafs]}")
                
                # 获取绕过策略
                waf_name = self.detected_wafs[0]['name']
                bypass_hdrs = get_bypass_headers(waf_name)
                
                # 如果检测到WAF，添加信息到结果
                vulns.append({
                    "name": f"WAF防护 - {waf_name}",
                    "severity": "info",
                    "source": "flux-waf",
                    "description": f"目标使用{waf_name}进行防护",
                    "url": target,
                    "evidence": f"匹配规则: {', '.join(self.detected_wafs[0].get('matched', []))}",
                    "remediation": ["使用WAF绕过技术", "更换攻击向量", "尝试Bypass Payload"]
                })
        except Exception as e:
            print(f"[FLUX] WAF检测失败: {e}")
        
        return vulns
    
    async def _flux_fingerprint(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """FLUX 指纹识别"""
        vulns = []
        try:
            resp = await client.get(target, timeout=self.timeout)
            cookies = dict(resp.cookies)
            headers = dict(resp.headers)
            
            # 指纹识别
            fingerprints = detect_fingerprint(headers, cookies, resp.text, target)
            self.detected_fingerprints = fingerprints
            
            if fingerprints:
                print(f"[FLUX] 识别组件: {[f['name'] for f in fingerprints[:5]]}")
                
                for fp in fingerprints[:10]:
                    vulns.append({
                        "name": f"组件识别 - {fp['name']}",
                        "severity": "info",
                        "source": "flux-fingerprint",
                        "category": fp.get('category', 'unknown'),
                        "description": f"识别到{fp['category']}组件: {fp['name']}",
                        "url": target,
                        "evidence": f"置信度: {fp['confidence']:.0%}, 匹配: {', '.join(fp.get('matched', [])[:3])}",
                        "remediation": ["确认组件版本", "检查已知CVE", "及时更新补丁"]
                    })
        except Exception as e:
            print(f"[FLUX] 指纹识别失败: {e}")
        
        return vulns
    
    async def _flux_js_analysis(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """FLUX JS敏感信息提取"""
        if not self.enable_js_analysis:
            return []
        
        vulns = []
        try:
            # 获取页面
            resp = await client.get(target, timeout=self.timeout)
            
            # 提取JS文件URL
            js_urls = self._extract_js_urls(resp.text, target)
            
            print(f"[FLUX] 发现 {len(js_urls)} 个JS文件")
            
            # 分析JS文件
            for js_url in js_urls[:10]:
                try:
                    js_resp = await client.get(js_url, timeout=self.timeout)
                    if js_resp.status_code != 200:
                        continue
                    
                    # 提取敏感信息
                    secrets = self.js_extractor.extract(js_resp.text, js_url)
                    
                    for secret in secrets[:5]:
                        vulns.append({
                            "name": f"敏感信息 - {secret.type}",
                            "severity": "high" if 'key' in secret.type or 'token' in secret.type else "medium",
                            "source": "flux-js",
                            "description": f"在JS中发现敏感信息: {secret.type}",
                            "url": js_url,
                            "evidence": f"类型: {secret.type}, 置信度: {secret.confidence:.0%}",
                            "remediation": ["移除硬编码密钥", "使用环境变量", "密钥轮换"]
                        })
                    
                    # 提取API端点
                    endpoints = self.js_extractor.extract_endpoints(js_resp.text, js_url)
                    for ep in endpoints[:5]:
                        self.discovered_paths.append(ep['path'])
                        
                except:
                    continue
                    
        except Exception as e:
            print(f"[FLUX] JS分析失败: {e}")
        
        return vulns
    
    async def _flux_cloud_security(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """FLUX 云安全检测"""
        if not self.enable_cloud_security:
            return []
        
        vulns = []
        try:
            resp = await client.get(target, timeout=self.timeout)
            content = resp.text
            
            # 云服务商Access Key检测
            cloud_patterns = {
                "aws": r'AKIA[0-9A-Z]{16}',
                "aliyun": r'(?i)(aliyun|aliyundl)[_-]?access[_-]?key[_-]?id[:\s]*["\']{0,1}[a-zA-Z0-9]{24}',
                "tencent": r'(?i)qcloud[_-]?secret[_-]?id[:\s]*["\']{0,1}[A-Z0-9]{40}',
                "github": r'ghp_[a-zA-Z0-9]{36}',
                "slack": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            }
            
            for cloud_name, pattern in cloud_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    vulns.append({
                        "name": f"云凭证泄露 - {cloud_name.upper()}",
                        "severity": "critical",
                        "source": "flux-cloud",
                        "description": f"发现{cloud_name.upper()}服务凭证",
                        "url": target,
                        "evidence": f"匹配模式: {match.group(0)[:50]}...",
                        "remediation": ["立即撤销泄露的凭证", "轮换访问密钥", "使用密钥管理服务"]
                    })
            
            # 云存储桶检测
            bucket_patterns = [
                r'([a-z0-9][-a-z0-9]*\.s3\.amazonaws\.com)',
                r'([a-z0-9][-a-z0-9]*\.oss\.aliyuncs\.com)',
                r'([a-z0-9][-a-z0-9]*\.cos\.myqcloud\.com)',
                r'bucket=([a-z0-9][-a-z0-9]*)',
            ]
            
            for pattern in bucket_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    bucket = match.group(1) if match.lastindex else match.group(0)
                    vulns.append({
                        "name": "云存储桶地址泄露",
                        "severity": "medium",
                        "source": "flux-cloud",
                        "description": f"发现云存储桶地址",
                        "url": target,
                        "evidence": f"存储桶: {bucket}",
                        "remediation": ["确认桶权限配置", "启用访问日志", "使用私有桶"]
                    })
                    
        except Exception as e:
            print(f"[FLUX] 云安全检测失败: {e}")
        
        return vulns
    
    async def _flux_differential_test(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """FLUX 差分测试 - 减少误报"""
        if not self.enable_differential_test:
            return []
        
        vulns = []
        try:
            tester = self.differential_tester
            
            # 获取基准响应
            baseline = await tester.get_baseline(client, target)
            if not baseline:
                return []
            
            # 获取Bypass Payload
            bypass_pocs = get_bypass_payloads()
            
            # SQL注入差分测试
            sqli_payloads = bypass_pocs.get_sqli_payloads()[:10]
            for payload in sqli_payloads:
                test_url = f"{target}?id={payload}"
                try:
                    resp = await client.get(test_url, timeout=self.timeout)
                    payload_response = tester._build_baseline_response(resp, 0)
                    result = tester.compare(baseline, payload_response)
                    
                    if result.is_vulnerable:
                        vulns.append({
                            "name": "SQL注入 (差分检测)",
                            "severity": "high",
                            "source": "flux-differential",
                            "description": "通过差分测试检测到SQL注入漏洞",
                            "url": test_url,
                            "payload": payload,
                            "evidence": result.evidence,
                            "confidence": result.confidence,
                            "remediation": ["使用参数化查询", "输入过滤验证", "最小权限数据库账户"]
                        })
                        break  # 找到一个就够了
                except:
                    continue
            
            # XSS差分测试
            xss_payloads = bypass_pocs.get_xss_payloads()[:10]
            for payload in xss_payloads:
                test_url = f"{target}?q={payload}"
                try:
                    resp = await client.get(test_url, timeout=self.timeout)
                    
                    # 检查Payload是否被反射
                    if payload in resp.text:
                        vulns.append({
                            "name": "XSS跨站脚本 (反射检测)",
                            "severity": "medium",
                            "source": "flux-differential",
                            "description": "Payload被反射到响应中",
                            "url": test_url,
                            "payload": payload,
                            "evidence": "Payload反射在响应中",
                            "remediation": ["输入输出编码", "Content-Security-Policy", "HttpOnly Cookie"]
                        })
                        break
                except:
                    continue
                    
        except Exception as e:
            print(f"[FLUX] 差分测试失败: {e}")
        
        return vulns
    
    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """从HTML提取JS文件URL"""
        js_urls = []
        pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        matches = re.finditer(pattern, html, re.IGNORECASE)
        for match in matches:
            url = match.group(1)
            if not url.startswith('http'):
                url = urljoin(base_url, url)
            js_urls.append(url)
        
        # 去重
        return list(set(js_urls))
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行组合扫描"""
        valid_targets = [self._normalize_url(t) for t in targets if await self.validate_target(t)]
        
        if not valid_targets:
            return
        
        total = len(valid_targets)
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
            for i, target in enumerate(valid_targets):
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"开始组合扫描: {target}",
                    vulns=0
                )
                
                parsed = urlparse(target)
                result = HostResult(
                    ip=parsed.netloc,
                    port=443 if parsed.scheme == "https" else 80,
                    protocol=parsed.scheme,
                    service="http",
                    product="",
                    banner=""
                )
                
                all_vulns = []
                
                # ========== FLUX增强：0步 WAF检测 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在检测WAF...",
                    vulns=0
                )
                waf_vulns = await self._flux_waf_detection(client, target)
                all_vulns.extend(waf_vulns)
                
                # ========== FLUX增强：1步 指纹识别 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在进行指纹识别...",
                    vulns=0
                )
                fp_vulns = await self._flux_fingerprint(client, target)
                all_vulns.extend(fp_vulns)
                
                # ========== FLUX增强：2步 JS敏感信息 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在分析JS敏感信息...",
                    vulns=0
                )
                js_vulns = await self._flux_js_analysis(client, target)
                all_vulns.extend(js_vulns)
                
                # ========== FLUX增强：3步 云安全检测 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在检测云安全...",
                    vulns=len(all_vulns)
                )
                cloud_vulns = await self._flux_cloud_security(client, target)
                all_vulns.extend(cloud_vulns)
                
                # ========== 第一步：爬取目标 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在爬取页面...",
                    vulns=0
                )
                pages = await self._crawl_target(client, target)
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"爬取完成，发现 {len(pages)} 个页面",
                    vulns=0
                )
                
                # ========== 第二步：目录扫描 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在扫描敏感目录...",
                    vulns=0
                )
                dir_vulns = await self._scan_directory(client, target)
                all_vulns.extend(dir_vulns)
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"目录扫描完成，发现 {len(dir_vulns)} 个问题",
                    vulns=len(all_vulns)
                )
                
                # ========== 第三步：Web漏洞检测 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在进行Web漏洞检测...",
                    vulns=len(all_vulns)
                )
                web_vulns = await self._scan_web(client, target, pages)
                all_vulns.extend(web_vulns)
                
                # ========== FLUX增强：差分测试 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"正在进行差分测试(WAF绕过)...",
                    vulns=len(all_vulns)
                )
                diff_vulns = await self._flux_differential_test(client, target)
                all_vulns.extend(diff_vulns)
                
                # ========== 第四步：Nuclei扫描 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"Nuclei深度扫描 ({len(pages)} 页面)...",
                    vulns=len(all_vulns)
                )
                nuclei_vulns = await self._scan_nuclei(target)
                all_vulns.extend(nuclei_vulns)
                
                # 对发现的所有路径单独执行Nuclei扫描
                for path in self.discovered_paths[:10]:
                    path_nuclei = await self._scan_nuclei(path)
                    nuclei_vulns.extend(path_nuclei)
                all_vulns.extend(nuclei_vulns)
                
                # ========== 第五步：Xray POC扫描 ==========
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"Xray POC扫描 ({len(self.xray_pocs)} POC)...",
                    vulns=len(all_vulns)
                )
                xray_vulns = await self._scan_xray(client, target)
                all_vulns.extend(xray_vulns)
                
                # 去重
                seen = set()
                unique_vulns = []
                for v in all_vulns:
                    key = (v.get('name'), v.get('url', v.get('path', '')))
                    if key not in seen:
                        seen.add(key)
                        unique_vulns.append(v)
                
                result.vulns = unique_vulns
                
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"扫描完成，共发现 {len(unique_vulns)} 个漏洞 (爬取 {len(pages)} 页面, {len(self.discovered_paths)} 路径)",
                    vulns=len(unique_vulns)
                )
                
                yield result
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
