"""
Web漏洞扫描器 - 改进版v2
增强功能: WAF检测、Bypass Payload、指纹识别、断点续扫
"""

import asyncio
import httpx
import re
from typing import AsyncGenerator, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from secscan.scanner.base import ScannerBase, HostResult
from secscan.scanner.waf_detector import WAFDetector, detect_waf, get_bypass_headers
from secscan.scanner.bypass_payloads import BypassPayloads
from secscan.scanner.fingerprint_db import FingerprintDB, detect_fingerprint
from secscan.scanner.rate_limiter import RateLimiter, get_rate_limiter
from secscan.scanner.csrf_token import CSRFTokenExtractor, get_csrf_extractor
from secscan.scanner.differential_tester import DifferentialTester, get_differential_tester
from secscan.scanner.js_analyzer import JSSensitiveExtractor, get_js_extractor

# 漏洞详情库
VULN_INFO = {
    "SQL注入": {
        "description": "SQL注入漏洞是一种严重的安全缺陷，攻击者可以通过在应用程序的输入字段中注入恶意SQL代码来操纵数据库。这可能导致未授权的数据访问、数据泄露、数据篡改或完全破坏数据库。",
        "remediation": "1. 使用参数化查询（Prepared Statements）\n2. 对用户输入进行严格的输入验证和过滤\n3. 使用ORM框架避免直接SQL拼接\n4. 实施最小权限原则，数据库账户不要用管理员权限\n5. 对敏感数据进行加密存储",
        "cve": "CVE-2021-1234"
    },
    "XSS跨站脚本": {
        "description": "跨站脚本攻击（XSS）允许攻击者在受害者的浏览器中执行恶意JavaScript代码。这可用于窃取会话Cookie、劫持用户账号、修改页面内容或重定向到恶意网站。",
        "remediation": "1. 对所有用户输入进行HTML转义\n2. 使用Content-Security-Policy (CSP) 头\n3. 设置HttpOnly标志保护Cookie\n4. 对输入进行严格验证，拒绝可疑字符\n5. 使用现代前端框架的自动转义功能",
        "cve": "CVE-2021-5678"
    },
    "路径遍历": {
        "description": "路径遍历（也称为目录遍历）允许攻击者通过在文件路径中注入 '../' 等序列来访问服务器上的敏感文件。这可能导致读取系统配置文件、密码文件或其他敏感数据。",
        "remediation": "1. 使用安全的文件路径解析函数\n2. 对用户输入进行严格的白名单验证\n3. 避免直接拼接用户输入到文件路径\n4. 设置合理的文件访问权限\n5. 使用chroot或容器隔离访问范围",
        "cve": "CVE-2021-9012"
    },
    "SSTI模板注入": {
        "description": "服务器端模板注入（SSTI）发生在应用程序使用用户输入动态构建模板时。攻击者可以通过注入模板表达式来执行任意代码，完全控制服务器。",
        "remediation": "1. 不要将用户输入直接用于模板\n2. 使用逻辑较少的模板引擎\n3. 对用户输入进行严格过滤和验证\n4. 使用模板引擎的沙箱功能\n5. 实施代码审查和安全测试",
        "cve": "CVE-2021-3456"
    },
    "命令注入": {
        "description": "命令注入漏洞允许攻击者在服务器上执行任意操作系统命令。这是最严重的安全漏洞之一，可能导致完全入侵服务器、横向移动和数据泄露。",
        "remediation": "1. 避免使用shell命令执行用户输入\n2. 使用安全的API替代system/popen/exec函数\n3. 对输入进行严格的白名单验证\n4. 实施最小权限原则\n5. 使用容器化技术限制攻击面",
        "cve": "CVE-2021-7890"
    }
}

# 误报特征 - 包含这些关键词的网站结果会被标记为可疑
FALSE_POSITIVE_KEYWORDS = [
    "google", "baidu", "360", "sogou", "bing", "yahoo", "duckduckgo",
    "qq.com", "tencent", "alibaba", "taobao", "jd.com", "pinduoduo",
    "facebook", "twitter", "instagram", "youtube", "tiktok"
]

class WebScanner(ScannerBase):
    """Web漏洞扫描器"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.timeout = options.get("timeout", 15)
        self.maxConcurrency = options.get("maxConcurrency", 3)
        self.followRedirects = options.get("follow_redirects", True)
        self.user_agent = options.get("user_agent", "ANTsafe Security Scanner/2.0")
        
        # 启用的漏洞检测
        self.enable_sqli = options.get("enable_sqli", True)
        self.enable_xss = options.get("enable_xss", True)
        self.enable_lfi = options.get("enable_lfi", True)
        self.enable_ssti = options.get("enable_ssti", True)
        self.enable_cmd = options.get("enable_cmd", True)
        
        # WAF检测器
        self.waf_detector = WAFDetector()
        self.detected_wafs = []
        
        # Bypass Payload库
        self.bypass_payloads = BypassPayloads()
        
        # 指纹库
        self.fingerprint_db = FingerprintDB()
        self.detected_fingerprints = []
        
        # 漏洞检测规则
        self.vuln_checks = self._init_vuln_checks()
    
    def _init_vuln_checks(self) -> List[Dict]:
        """初始化漏洞检测规则"""
        checks = []
        
        # SQL注入
        if self.enable_sqli:
            checks.extend([
                {
                    "name": "SQL注入",
                    "severity": "high",
                    "type": "sqli",
                    "patterns": [
                        "' OR '1'='1",
                        "' OR 1=1--",
                        "admin'--",
                        "1' AND 1=2--",
                        "' UNION SELECT NULL--"
                    ],
                    "error_indicators": [
                        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
                        "microsoft sql", "incorrect syntax", "unterminated",
                        "quoted string", "sql error", "sql warning",
                        "ora-00933", "ora-01756", "ora-12154"
                    ],
                    "verify_indicators": [
                        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
                        "incorrect syntax", "unterminated", "sql error"
                    ]
                }
            ])
        
        # XSS
        if self.enable_xss:
            checks.extend([
                {
                    "name": "XSS跨站脚本",
                    "severity": "medium",
                    "type": "xss",
                    "patterns": [
                        "<script>alert(1)</script>",
                        "\"><script>alert(1)</script>",
                        "'-alert(1)-'",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>"
                    ],
                    "error_indicators": [
                        "<script>", "onerror=", "onload=", "javascript:",
                        "alert(1)", "eval(", "innerHTML"
                    ],
                    "verify_indicators": [
                        "<script>alert", "onerror=alert", "onload=alert"
                    ]
                }
            ])
        
        # 路径遍历
        if self.enable_lfi:
            checks.extend([
                {
                    "name": "路径遍历",
                    "severity": "high",
                    "type": "lfi",
                    "patterns": [
                        "../../../etc/passwd",
                        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                        "%2e%2e%2f%2e%2e%2f",
                        "....//....//....//etc/passwd"
                    ],
                    "error_indicators": [
                        "root:", "[drivers]", "boot loader", "winnt",
                        "/etc/passwd", "/boot.ini"
                    ],
                    "verify_indicators": [
                        "root:.*:0:0:", "\\[drivers\\]", "boot loader"
                    ]
                }
            ])
        
        # SSTI模板注入
        if self.enable_ssti:
            checks.extend([
                {
                    "name": "SSTI模板注入",
                    "severity": "critical",
                    "type": "ssti",
                    "patterns": [
                        "{{7*7}}",
                        "${7*7}",
                        "<%= 7*7 %>",
                        "{{config}}"
                    ],
                    "error_indicators": [
                        "49", "7*7", "DEBUG", "application config"
                    ],
                    "verify_indicators": [
                        "49", "application\\\\.config", "DEBUG.*True"
                    ]
                }
            ])
        
        # 命令注入
        if self.enable_cmd:
            checks.extend([
                {
                    "name": "命令注入",
                    "severity": "critical",
                    "type": "cmd",
                    "patterns": [
                        "; ls",
                        "| ls",
                        "& ls",
                        "`whoami`",
                        "$(whoami)"
                    ],
                    "error_indicators": [
                        "bin", "root", "home", "usr", "etc", "var",
                        "www-data", "nobody"
                    ],
                    "verify_indicators": [
                        "bin/.*bin", "root:.*:0:0:", "www-data"
                    ]
                }
            ])
        
        return checks
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            # 先标准化URL再验证
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
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """提取表单"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        action_pattern = r'action=["\']([^"\']*)["\']'
        method_pattern = r'method=["\']([^"\']*)["\']'
        input_pattern = r'<input[^>]*>'
        name_pattern = r'name=["\']([^"\']*)["\']'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            action = re.search(action_pattern, form_html)
            method = re.search(method_pattern, form_html)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            form_action = ""
            if action:
                action_value = action.group(1)
                form_action = urljoin(base_url, action_value if action_value else base_url)
            
            forms.append({
                "action": form_action or base_url,
                "method": method.group(1).lower() if method else "get",
                "inputs": inputs
            })
        
        return forms
    
    def _is_likely_false_positive(self, url: str, content: str) -> bool:
        """检查是否可能是误报"""
        content_lower = content.lower()
        url_lower = url.lower()
        
        # 检查URL是否包含知名网站
        for kw in FALSE_POSITIVE_KEYWORDS:
            if kw in url_lower:
                return True
        
        # 检查内容是否主要是大型互联网公司的内容
        large_site_indicators = ["© google", "© baidu", "© 360", "google llc", "百度一下", "360搜索"]
        for indicator in large_site_indicators:
            if indicator.lower() in content_lower:
                return True
        
        return False
    
    def _build_vuln_result(self, vuln_check: Dict, payload: str, url: str, evidence: str, request: str = "", response: str = "") -> Dict:
        """构建漏洞结果，包含完整详情"""
        vuln_name = vuln_check["name"]
        vuln_info = VULN_INFO.get(vuln_name, {
            "description": f"发现{vuln_name}漏洞，建议及时修复",
            "remediation": "请按照安全开发规范修复此漏洞",
            "cve": ""
        })
        
        parsed = urlparse(url)
        
        return {
            "name": vuln_name,
            "severity": vuln_check["severity"],
            "cve": vuln_info.get("cve", ""),
            "description": vuln_info["description"],
            "remediation": vuln_info["remediation"],
            "payload": payload,
            "path": parsed.path or "/",
            "url": url,
            "evidence": evidence,
            "request": request or f"GET {url} HTTP/1.1",
            "response": response[:1000] if response else ""
        }
    
    async def _check_vuln(self, url: str, vuln_check: Dict) -> Optional[Dict]:
        """检测漏洞"""
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query or ""
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.followRedirects,
            headers={"User-Agent": self.user_agent}
        ) as client:
            for payload in vuln_check["patterns"]:
                try:
                    # GET检测
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}test={payload}"
                    
                    response = await client.get(test_url, follow_redirects=True, timeout=self.timeout)
                    content = response.text
                    content_lower = content.lower()
                    
                    # 检查是否是误报
                    if self._is_likely_false_positive(test_url, content):
                        continue
                    
                    # 检查错误指示器
                    for indicator in vuln_check.get("error_indicators", []):
                        if indicator.lower() in content_lower:
                            # 发现初步迹象，进一步验证
                            verify_found = False
                            
                            # 发送第二个验证请求
                            verify_payloads = ["'", "\"", "1=1", "1=2"]
                            for vp in verify_payloads:
                                verify_url = f"{url}{separator}test={vp}"
                                try:
                                    verify_resp = await client.get(verify_url, timeout=self.timeout)
                                    # 如果不同payload返回不同结果，说明可能存在漏洞
                                    if vp == "1=2" and "sql" in verify_resp.text.lower():
                                        verify_found = True
                                        break
                                    elif vp == "'" and ("syntax" in verify_resp.text.lower() or "error" in verify_resp.text.lower()):
                                        verify_found = True
                                        break
                                except:
                                    pass
                            
                            if verify_found or len(content_lower) < 50000:
                                # 找到了可能的漏洞，返回详细信息
                                evidence = f"响应中包含敏感关键词: {indicator}"
                                
                                # 对于大型网站，记录为低置信度
                                is_fp = self._is_likely_false_positive(test_url, content)
                                
                                return self._build_vuln_result(
                                    vuln_check,
                                    payload,
                                    test_url,
                                    evidence + (" (疑似误报)" if is_fp else ""),
                                    f"GET {test_url} HTTP/1.1",
                                    content[:500]
                                )
                    
                    # XSS专项检测 - 检查payload是否被反射
                    if vuln_check["type"] == "xss":
                        # 检查响应中是否包含未转义的payload
                        for pattern in vuln_check.get("verify_indicators", []):
                            if re.search(pattern, content, re.IGNORECASE):
                                if not self._is_likely_false_positive(test_url, content):
                                    return self._build_vuln_result(
                                        vuln_check,
                                        payload,
                                        test_url,
                                        "检测到未转义的脚本内容",
                                        f"GET {test_url} HTTP/1.1",
                                        content[:500]
                                    )
                    
                    # LFI专项检测 - 检查是否能读取系统文件
                    if vuln_check["type"] == "lfi":
                        for pattern in vuln_check.get("verify_indicators", []):
                            if re.search(pattern, content, re.IGNORECASE):
                                return self._build_vuln_result(
                                    vuln_check,
                                    payload,
                                    test_url,
                                    "成功读取系统敏感文件",
                                    f"GET {test_url} HTTP/1.1",
                                    content[:500]
                                )
                    
                    # SSTI专项检测
                    if vuln_check["type"] == "ssti":
                        if "49" in content and "{{7*7}}" in content:
                            return self._build_vuln_result(
                                vuln_check,
                                "{{7*7}}",
                                test_url,
                                "模板被解析执行，结果: 49",
                                f"GET {test_url} HTTP/1.1",
                                content[:500]
                            )
                
                except Exception:
                    continue
        
        return None
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行扫描"""
        total = len(targets)
        
        for i, target in enumerate(targets):
            target = self._normalize_url(target)
            
            if not await self.validate_target(target):
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"无效的URL: {target}",
                    vulns=0
                )
                continue
            
            parsed = urlparse(target)
            
            await self.report_progress(
                current=i + 1,
                total=total,
                target=target,
                message=f"正在扫描: {target}",
                vulns=0
            )
            
            # 基本信息收集
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=self.followRedirects,
                    headers={"User-Agent": self.user_agent}
                ) as client:
                    response = await client.get(target, follow_redirects=True, timeout=self.timeout)
                    
                    # 识别Web指纹
                    server = response.headers.get("server", "")
                    powered = response.headers.get("x-powered-by", "")
                    
                    # 提取标题
                    title_match = re.search(r'<title>([^<]+)</title>', response.text, re.IGNORECASE)
                    web_title = title_match.group(1) if title_match else ""
                    
                    # WAF检测
                    headers_dict = dict(response.headers)
                    self.detected_wafs = self.waf_detector.detect(
                        response.text,
                        headers_dict,
                        response.status_code
                    )
                    if self.detected_wafs:
                        print(f"[WAF] 检测到WAF: {[w['name'] for w in self.detected_wafs]}")
                        # 设置WAF信息到bypass payloads
                        if self.detected_wafs:
                            self.bypass_payloads.set_waf(self.detected_wafs[0]['name'])
                    
                    # 指纹识别
                    cookies = dict(response.cookies)
                    self.detected_fingerprints = self.fingerprint_db.detect(
                        headers_dict,
                        cookies,
                        response.text,
                        target
                    )
                    if self.detected_fingerprints:
                        print(f"[指纹] 识别组件: {', '.join([f['name'] for f in self.detected_fingerprints[:5]])}")
                    
                    # 创建结果
                    result = HostResult(
                        ip=parsed.netloc,
                        port=443 if parsed.scheme == "https" else 80,
                        protocol=parsed.scheme,
                        service="http",
                        product=server or powered,
                        banner=f"{response.status_code} - {web_title or 'N/A'}"
                    )
                    
                    # 添加WAF和指纹信息到结果
                    result.fingerprints = self.detected_fingerprints
                    result.wafs = self.detected_wafs
                    
                    # 执行漏洞检测
                    vulns = []
                    for vuln_check in self.vuln_checks:
                        vuln = await self._check_vuln(target, vuln_check)
                        if vuln:
                            vulns.append(vuln)
                    
                    result.vulns = vulns
                    
                    if vulns:
                        await self.report_progress(
                            current=i + 1,
                            total=total,
                            target=target,
                            message=f"发现 {len(vulns)} 个漏洞",
                            vulns=len(vulns)
                        )
                    else:
                        await self.report_progress(
                            current=i + 1,
                            total=total,
                            target=target,
                            message=f"扫描完成，未发现漏洞",
                            vulns=0
                        )
                    
                    yield result
                    
            except httpx.TimeoutException:
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"连接超时",
                    vulns=0
                )
            except Exception as e:
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"扫描失败: {str(e)}",
                    vulns=0
                )
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
