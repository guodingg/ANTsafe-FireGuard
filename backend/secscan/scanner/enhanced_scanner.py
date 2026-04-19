"""
增强扫描器 - 集成FLUX优秀功能
包含：云安全、K8s/容器安全、CI/CD检测、WAF绕过、断点续扫
"""

import asyncio
import httpx
import re
import hashlib
from typing import AsyncGenerator, List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

from secscan.scanner.base import ScannerBase, HostResult
from secscan.scanner.waf_detector import detect_waf, get_bypass_headers, get_bypass_ua
from secscan.scanner.bypass_payloads import get_bypass_payloads
from secscan.scanner.fingerprint_db import detect_fingerprint
from secscan.scanner.rate_limiter import get_rate_limiter
from secscan.scanner.csrf_token import get_csrf_extractor, get_cookie_persistence
from secscan.scanner.differential_tester import get_differential_tester
from secscan.scanner.js_analyzer import get_js_extractor
from secscan.scanner.scan_state import get_scan_state_manager

# 云服务商Access Key检测模式
CLOUD_KEY_PATTERNS = {
    "aws": {
        "access_key": r'AKIA[0-9A-Z]{16}',
        "secret_key": r'(?i)aws[_-]?secret[_-]?access[_-]?key[:\s]*["\'][A-Za-z0-9/+=]{40}["\']',
    },
    "aliyun": {
        "access_key": r'(?i)(aliyun|aliyundl)[_-]?access[_-]?key[_-]?id[:\s]*["\'][a-zA-Z0-9]{24}["\']',
        "secret_key": r'(?i)(aliyun|aliyundl)[_-]?secret[:\s]*["\'][a-zA-Z0-9]{30}["\']',
    },
    "tencent": {
        "secret_id": r'(?i)qcloud[_-]?secret[_-]?id[:\s]*["\'][A-Z0-9]{40}["\']',
        "secret_key": r'(?i)qcloud[_-]?secret[_-]?key[:\s]*["\'][a-zA-Z0-9]{32}["\']',
    },
    "huawei": {
        "access_key": r'(?i)huawei[_-]?cloud[_-]?access[_-]?key[:\s]*["\'][a-zA-Z0-9]{20,32}["\']',
        "secret_key": r'(?i)huawei[_-]?cloud[_-]?secret[:\s]*["\'][a-zA-Z0-9]{30,40}["\']',
    },
    "azure": {
        "storage_key": r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
    },
    "google": {
        "api_key": r'AIza[0-9A-Za-z\-_]{35}',
        "service_account": r'"type": "service_account"',
    }
}

# 云存储桶检测模式
BUCKET_PATTERNS = [
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.s3\.amazonaws\.com)',
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.blob\.core\.windows\.net)',
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.oss\.aliyuncs\.com)',
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.cos\.myqcloud\.com)',
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.obs\.hwclouds\.com)',
    r'(?:https?://)?([a-z0-9][-a-z0-9]*\.bos\.yunbaidu\.com)',
    r'bucket=([a-z0-9][-a-z0-9]*)',
    r'Bucket:?\s*([a-z0-9][-a-z0-9]*)',
]

# CI/CD配置文件检测
CICD_PATTERNS = {
    "gitlab_ci": [r'\.gitlab-ci\.yml', r'gitlayers', r'before_script:', r'after_script:'],
    "jenkins": [r'Jenkinsfile', r'credentials\.xml', r'\$BUILD_NUMBER', r'node\s*{'],
    "github_actions": [r'\.github/workflows/', r'on:\s*(push|pull_request)', r'jobs:', r'steps:'],
    "docker": [r'Dockerfile', r'docker-compose\.ya?ml', r'FROM\s+\w+', r'RUN\s+'],
    "k8s": [r'deployment\.yaml', r'service\.yaml', r'ingress\.yaml', r'kubectl'],
    "terraform": [r'terraform', r'resource\s+"', r'provider\s+"', r'\.tfstate'],
}

# 敏感Token模式
TOKEN_PATTERNS = [
    # Git
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
    (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
    (r'github[_-]?token[:\s]*["\'][a-zA-Z0-9_\-]{36,40}["\']', 'GitHub Token'),
    # Docker
    (r'(?i)docker[_-]?hub[_-]?token[:\s]*["\'][^"\']{36}["\']', 'Docker Hub Token'),
    # Slack
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'Slack Token'),
    # NPM
    (r'npm_[A-Za-z0-9]{36}', 'NPM Token'),
    # AWS
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    # PyPI
    (r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_~]{50,100}', 'PyPI Token'),
]


class EnhancedScanner:
    """增强扫描器 - 集成FLUX优秀功能"""
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        self.task_id = task_id
        self.options = options or {}
        
        # 扫描配置
        self.timeout = self.options.get("timeout", 15)
        self.maxConcurrency = self.options.get("maxConcurrency", 10)
        self.user_agent = self.options.get("user_agent", "ANTsafe Security Scanner/2.0")
        
        # 功能开关
        self.enable_waf_detection = self.options.get("enable_waf_detection", True)
        self.enable_bypass = self.options.get("enable_bypass", True)
        self.enable_cloud_security = self.options.get("enable_cloud_security", True)
        self.enable_k8s_security = self.options.get("enable_k8s_security", True)
        self.enable_cicd_security = self.options.get("enable_cicd_security", True)
        self.enable_js_analysis = self.options.get("enable_js_analysis", True)
        self.enable_differential_test = self.options.get("enable_differential_test", True)
        self.enable_rate_limit = self.options.get("enable_rate_limit", True)
        
        # 初始化组件
        self.rate_limiter = get_rate_limiter(initial_rate=self.maxConcurrency)
        self.differential_tester = get_differential_tester(timeout=self.timeout)
        self.csrf_extractor = get_csrf_extractor()
        self.cookie_persistence = get_cookie_persistence()
        self.js_extractor = get_js_extractor()
        self.scan_state_manager = get_scan_state_manager()
        
        # 检测结果
        self.detected_wafs = []
        self.detected_fingerprints = []
        self.discovered_secrets = []
        self.discovered_buckets = []
        self.discovered_cicd = []
    
    async def scan(self, target: str, progress_callback=None) -> AsyncGenerator[Dict, None]:
        """
        执行增强扫描
        
        Args:
            target: 目标URL
            progress_callback: 进度回调函数
            
        Yields:
            扫描结果
        """
        target = self._normalize_url(target)
        
        if progress_callback:
            await progress_callback(0, 100, "初始化扫描...")
        
        # 获取或创建扫描状态（断点续扫）
        scan_state = self.scan_state_manager.get_state(self.task_id)
        scan_state.update_status("running")
        scan_state.start_timer()
        
        try:
            # 1. WAF检测
            if self.enable_waf_detection:
                if progress_callback:
                    await progress_callback(5, 100, "检测WAF...")
                await self._detect_waf(target)
            
            # 2. 指纹识别
            if progress_callback:
                await progress_callback(10, 100, "识别Web指纹...")
            await self._detect_fingerprint(target)
            
            # 3. JS敏感信息提取
            if self.enable_js_analysis:
                if progress_callback:
                    await progress_callback(15, 100, "分析JavaScript敏感信息...")
                await self._analyze_js_files(target)
            
            # 4. 云安全检测
            if self.enable_cloud_security:
                if progress_callback:
                    await progress_callback(30, 100, "检测云安全...")
                await self._scan_cloud_security(target)
            
            # 5. CI/CD配置检测
            if self.enable_cicd_security:
                if progress_callback:
                    await progress_callback(50, 100, "检测CI/CD配置...")
                await self._scan_cicd_config(target)
            
            # 6. K8s/容器安全检测
            if self.enable_k8s_security:
                if progress_callback:
                    await progress_callback(70, 100, "检测K8s/容器安全...")
                await self._scan_container_security(target)
            
            # 7. Web漏洞检测（带WAF绕过）
            if progress_callback:
                await progress_callback(80, 100, "Web漏洞检测...")
            web_vulns = await self._scan_web_vulns(target)
            
            scan_state.update_status("completed")
            scan_state.end_timer()
            scan_state.update_progress(100)
            
            yield {
                "type": "scan_complete",
                "target": target,
                "wafs": self.detected_wafs,
                "fingerprints": self.detected_fingerprints,
                "secrets": self.discovered_secrets,
                "buckets": self.discovered_buckets,
                "cicd": self.discovered_cicd,
                "web_vulns": web_vulns,
            }
            
        except Exception as e:
            scan_state.update_status("failed")
            scan_state.add_error(str(e))
            yield {"type": "error", "message": str(e)}
    
    async def _detect_waf(self, target: str):
        """检测WAF"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(target)
                
                headers = dict(response.headers)
                self.detected_wafs = detect_waf(
                    response.text,
                    headers,
                    response.status_code
                )
                
                if self.detected_wafs:
                    print(f"[EnhancedScanner] 检测到WAF: {[w['name'] for w in self.detected_wafs]}")
                    
                    # 根据WAF类型获取绕过策略
                    waf_name = self.detected_wafs[0]['name']
                    bypass_ua = get_bypass_ua(waf_name)
                    bypass_headers = get_bypass_headers(waf_name)
                    
                    if bypass_ua:
                        self.user_agent = bypass_ua
                    if bypass_headers:
                        print(f"[EnhancedScanner] 已启用绕过策略 for {waf_name}")
                        
        except Exception as e:
            print(f"[EnhancedScanner] WAF检测失败: {e}")
    
    async def _detect_fingerprint(self, target: str):
        """识别Web指纹"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(target)
                
                cookies = dict(response.cookies)
                headers = dict(response.headers)
                
                self.detected_fingerprints = detect_fingerprint(
                    headers,
                    cookies,
                    response.text,
                    target
                )
                
                if self.detected_fingerprints:
                    print(f"[EnhancedScanner] 识别组件: {[f['name'] for f in self.detected_fingerprints[:5]]}")
                    
        except Exception as e:
            print(f"[EnhancedScanner] 指纹识别失败: {e}")
    
    async def _analyze_js_files(self, target: str):
        """分析JS文件中的敏感信息"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # 获取页面
                response = await client.get(target)
                
                # 提取JS文件URL
                js_urls = self._extract_js_urls(response.text, target)
                
                # 分析每个JS文件
                for js_url in js_urls[:20]:  # 限制数量
                    try:
                        js_response = await client.get(js_url)
                        if js_response.status_code == 200:
                            # 提取敏感信息
                            secrets = self.js_extractor.extract(js_response.text, js_url)
                            self.discovered_secrets.extend(secrets)
                            
                            # 提取API端点
                            endpoints = self.js_extractor.extract_endpoints(js_response.text, js_url)
                            
                            # 提取敏感路径
                            paths = self.js_extractor.extract_paths(js_response.text)
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"[EnhancedScanner] JS分析失败: {e}")
    
    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """提取JS文件URL"""
        js_urls = []
        
        # <script src="...">
        pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        matches = re.finditer(pattern, html, re.IGNORECASE)
        for match in matches:
            url = match.group(1)
            if not url.startswith('http'):
                url = urljoin(base_url, url)
            js_urls.append(url)
        
        # 去除重复和第三方JS
        seen = set()
        unique_urls = []
        for url in js_urls:
            if url not in seen and base_url.split('/')[2] in url:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    async def _scan_cloud_security(self, target: str):
        """云安全检测"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(target)
                content = response.text
                
                # 检测云Access Key
                for cloud_name, patterns in CLOUD_KEY_PATTERNS.items():
                    for key_type, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            self.discovered_secrets.append({
                                "type": f"{cloud_name}_{key_type}",
                                "value": match.group(0)[:100],
                                "source": "cloud_key",
                                "confidence": 0.8
                            })
                
                # 检测云存储桶
                for pattern in BUCKET_PATTERNS:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        bucket = match.group(1) if match.lastindex else match.group(0)
                        
                        # 检测存储桶遍历
                        traversal_vuln = await self._check_bucket_traversal(client, bucket)
                        
                        self.discovered_buckets.append({
                            "bucket": bucket,
                            "url": match.group(0),
                            "traversal": traversal_vuln
                        })
                        
        except Exception as e:
            print(f"[EnhancedScanner] 云安全检测失败: {e}")
    
    async def _check_bucket_traversal(self, client: httpx.AsyncClient, bucket: str) -> bool:
        """检测存储桶遍历漏洞"""
        try:
            # 尝试访问存储桶根目录
            test_urls = [
                f"https://{bucket}",
                f"https://{bucket}/",
                f"https://{bucket}?max-keys=1000",
            ]
            
            for url in test_urls:
                try:
                    response = await client.get(url, timeout=10)
                    if response.status_code == 200:
                        # 检查是否返回了文件列表
                        if 'Contents' in response.text or 'CommonPrefixes' in response.text:
                            return True
                except:
                    continue
                    
        except Exception:
            pass
        
        return False
    
    async def _scan_cicd_config(self, target: str):
        """CI/CD配置安全检测"""
        try:
            # 常见CI/CD配置文件
            cicd_paths = [
                "/.gitlab-ci.yml",
                "/.gitlab-ci.yaml", 
                "/Jenkinsfile",
                "/.github/workflows/*.yml",
                "/.github/workflows/*.yaml",
                "/.github/workflows/*.json",
                "/docker-compose.yml",
                "/docker-compose.yaml",
                "/Dockerfile",
                "/deployment.yaml",
                "/deployment.yml",
                "/service.yaml",
                "/service.yml",
                "/config.yaml",
                "/config.yml",
                "/terraform.tfstate",
                "/.tf",
                "/credentials.json",
                "/secrets.yml",
                "/.env",
                "/.env.production",
                "/.env.local",
            ]
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for path in cicd_paths:
                    try:
                        url = urljoin(target, path)
                        response = await client.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            # 分析配置文件内容
                            content = response.text
                            
                            # 检测敏感信息
                            for pattern, desc in TOKEN_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.discovered_cicd.append({
                                        "path": path,
                                        "type": "sensitive_token",
                                        "description": desc,
                                        "url": url
                                    })
                            
                            # 检测配置文件类型
                            for cicd_type, signatures in CICD_PATTERNS.items():
                                for sig in signatures:
                                    if re.search(sig, content, re.IGNORECASE):
                                        self.discovered_cicd.append({
                                            "path": path,
                                            "type": cicd_type,
                                            "description": f"发现{cicd_type}配置文件",
                                            "url": url
                                        })
                                        break
                                        
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"[EnhancedScanner] CI/CD检测失败: {e}")
    
    async def _scan_container_security(self, target: str):
        """K8s/容器安全检测"""
        try:
            # K8s API端点
            k8s_endpoints = [
                "/api/v1",
                "/api/v1/namespaces",
                "/api/v1/pods",
                "/api/v1/secrets",
                "/api/v1/configmaps",
                "/apis/apps/v1/deployments",
                "/swagger.json",
                "/swagger-ui/",
                "/api",
                "/kapis/",
                "/healthz",
                "/readyz",
                "/livez",
            ]
            
            # Docker API端点
            docker_endpoints = [
                "/containers/json",
                "/images/json",
                "/volumes",
                "/info",
                "/version",
            ]
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # 检测K8s
                for endpoint in k8s_endpoints[:5]:
                    try:
                        url = urljoin(target, endpoint)
                        response = await client.get(url, timeout=5)
                        
                        if response.status_code in [200, 401, 403]:
                            # 可能存在K8s API
                            if "kubernetes" in response.text.lower() or \
                               "namespaces" in response.text or \
                               response.status_code in [401, 403]:
                                # 发现K8s组件
                                self.discovered_cicd.append({
                                    "type": "kubernetes",
                                    "endpoint": endpoint,
                                    "status_code": response.status_code,
                                    "url": url,
                                    "description": "发现Kubernetes API端点"
                                })
                    except:
                        continue
                
                # 检测Docker
                for endpoint in docker_endpoints[:3]:
                    try:
                        url = urljoin(target, endpoint)
                        response = await client.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            if "Containers" in response.text or "Images" in response.text:
                                self.discovered_cicd.append({
                                    "type": "docker",
                                    "endpoint": endpoint,
                                    "status_code": response.status_code,
                                    "url": url,
                                    "description": "发现Docker API端点"
                                })
                    except:
                        continue
                        
        except Exception as e:
            print(f"[EnhancedScanner] 容器安全检测失败: {e}")
    
    async def _scan_web_vulns(self, target: str):
        """Web漏洞检测（带WAF绕过）"""
        vulns = []
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # 获取绕过头部
                bypass_headers = {}
                if self.detected_wafs:
                    bypass_headers = get_bypass_headers(self.detected_wafs[0]['name'])
                
                # 使用差分测试检测漏洞
                if self.enable_differential_test:
                    differential_tester = get_differential_tester(timeout=self.timeout)
                    
                    # 获取页面基本响应
                    baseline = await differential_tester.get_baseline(client, target)
                    
                    # 使用Bypass Payload测试
                    bypass_payloads = get_bypass_payloads()
                    
                    # SQL注入测试
                    sqli_payloads = bypass_payloads.get_sqli_payloads()[:20]
                    for payload in sqli_payloads:
                        test_url = f"{target}?id={payload}"
                        try:
                            response = await client.get(test_url, headers=bypass_headers)
                            
                            # 使用差分测试
                            result = differential_tester.compare(
                                baseline,
                                differential_tester._build_baseline_response(response, 0)
                            )
                            
                            if result.is_vulnerable:
                                vulns.append({
                                    "type": "sqli",
                                    "url": test_url,
                                    "payload": payload,
                                    "confidence": result.confidence,
                                    "evidence": result.evidence
                                })
                                break  # 找到一个就够了
                        except:
                            continue
                    
                    # XSS测试
                    xss_payloads = bypass_payloads.get_xss_payloads()[:20]
                    for payload in xss_payloads:
                        test_url = f"{target}?q={payload}"
                        try:
                            response = await client.get(test_url, headers=bypass_headers)
                            
                            # 检查反射
                            if payload in response.text:
                                vulns.append({
                                    "type": "xss",
                                    "url": test_url,
                                    "payload": payload,
                                    "confidence": 0.7,
                                    "evidence": f"Payload反射在响应中"
                                })
                                break
                        except:
                            continue
                            
        except Exception as e:
            print(f"[EnhancedScanner] Web漏洞检测失败: {e}")
        
        return vulns
    
    def _normalize_url(self, url: str) -> str:
        """标准化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    async def close(self):
        """清理资源"""
        self.differential_tester.clear_baseline_cache()
