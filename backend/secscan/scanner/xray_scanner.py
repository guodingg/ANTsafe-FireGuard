"""
Xray POC 扫描器
"""

import asyncio
import httpx
import yaml
import re
from pathlib import Path
from typing import AsyncGenerator, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from secscan.scanner.base import ScannerBase, HostResult

class XrayScanner(ScannerBase):
    """Xray POC 漏洞扫描器"""
    
    # POC目录
    POC_DIR = Path("/app/xray-pocs")
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.task_id = task_id
        self.options = options or {}
        
        self.timeout = self.options.get("timeout", 30)
        self.rate_limit = self.options.get("rate_limit", 10)
        self.user_agent = self.options.get("user_agent", "Mozilla/5.0 (compatible; xray scanner)")
        
        # 加载POC
        self.pocs = self._load_pocs()
        print(f"[XrayScanner] 加载了 {len(self.pocs)} 个POC规则")
    
    def _load_pocs(self) -> List[Dict]:
        """加载本地POC"""
        pocs = []
        poc_dir = Path(self.POC_DIR)
        
        if not poc_dir.exists():
            print(f"[XrayScanner] POC目录不存在: {poc_dir}")
            return pocs
        
        for yaml_file in poc_dir.glob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    poc_data = yaml.safe_load(f)
                
                if not poc_data:
                    continue
                
                # 解析POC
                info = poc_data.get('info', {})
                poc = {
                    'name': info.get('name', yaml_file.stem),
                    'severity': info.get('severity', 'medium'),
                    'description': info.get('description', ''),
                    'cve': info.get('cve-id', ''),
                    'category': info.get('category', ''),
                    'yaml': poc_data,
                    'raw': yaml_file.read_text()
                }
                
                # 解析检测表达式
                if 'expression' in poc_data:
                    poc['expression'] = poc_data['expression']
                
                # 解析请求
                if 'request' in poc_data:
                    poc['request'] = poc_data['request']
                
                pocs.append(poc)
                
            except Exception as e:
                print(f"[XrayScanner] 加载POC失败 {yaml_file.name}: {e}")
        
        return pocs
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        try:
            result = urlparse(target)
            return all([result.scheme in ["http", "https"], result.netloc])
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """标准化URL"""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target
    
    async def _execute_poc(self, client: httpx.AsyncClient, target: str, poc: Dict) -> Optional[Dict]:
        """执行单个POC检测"""
        try:
            request_config = poc.get('request', {})
            method = request_config.get('method', 'get').lower()
            path = request_config.get('path', '/')
            
            # 构建完整URL
            target_url = target.rstrip('/')
            if path.startswith('/'):
                parsed = urlparse(target_url)
                full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            else:
                full_url = f"{target_url}/{path}"
            
            headers = request_config.get('headers', {})
            headers['User-Agent'] = self.user_agent
            
            body = request_config.get('body')
            params = request_config.get('params', {})
            
            # 发送请求
            if method == 'get':
                resp = await client.get(full_url, headers=headers, params=params, timeout=self.timeout, follow_redirects=True)
            elif method == 'post':
                resp = await client.post(full_url, headers=headers, data=body, params=params, timeout=self.timeout, follow_redirects=True)
            else:
                return None
            
            # 检查表达式
            expression = poc.get('expression', '')
            if expression:
                # 简单表达式评估
                if 'response.status' in expression:
                    if f'response.status == {resp.status_code}' in expression or f'response.status_code == {resp.status_code}' in expression:
                        return self._build_result(target, poc, resp)
                
                # 检查响应体
                if 'response.body' in expression or 'response.text' in expression:
                    if any(kw in resp.text for kw in ['sql', 'error', 'syntax', 'mysql', 'postgresql']):
                        return self._build_result(target, poc, resp)
            
            # 检查CVE等关键字
            keywords = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'sql error', 
                       'xss', 'script>', 'onerror=', '<script', 
                       'rce', 'command', 'exec', 'whoami',
                       'path traversal', 'lfi', '../', 'etc/passwd']
            
            resp_lower = resp.text.lower()
            for kw in keywords:
                if kw in resp_lower:
                    return self._build_result(target, poc, resp)
            
        except Exception as e:
            pass
        
        return None
    
    def _build_result(self, target: str, poc: Dict, resp) -> Dict:
        """构建结果"""
        parsed = urlparse(target)
        
        return {
            'name': poc['name'],
            'severity': poc['severity'],
            'cve': poc.get('cve', ''),
            'description': poc.get('description', ''),
            'category': poc.get('category', ''),
            'path': parsed.path or '/',
            'url': target,
            'evidence': f"响应状态: {resp.status_code}, 长度: {len(resp.text)}",
            'response': resp.text[:500]
        }
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行Xray扫描"""
        valid_targets = [self._normalize_url(t) for t in targets if await self.validate_target(t)]
        
        if not valid_targets:
            return
        
        total = len(valid_targets)
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for i, target in enumerate(valid_targets):
                await self.report_progress(
                    current=i + 1,
                    total=total,
                    target=target,
                    message=f"Xray扫描: {target}",
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
                
                vulns = []
                
                # 执行POC检测
                for poc in self.pocs[:50]:  # 限制检测数量避免太慢
                    vuln = await self._execute_poc(client, target, poc)
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
                
                yield result
        
        await self.close()
    
    async def close(self):
        """清理"""
        pass
