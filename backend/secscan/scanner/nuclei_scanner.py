"""
Nuclei扫描器 - 集成开源漏洞扫描
"""

import asyncio
import json
import subprocess
import yaml
from pathlib import Path
from typing import AsyncGenerator, List, Dict, Any, Optional
from datetime import datetime

from secscan.scanner.base import ScannerBase, HostResult

class NucleiScanner(ScannerBase):
    """Nuclei漏洞扫描器"""
    
    # 默认模板目录
    DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent.parent.parent / "data" / "nuclei-templates"
    
    def __init__(self, task_id: int, options: Dict[str, Any] = None):
        super().__init__(task_id, options)
        self.task_id = task_id
        self.options = options or {}
        
        # Nuclei配置
        self.nuclei_path = self.options.get("nuclei_path", "nuclei")
        self.template_dir = self.options.get("template_dir", str(self.DEFAULT_TEMPLATE_DIR))
        self.rate_limit = self.options.get("rate_limit", 150)  # 请求/秒
        self.timeout = self.options.get("timeout", 5)
        self.retries = self.options.get("retries", 1)
        
        # 扫描模式
        self.severity = self.options.get("severity", ["critical", "high", "medium", "low", "info"])
        self.tags = self.options.get("tags", [])  # 自定义标签筛选
        
        # 统计
        self.stats = {
            "requests_sent": 0,
            "matched": 0,
            "errors": 0
        }
    
    async def validate_target(self, target: str) -> bool:
        """验证目标"""
        return target.startswith(("http://", "https://", "://"))
    
    async def scan(self, targets: List[str]) -> AsyncGenerator[HostResult, None]:
        """执行Nuclei扫描"""
        # 过滤有效目标
        valid_targets = [t.strip() for t in targets if await self.validate_target(t.strip())]
        
        if not valid_targets:
            return
        
        total = len(valid_targets)
        
        for i, target in enumerate(valid_targets):
            await self.report_progress(
                current=i + 1,
                total=total,
                target=target,
                message=f"Nuclei扫描: {target}",
                vulns=0
            )
            
            # 执行Nuclei扫描
            results = await self._run_nuclei(target)
            
            for result in results:
                yield result
        
        await self.close()
    
    async def _run_nuclei(self, target: str) -> List[HostResult]:
        """运行Nuclei扫描"""
        results = []
        
        try:
            # 构建Nuclei命令
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-json",  # JSON输出
                "-silent",  # 只输出结果
                "-rate-limit", str(self.rate_limit),
                "-timeout", str(self.timeout),
                "-retries", str(self.retries),
            ]
            
            # 添加severity过滤
            for sev in self.severity:
                cmd.extend(["-severity", sev])
            
            # 添加模板目录
            if Path(self.template_dir).exists():
                cmd.extend(["-t", self.template_dir])
            
            # 运行命令
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout * 60  # 默认超时
            )
            
            # 解析JSON输出
            if stdout:
                for line in stdout.decode('utf-8').strip().split('\n'):
                    if line:
                        try:
                            nuclei_result = json.loads(line)
                            host_result = self._parse_nuclei_result(nuclei_result, target)
                            if host_result:
                                results.append(host_result)
                        except json.JSONDecodeError:
                            continue
            
            self.stats["requests_sent"] += 1
            
        except asyncio.TimeoutError:
            self.stats["errors"] += 1
        except FileNotFoundError:
            # Nuclei未安装
            print(f"[警告] Nuclei未安装: {self.nuclei_path}")
            # 返回模拟结果
            results.append(self._create_mock_result(target))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[错误] Nuclei扫描失败: {e}")
        
        return results
    
    def _parse_nuclei_result(self, nuclei_result: Dict, target: str) -> Optional[HostResult]:
        """解析Nuclei结果"""
        try:
            info = nuclei_result.get("info", {})
            matched = nuclei_result.get("matched-at", target)
            template = nuclei_result.get("template-id", "")
            
            # 提取IP
            from urllib.parse import urlparse
            parsed = urlparse(matched)
            ip = parsed.netloc or target
            
            host_result = HostResult(
                ip=ip,
                port=443 if parsed.scheme == "https" else 80,
                protocol=parsed.scheme or "https",
                service="http",
                product=info.get("name", template),
                banner=info.get("description", "")
            )
            
            # 添加漏洞信息
            host_result.vulns = [{
                "name": info.get("name", "未知漏洞"),
                "severity": info.get("severity", "medium"),
                "cve": info.get("cve-id", ""),
                "cwe": info.get("cwe-id", ""),
                "description": info.get("description", ""),
                "matched_at": matched,
                "template_id": template,
                "reference": info.get("reference", []),
                "remediation": info.get("classification", {}).get("remediation", "")
            }]
            
            self.stats["matched"] += 1
            return host_result
            
        except Exception as e:
            print(f"[错误] 解析Nuclei结果失败: {e}")
            return None
    
    def _create_mock_result(self, target: str) -> HostResult:
        """创建模拟结果（当Nuclei未安装时）"""
        return HostResult(
            ip=target,
            port=80,
            protocol="http",
            service="http",
            banner="Nuclei模拟扫描结果"
        )
    
    async def close(self):
        """清理"""
        pass
    
    @classmethod
    async def update_templates(cls, template_dir: str = None) -> Dict[str, Any]:
        """更新Nuclei模板库"""
        template_dir = template_dir or str(cls.DEFAULT_TEMPLATE_DIR)
        
        result = {
            "success": False,
            "templates_dir": template_dir,
            "templates_count": 0,
            "categories": [],
            "message": ""
        }
        
        try:
            # 克隆或更新nuclei-templates
            template_path = Path(template_dir)
            
            if not template_path.exists():
                # 首次下载
                cmd = ["git", "clone", "--depth", "1", 
                       "https://github.com/projectdiscovery/nuclei-templates.git",
                       template_dir]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    result["success"] = True
                    result["message"] = "模板库下载成功"
                else:
                    result["message"] = f"下载失败: {stderr.decode()}"
            else:
                # 更新现有模板
                cmd = ["git", "-C", template_dir, "pull", "--rebase"]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    result["success"] = True
                    result["message"] = "模板库更新成功"
                else:
                    result["message"] = f"更新失败: {stderr.decode()}"
            
            # 统计模板数量
            if template_path.exists():
                templates = list(template_path.rglob("*.yaml"))
                result["templates_count"] = len(templates)
                
                # 统计分类
                categories = set()
                for t in templates[:1000]:  # 只检查前1000个
                    try:
                        with open(t, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            if data and 'info' in data:
                                cat = data['info'].get('classification', {}).get('category', '')
                                if cat:
                                    categories.add(cat)
                    except:
                        pass
                
                result["categories"] = list(categories)
            
        except FileNotFoundError:
            result["message"] = "Git未安装，无法更新模板库"
        except Exception as e:
            result["message"] = f"更新失败: {str(e)}"
        
        return result
