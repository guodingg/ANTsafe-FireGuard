"""
Nuclei服务 - 管理和执行Nuclei扫描
"""

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

class NucleiService:
    """Nuclei服务管理器"""
    
    # 模板目录
    TEMPLATE_DIR = Path(__file__).parent.parent.parent / "data" / "nuclei-templates"
    
    # Nuclei路径
    NUCLEI_PATH = "nuclei"
    
    _template_cache: Dict[str, Any] = {}
    
    @classmethod
    def get_template_dir(cls) -> str:
        """获取模板目录"""
        cls.TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
        return str(cls.TEMPLATE_DIR)
    
    @classmethod
    async def update_templates(cls) -> Dict[str, Any]:
        """更新模板库"""
        template_dir = cls.get_template_dir()
        
        result = {
            "success": False,
            "templates_dir": template_dir,
            "templates_count": 0,
            "templates_by_category": {},
            "message": ""
        }
        
        try:
            # 检查git是否存在
            import shutil
            if not shutil.which("git"):
                return {"success": False, "message": "Git未安装，无法下载模板库"}
            
            template_path = Path(template_dir)
            
            if not template_path.exists() or not list(template_path.glob("*.yaml")):
                # 首次下载
                print(f"[Nuclei] 首次下载模板库到 {template_dir}")
                
                process = await asyncio.create_subprocess_exec(
                    "git", "clone", "--depth", "1",
                    "https://github.com/projectdiscovery/nuclei-templates.git",
                    template_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    return {"success": False, "message": f"下载失败: {stderr.decode()}"}
                
                result["message"] = "模板库下载成功"
            else:
                # 更新
                print(f"[Nuclei] 更新现有模板库")
                
                process = await asyncio.create_subprocess_exec(
                    "git", "-C", template_dir, "pull", "--rebase",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    result["message"] = "模板库更新成功"
                else:
                    result["message"] = f"更新失败，将使用现有模板"
            
            # 统计模板
            templates = list(template_path.rglob("*.yaml"))
            result["templates_count"] = len(templates)
            
            # 按分类统计
            categories = {}
            for t in templates:
                try:
                    with open(t, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if data and 'info' in data:
                            info = data['info']
                            cat = info.get('category', 'other')
                            if cat not in categories:
                                categories[cat] = {"count": 0, "templates": []}
                            categories[cat]["count"] += 1
                            if len(categories[cat]["templates"]) < 5:
                                categories[cat]["templates"].append({
                                    "name": info.get("name", ""),
                                    "severity": info.get("severity", ""),
                                    "path": str(t.relative_to(template_path))
                                })
                except:
                    pass
            
            result["templates_by_category"] = categories
            result["success"] = True
            
            # 更新缓存
            cls._template_cache = result
            
        except FileNotFoundError:
            result["message"] = "Git未安装"
        except Exception as e:
            result["message"] = f"更新失败: {str(e)}"
        
        return result
    
    @classmethod
    def get_templates(cls) -> Dict[str, Any]:
        """获取模板列表"""
        if cls._template_cache:
            return cls._template_cache
        
        # 从磁盘加载
        template_dir = Path(cls.get_template_dir())
        if not template_dir.exists():
            return {"templates_count": 0, "templates_by_category": {}}
        
        result = {"templates_count": 0, "templates_by_category": {}}
        templates = list(template_dir.rglob("*.yaml"))
        result["templates_count"] = len(templates)
        
        categories = {}
        for t in templates[:500]:
            try:
                with open(t, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'info' in data:
                        info = data['info']
                        cat = info.get('category', 'other')
                        if cat not in categories:
                            categories[cat] = {"count": 0}
                        categories[cat]["count"] += 1
            except:
                pass
        
        result["templates_by_category"] = categories
        return result
    
    @classmethod
    async def search_templates(
        cls, 
        keyword: str = None,
        severity: str = None,
        category: str = None,
        tags: List[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """搜索模板"""
        template_dir = Path(cls.get_template_dir())
        
        if not template_dir.exists():
            return []
        
        results = []
        templates = list(template_dir.rglob("*.yaml"))
        
        for t in templates:
            if len(results) >= limit:
                break
            
            try:
                with open(t, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if not data or 'info' not in data:
                        continue
                    
                    info = data['info']
                    
                    # 关键词过滤
                    if keyword:
                        name = info.get('name', '').lower()
                        desc = info.get('description', '').lower()
                        if keyword.lower() not in name and keyword.lower() not in desc:
                            continue
                    
                    # 严重性过滤
                    if severity and info.get('severity', '') != severity:
                        continue
                    
                    # 分类过滤
                    if category and info.get('category', '') != category:
                        continue
                    
                    # 标签过滤
                    if tags:
                        template_tags = info.get('tags', [])
                        if not any(tag in template_tags for tag in tags):
                            continue
                    
                    results.append({
                        "id": data.get('id', t.stem),
                        "name": info.get('name', ''),
                        "severity": info.get('severity', ''),
                        "description": info.get('description', ''),
                        "category": info.get('category', ''),
                        "tags": info.get('tags', []),
                        "cve": info.get('cve-id', ''),
                        "cwe": info.get('cwe-id', ''),
                        "path": str(t.relative_to(template_dir)),
                        "matched": True
                    })
                    
            except:
                continue
        
        return results
    
    @classmethod
    def get_template_detail(cls, template_id: str) -> Optional[Dict[str, Any]]:
        """获取模板详情"""
        template_dir = Path(cls.get_template_dir())
        
        # 直接搜索
        for t in template_dir.rglob(f"{template_id}.yaml"):
            try:
                with open(t, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data:
                        return {
                            "id": data.get('id', template_id),
                            "name": data.get('name', ''),
                            "info": data.get('info', {}),
                            "path": str(t),
                            "raw": open(t, 'r', encoding='utf-8').read()
                        }
            except:
                pass
        
        return None
    
    @classmethod
    async def run_scan(
        cls,
        target: str,
        template_ids: List[str] = None,
        severity: List[str] = None,
        tags: List[str] = None,
        rate_limit: int = 150
    ) -> List[Dict[str, Any]]:
        """运行Nuclei扫描"""
        results = []
        
        try:
            cmd = [
                cls.NUCLEI_PATH,
                "-u", target,
                "-json", "-silent",
                "-rate-limit", str(rate_limit)
            ]
            
            # 添加severity过滤
            if severity:
                for sev in severity:
                    cmd.extend(["-severity", sev])
            
            # 添加特定模板
            if template_ids:
                template_dir = cls.get_template_dir()
                for tid in template_ids:
                    path = Path(template_dir) / tid
                    if path.exists():
                        cmd.extend(["-t", str(path)])
            
            # 添加标签过滤
            if tags:
                for tag in tags:
                    cmd.extend(["-tag", tag])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )
            
            if stdout:
                for line in stdout.decode('utf-8').strip().split('\n'):
                    if line:
                        try:
                            results.append(json.loads(line))
                        except:
                            pass
                            
        except FileNotFoundError:
            print("[警告] Nuclei未安装")
        except asyncio.TimeoutError:
            print("[警告] Nuclei扫描超时")
        except Exception as e:
            print(f"[错误] Nuclei扫描失败: {e}")
        
        return results
