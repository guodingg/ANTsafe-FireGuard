"""
Xray POC 服务
"""

import httpx
import yaml
import zipfile
import io
import shutil
from pathlib import Path
from typing import List, Dict, Optional
import re

class XrayService:
    """Xray POC 管理服务"""
    
    XRAY_POC_REPO = "https://api.github.com/repos/chaitin/xray/contents/pocs"
    XRAY_POC_GITHUB = "https://github.com/chaitin/xray/tree/master/pocs"
    
    @staticmethod
    def get_poc_dir() -> str:
        """获取POC目录"""
        return "/app/xray-pocs"
    
    @staticmethod
    async def fetch_poc_list() -> List[Dict]:
        """获取Xray POC列表"""
        pocs = []
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(XrayService.XRAY_POC_REPO)
                
                if response.status_code == 200:
                    files = response.json()
                    for f in files:
                        if f['name'].endswith('.yaml') or f['name'].endswith('.yml'):
                            pocs.append({
                                'name': f['name'],
                                'path': f['path'],
                                'download_url': f['download_url'],
                                'size': f.get('size', 0)
                            })
                else:
                    # 如果API失败，使用备用URL
                    pocs = XrayService._parse_poc_from_github_page()
                    
        except Exception as e:
            print(f"获取Xray POC列表失败: {e}")
            # 返回本地已下载的POC
            pocs = XrayService._get_local_pocs()
        
        return pocs
    
    @staticmethod
    def _parse_poc_from_github_page() -> List[Dict]:
        """从GitHub页面解析POC列表"""
        # 简化实现，返回本地POC
        return XrayService._get_local_pocs()
    
    @staticmethod
    def _get_local_pocs() -> List[Dict]:
        """获取本地POC列表"""
        poc_dir = Path(XrayService.get_poc_dir())
        pocs = []
        
        if poc_dir.exists():
            for yaml_file in poc_dir.glob("*.yml"):
                pocs.append({
                    'name': yaml_file.name,
                    'path': str(yaml_file.relative_to(poc_dir)),
                    'size': yaml_file.stat().st_size
                })
        
        return pocs
    
    @staticmethod
    async def download_poc(poc_url: str, filename: str) -> bool:
        """下载单个POC"""
        try:
            poc_dir = Path(XrayService.get_poc_dir())
            poc_dir.mkdir(parents=True, exist_ok=True)
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(poc_url)
                
                if response.status_code == 200:
                    poc_path = poc_dir / filename
                    with open(poc_path, 'wb') as f:
                        f.write(response.content)
                    return True
                    
        except Exception as e:
            print(f"下载POC失败: {e}")
        
        return False
    
    @staticmethod
    async def update_all_pocs(progress_callback=None) -> Dict:
        """更新所有Xray POC"""
        import asyncio
        
        result = {
            'success': True,
            'total': 0,
            'downloaded': 0,
            'failed': 0,
            'categories': {},
            'errors': []
        }
        
        poc_dir = Path(XrayService.get_poc_dir())
        poc_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                # 获取POC列表
                response = await client.get(XrayService.XRAY_POC_REPO)
                
                if response.status_code != 200:
                    result['success'] = False
                    result['errors'].append(f"获取POC列表失败: HTTP {response.status_code}")
                    return result
                
                files = response.json()
                poc_files = [f for f in files if f['name'].endswith(('.yaml', '.yml'))]
                result['total'] = len(poc_files)
                
                # 统计类别
                for f in poc_files:
                    cat = XrayService._guess_category(f['name'])
                    result['categories'][cat] = result['categories'].get(cat, 0) + 1
                
                # 下载每个POC
                for i, f in enumerate(poc_files):
                    try:
                        dl_response = await client.get(f['download_url'])
                        
                        if dl_response.status_code == 200:
                            poc_path = poc_dir / f['name']
                            with open(poc_path, 'wb') as fp:
                                fp.write(dl_response.content)
                            result['downloaded'] += 1
                        
                        if progress_callback:
                            await progress_callback(i + 1, len(poc_files), f'name')
                            
                        # 避免请求过快
                        if (i + 1) % 10 == 0:
                            await asyncio.sleep(0.5)
                            
                    except Exception as e:
                        result['failed'] += 1
                        result['errors'].append(f"{f['name']}: {str(e)}")
                
        except Exception as e:
            result['success'] = False
            result['errors'].append(f"更新失败: {str(e)}")
        
        return result
    
    @staticmethod
    def _guess_category(filename: str) -> str:
        """根据文件名猜测POC类别"""
        name_lower = filename.lower()
        
        categories = {
            'sql': ['sql', 'sqli', 'mysql', 'postgresql', 'oracle', 'mssql'],
            'xss': ['xss', 'cross-site', 'script'],
            'rce': ['rce', 'remote', 'exec', 'command', 'shells'],
            'lfi': ['lfi', 'file', 'include', 'traversal', 'read'],
            'ssrf': ['ssrf', 'url', 'fetch'],
            'csrf': ['csrf', 'cross-site'],
            'redis': ['redis', 'noauth'],
            'mongodb': ['mongodb', 'nosql'],
            'jenkins': ['jenkins'],
            'tomcat': ['tomcat'],
            'weblogic': ['weblogic'],
            'struts': ['struts'],
            'spring': ['spring'],
            'discuz': ['discuz'],
            'wordpress': ['wordpress'],
            'dedecms': ['dedecms', '织梦'],
            'thinkphp': ['thinkphp'],
            'phpunit': ['phpunit'],
            'gitlab': ['gitlab'],
            'jenkins': ['jenkins'],
            'elasticsearch': ['elasticsearch'],
            'vbulletin': ['vbulletin'],
        }
        
        for cat, keywords in categories.items():
            for kw in keywords:
                if kw in name_lower:
                    return cat
        
        return 'other'
    
    @staticmethod
    def get_stats() -> Dict:
        """获取本地Xray POC统计"""
        poc_dir = Path(XrayService.get_poc_dir())
        
        stats = {
            'installed': poc_dir.exists(),
            'total': 0,
            'disk_usage': 0,
            'categories': {},
            'last_update': None
        }
        
        if poc_dir.exists():
            pocs = list(poc_dir.glob("*.yml"))
            stats['total'] = len(pocs)
            
            # 磁盘使用
            total_size = sum(f.stat().st_size for f in poc_dir.rglob('*') if f.is_file())
            stats['disk_usage'] = total_size
            
            # 分类统计
            for p in pocs:
                cat = XrayService._guess_category(p.name)
                stats['categories'][cat] = stats['categories'].get(cat, 0) + 1
            
            # 最后更新时间
            if pocs:
                latest = max(p.stat().st_mtime for p in pocs)
                from datetime import datetime
                stats['last_update'] = datetime.fromtimestamp(latest).isoformat()
        
        return stats
    
    @staticmethod
    async def import_from_zip(zip_content: bytes) -> Dict:
        """从ZIP导入POC"""
        result = {
            'success': True,
            'imported': 0,
            'failed': 0,
            'errors': []
        }
        
        poc_dir = Path(XrayService.get_poc_dir())
        poc_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            zip_buffer = io.BytesIO(zip_content)
            
            with zipfile.ZipFile(zip_buffer, 'r') as zf:
                yaml_files = [f for f in zf.namelist() if f.endswith(('.yaml', '.yml'))]
                
                for yaml_file in yaml_files:
                    try:
                        content = zf.read(yaml_file)
                        filename = Path(yaml_file).name
                        
                        # 验证YAML格式
                        yaml.safe_load(content)
                        
                        # 保存文件
                        with open(poc_dir / filename, 'wb') as f:
                            f.write(content)
                        
                        result['imported'] += 1
                        
                    except Exception as e:
                        result['failed'] += 1
                        result['errors'].append(f"{yaml_file}: {str(e)}")
                        
        except zipfile.BadZipFile:
            result['success'] = False
            result['errors'].append("无效的ZIP文件")
        except Exception as e:
            result['success'] = False
            result['errors'].append(f"导入失败: {str(e)}")
        
        return result
