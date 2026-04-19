"""
JS敏感信息提取器
从JavaScript文件中提取API密钥、Token、路径等敏感信息
"""

import re
import math
import httpx
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

@dataclass
class SecretMatch:
    """敏感信息匹配结果"""
    type: str  # 类型: api_key, token, password, path, endpoint, cloud_key
    value: str  # 匹配到的值
    context: str  # 上下文
    confidence: float  # 置信度
    entropy: float  # 熵值
    source: str  # 来源文件URL

class JSSensitiveExtractor:
    """JS敏感信息提取器"""
    
    # API密钥模式
    API_KEY_PATTERNS = {
        # 通用模式
        "generic_api_key": (
            r'(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[=:\s]*["\']([a-zA-Z0-9_\-]{16,64})["\']',
            0.7
        ),
        # AWS
        "aws_access_key": (
            r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            0.9
        ),
        "aws_secret_key": (
            r'(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[=:\s]*["\'][^"\']{40}["\']',
            0.9
        ),
        # GitHub
        "github_token": (
            r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github[_-]?token\s*[=:\s]*["\'][a-zA-Z0-9_\-]{36,40}["\']',
            0.9
        ),
        # Slack
        "slack_token": (
            r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            0.9
        ),
        # Google API
        "google_api_key": (
            r'AIza[0-9A-Za-z\-_]{35}',
            0.9
        ),
        # Azure
        "azure_key": (
            r'(?:azure|azure[_-]?storage[_-]?(?:account|primary)[_-]?(?:key|connection[_-]?string))?\s*[=:\s]*["\'][^"\']{60,}["\']',
            0.6
        ),
        # 腾讯云
        "tencent_secret_id": (
            r'(?:tencent[_-]?cloud[_-]?secret[_-]?id|qcloud[_-]?secret[_-]?id)\s*[=:\s]*["\'][A-Z0-9]{40}["\']',
            0.8
        ),
        "tencent_secret_key": (
            r'(?:tencent[_-]?cloud[_-]?secret[_-]?key|qcloud[_-]?secret[_-]?key)\s*[=:\s]*["\'][a-zA-Z0-9]{32}["\']',
            0.8
        ),
        # 阿里云
        "aliyun_access_key": (
            r'(?:aliyun|aliyundl)[\w]*[_-]?(?:access[_-]?key[_-]?id|access[_-]?key)\s*[=:\s]*["\'][a-zA-Z0-9]{24}["\']',
            0.8
        ),
        "aliyun_secret": (
            r'(?:aliyun|aliyundl)[\w]*[_-]?secret\s*[=:\s]*["\'][a-zA-Z0-9]{30}["\']',
            0.8
        ),
        # JWT Token
        "jwt_token": (
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            0.6
        ),
        # 通用Token
        "bearer_token": (
            r'(?:Bearer|Basic|Token)\s+[a-zA-Z0-9_\-\.]+',
            0.5
        ),
        # 密码
        "password": (
            r'(?:password|passwd|pwd)\s*[=:\s]*["\'][^"\']{4,50}["\']',
            0.5
        ),
        # 私钥
        "private_key": (
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            0.9
        ),
    }
    
    # 敏感路径模式
    SENSITIVE_PATHS = [
        # 后台路径
        r'/admin', r'/manage', r'/manager', r'/console', r'/control',
        r'/cp/', r'/backend', r'/dashboard', r'/controlpanel',
        # 配置路径
        r'/config', r'/settings', r'/configuration', r'/conf',
        r'/application\.json', r'/config\.js', r'/settings\.py',
        # 数据库
        r'/database', r'/db', r'/sql', r'/mysql', r'/postgres',
        # API路径
        r'/api/v\d+', r'/api/admin', r'/api/internal', r'/api/private',
        r'/swagger', r'/swagger-ui', r'/api-docs', r'/docs',
        # 敏感文件
        r'\.env', r'\.git', r'\.svn', r'\.htaccess', r'/\.aws',
        r'credentials\.json', r'service-account\.json', r'/secrets',
        r'id_rsa', r'id_dsa', r'id_ecdsa',
        # 运维
        r'/jenkins', r'/gitlab', r'/jira', r'/confluence',
        r'/phpmyadmin', r'/adminer', r'/mysql', r'/mongo',
    ]
    
    # API端点提取模式
    ENDPOINT_PATTERNS = [
        # fetch/axios
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'axios\s*\(\s*["\']([^"\']+)["\']',
        # XMLHttpRequest
        r'new\s+XMLHttpRequest[^;]+open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
        # $.ajax
        r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        # URL构造
        r'(?:api|apiUrl|baseUrl|baseURL)\s*[+:]\s*["\']([^"\']+)["\']',
        # 常见路径
        r'["\'](/api/[^"\']+)["\']', r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/admin/api/[^"\']+)["\']',
    ]
    
    # URL正则
    URL_PATTERN = r'https?://[^\s"\'<>\)]+'
    
    def __init__(self):
        self.secrets: List[SecretMatch] = []
        self.endpoints: List[Dict] = []
        self.paths: Set[str] = set()
        self.js_files: Set[str] = set()
    
    def extract(self, js_content: str, source_url: str = "") -> List[SecretMatch]:
        """
        从JS内容中提取敏感信息
        
        Args:
            js_content: JS文件内容
            source_url: 来源URL
            
        Returns:
            敏感信息列表
        """
        self.secrets = []
        
        # 解混淆（简单处理）
        decoded = self._deobfuscate(js_content)
        
        # 提取各类敏感信息
        for secret_type, (pattern, confidence) in self.API_KEY_PATTERNS.items():
            matches = re.finditer(pattern, decoded, re.IGNORECASE)
            for match in matches:
                value = match.group(0) if match.lastindex == 0 else match.group(1)
                context = match.group(0)[:100]
                
                # 计算熵值
                entropy = self._calculate_entropy(value)
                
                # 过滤假阳性
                if self._is_false_positive(value, secret_type):
                    continue
                
                # 置信度调整
                adjusted_confidence = confidence
                if entropy > 4.0:  # 高熵值增加置信度
                    adjusted_confidence = min(confidence + 0.1, 1.0)
                
                secret = SecretMatch(
                    type=secret_type,
                    value=value,
                    context=context,
                    confidence=adjusted_confidence,
                    entropy=entropy,
                    source=source_url
                )
                self.secrets.append(secret)
        
        return self.secrets
    
    def extract_endpoints(self, js_content: str, base_url: str = "") -> List[Dict]:
        """
        从JS内容中提取API端点
        
        Args:
            js_content: JS文件内容
            base_url: 基础URL
            
        Returns:
            端点列表
        """
        endpoints = []
        
        # 解混淆
        decoded = self._deobfuscate(js_content)
        
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, decoded, re.IGNORECASE)
            for match in matches:
                path = match.group(1) if match.lastindex else match.group(0)
                
                # 清理路径
                path = path.strip("'\"/ ")
                
                # 转绝对URL
                if base_url and not path.startswith('http'):
                    path = urljoin(base_url, path)
                
                # 分类
                method = self._guess_method(path, decoded, match.start())
                
                endpoints.append({
                    "path": path,
                    "method": method,
                    "source": base_url
                })
        
        # 去重
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = f"{ep['method']}:{ep['path']}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        self.endpoints = unique_endpoints
        return unique_endpoints
    
    def extract_paths(self, js_content: str) -> Set[str]:
        """提取敏感路径"""
        paths = set()
        
        decoded = self._deobfuscate(js_content)
        
        for path_pattern in self.SENSITIVE_PATHS:
            matches = re.finditer(path_pattern, decoded, re.IGNORECASE)
            for match in matches:
                path = match.group(0)
                paths.add(path)
        
        self.paths = paths
        return paths
    
    def _deobfuscate(self, js_content: str) -> str:
        """简单的反混淆"""
        decoded = js_content
        
        # atob解码
        atob_pattern = r'atob\s*\(\s*["\']([^"\']+)["\']\s*\)'
        while True:
            matches = list(re.finditer(atob_pattern, decoded))
            if not matches:
                break
            for match in reversed(matches):
                try:
                    import base64
                    decoded_bytes = base64.b64decode(match.group(1))
                    decoded = decoded[:match.start()] + decoded_bytes.decode('utf-8', errors='ignore') + decoded[match.end():]
                except:
                    break
        
        # String.fromCharCode解码
        charcode_pattern = r'String\.fromCharCode\s*\(([^)]+)\)'
        matches = list(re.finditer(charcode_pattern, decoded))
        for match in reversed(matches):
            try:
                codes = [int(c.strip()) for c in match.group(1).split(',')]
                decoded = decoded[:match.start()] + ''.join(chr(c) for c in codes) + decoded[match.end():]
            except:
                continue
        
        # 十六进制解码
        hex_pattern = r'\\x([0-9a-fA-F]{2})'
        decoded = re.sub(hex_pattern, lambda m: chr(int(m.group(1), 16)), decoded)
        
        # Unicode解码
        unicode_pattern = r'\\u([0-9a-fA-F]{4})'
        decoded = re.sub(unicode_pattern, lambda m: chr(int(m.group(1), 16)), decoded)
        
        return decoded
    
    def _calculate_entropy(self, s: str) -> float:
        """计算字符串的香农熵"""
        if not s:
            return 0.0
        
        import collections
        counter = collections.Counter(s)
        length = len(s)
        
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        """判断是否是假阳性"""
        # 常见假阳性模式
        false_positive_values = {
            "example", "test", "your", "xxxx", "0000", "1111",
            "password", "admin", "changeme", "undefined", "null",
            "placeholder", "demo", "sample", "fake", "mock"
        }
        
        value_lower = value.lower()
        
        # 检查是否包含假阳性关键词
        if any(fp in value_lower for fp in false_positive_values):
            return True
        
        # 检查是否全部相同字符
        if len(set(value)) == 1:
            return True
        
        # Token检查（如果太短）
        if secret_type in ["bearer_token", "jwt_token"] and len(value) < 20:
            return True
        
        return False
    
    def _guess_method(self, path: str, content: str, match_pos: int) -> str:
        """猜测HTTP方法"""
        # 检查周围的上下文
        start = max(0, match_pos - 50)
        end = min(len(content), match_pos + 50)
        context = content[start:end].lower()
        
        if 'post' in context:
            return 'POST'
        elif 'put' in context or 'update' in context:
            return 'PUT'
        elif 'delete' in context or 'remove' in context:
            return 'DELETE'
        elif 'patch' in context:
            return 'PATCH'
        
        # 根据路径猜测
        if '/add' in path or '/create' in path or '/register' in path:
            return 'POST'
        elif '/edit' in path or '/update' in path or '/modify' in path:
            return 'PUT'
        elif '/del' in path or '/remove' in path:
            return 'DELETE'
        
        return 'GET'
    
    def get_cloud_keys(self) -> List[Dict]:
        """获取云服务密钥"""
        cloud_keys = []
        
        for secret in self.secrets:
            if 'aws' in secret.type or 'aliyun' in secret.type or \
               'tencent' in secret.type or 'google' in secret.type or \
               'azure' in secret.type or 'slack' in secret.type:
                cloud_keys.append({
                    "type": secret.type,
                    "value": secret.value,
                    "confidence": secret.confidence,
                    "source": secret.source
                })
        
        return cloud_keys


# 全局实例
_js_extractor = JSSensitiveExtractor()

def get_js_extractor() -> JSSensitiveExtractor:
    """获取JS提取器"""
    return _js_extractor
