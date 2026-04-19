"""
CSRF Token自动提取与Cookie持久化管理
支持多种Token格式和会话管理
"""

import re
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class TokenInfo:
    """Token信息"""
    name: str  # Token参数名
    value: str  # Token值
    source: str  # 来源: cookie, header, body, html
    page_url: str  # 发现Token的页面URL

@dataclass
class SessionState:
    """会话状态"""
    cookies: Dict[str, str]
    tokens: Dict[str, TokenInfo]
    headers: Dict[str, str]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    created_at: float
    updated_at: float
    source_url: str

class CSRFTokenExtractor:
    """CSRF Token自动提取器"""
    
    # 常见CSRF Token名称
    TOKEN_NAMES = [
        # 标准CSRF Token
        "csrf_token", "csrftoken", "csrf-token", "csrf", "_csrf", "__csrf",
        "xsrf-token", "xsrf_token", "x-xsrf-token",
        # Django
        "csrfmiddlewaretoken",
        # Laravel
        "_token", "token",
        # Spring Security
        "_csrf", "csrf_value",
        # ASP.NET
        "__RequestVerificationToken", "__VIEWSTATE", "__EVENTVALIDATION",
        # Ruby on Rails
        "authenticity_token",
        # WordPress
        "_wpnonce", "_wpnonce_user",
        # 其他常见
        "sec_token", "security_token", "auth_token"
    ]
    
    # Token提取正则
    TOKEN_PATTERNS = [
        # HTML表单中的Token
        (r'(?:name|id)=["\']?(?:csrftoken|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|token)["\']?\s*(?:value)=["\']([^"\']+)["\']', "html"),
        (r'<input[^>]+(?:name|id)=["\']?(?:csrf_token|csrfmiddlewaretoken|token)["\']?[^>]*value=["\']([^"\']+)["\']', "html"),
        # Meta标签
        (r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', "html"),
        (r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']', "html"),
        # JavaScript变量
        (r'(?:var|let|const)\s+(?:csrf|csrfToken|xsrfToken)\s*=\s*["\']([^"\']+)["\']', "js"),
        (r'(?:csrf|csrfToken|xsrfToken)\s*[=:]\s*["\']([^"\']+)["\']', "js"),
        # Header
        (r'X-CSRF-Token:\s*([^\s\r\n]+)', "header"),
        (r'X-XSRF-Token:\s*([^\s\r\n]+)', "header"),
        (r'Csrf-Token:\s*([^\s\r\n]+)', "header"),
        # Cookie
        (r'csrf_token=([^;\s]+)', "cookie"),
        (r'csrftoken=([^;\s]+)', "cookie"),
        (r'__RequestVerificationToken=([^;\s]+)', "cookie"),
    ]
    
    def __init__(self):
        self.tokens: Dict[str, TokenInfo] = {}
        self.last_extraction_time = 0
    
    def extract_from_html(self, html: str, url: str = "") -> List[TokenInfo]:
        """从HTML中提取CSRF Token"""
        found_tokens = []
        
        for pattern, source in self.TOKEN_PATTERNS:
            if source not in ["html", "js"]:
                continue
                
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                value = match.group(1)
                # 提取Token名称
                name = self._extract_token_name(pattern, match.group(0))
                
                if name and value and len(value) > 5:
                    token_key = f"{name}@{url}" if url else name
                    if token_key not in self.tokens:
                        token_info = TokenInfo(
                            name=name,
                            value=value,
                            source=source,
                            page_url=url
                        )
                        self.tokens[token_key] = token_info
                        found_tokens.append(token_info)
        
        if found_tokens:
            self.last_extraction_time = time.time()
        
        return found_tokens
    
    def extract_from_headers(self, headers: Dict[str, str]) -> List[TokenInfo]:
        """从HTTP响应头中提取Token"""
        found_tokens = []
        
        # 检查常见的CSRF响应头
        csrf_headers = [
            "x-csrf-token", "x-xsrf-token", "csrf-token",
            "x-request-verification-token"
        ]
        
        for header_name, header_value in headers.items():
            if header_name.lower() in csrf_headers:
                name = header_name.lower().replace("x-", "").replace("-", "_")
                token_key = name
                
                if token_key not in self.tokens:
                    token_info = TokenInfo(
                        name=name,
                        value=header_value,
                        source="header",
                        page_url=""
                    )
                    self.tokens[token_key] = token_info
                    found_tokens.append(token_info)
        
        return found_tokens
    
    def extract_from_cookie(self, cookie_str: str) -> List[TokenInfo]:
        """从Cookie字符串中提取Token"""
        found_tokens = []
        
        for name in self.TOKEN_NAMES:
            pattern = rf'{name}=([^;\s]+)'
            match = re.search(pattern, cookie_str, re.IGNORECASE)
            if match:
                value = match.group(1)
                token_key = name
                
                if token_key not in self.tokens:
                    token_info = TokenInfo(
                        name=name,
                        value=value,
                        source="cookie",
                        page_url=""
                    )
                    self.tokens[token_key] = token_info
                    found_tokens.append(token_info)
        
        return found_tokens
    
    def extract_from_response(self, response_text: str, headers: Dict[str, str], 
                            url: str = "") -> List[TokenInfo]:
        """从完整响应中提取Token"""
        tokens = []
        
        # 优先从响应头提取
        tokens.extend(self.extract_from_headers(headers))
        
        # 从HTML中提取
        tokens.extend(self.extract_from_html(response_text, url))
        
        # 从Cookie中提取
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if set_cookie:
            tokens.extend(self.extract_from_cookie(set_cookie))
        
        return tokens
    
    def get_token_for_request(self, param_type: str = "form") -> Optional[Tuple[str, str]]:
        """
        获取用于请求的Token
        
        Args:
            param_type: 参数类型 - "form"表单, "header"头部, "cookie"
            
        Returns:
            (name, value)元组
        """
        if not self.tokens:
            return None
        
        # 优先使用最近提取的Token
        recent_tokens = sorted(
            self.tokens.values(),
            key=lambda t: t.page_url or "",
            reverse=True
        )
        
        for token in recent_tokens:
            if param_type == "header":
                # 返回适合放在Header中的Token
                if token.name in ["csrf_token", "csrftoken", "xsrf_token"]:
                    return (f"X-CSRF-Token", token.value)
            elif param_type == "form":
                # 返回适合放在表单中的Token
                if token.source in ["html", "js"]:
                    return (token.name, token.value)
            elif param_type == "cookie":
                if token.source == "cookie":
                    return (token.name, token.value)
        
        # 返回第一个可用的Token
        first = next(iter(self.tokens.values()), None)
        if first:
            return (first.name, first.value)
        
        return None
    
    def clear(self):
        """清空Token缓存"""
        self.tokens.clear()
    
    def _extract_token_name(self, pattern: str, match_text: str) -> Optional[str]:
        """从匹配文本中提取Token名称"""
        # 尝试从模式中提取
        name_pattern = r'(?:name|id)=["\']?(\w+)["\']?'
        name_match = re.search(name_pattern, match_text, re.IGNORECASE)
        if name_match:
            name = name_match.group(1).lower()
            # 检查是否是已知的CSRF Token名称
            for known_name in self.TOKEN_NAMES:
                if known_name in name or name in known_name:
                    return known_name
            return name
        
        # 从pattern推断
        for known_name in self.TOKEN_NAMES:
            if known_name in pattern.lower():
                return known_name
        
        return None


class CookiePersistence:
    """Cookie持久化管理"""
    
    def __init__(self, storage_dir: str = "/app/data/cookies"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: Dict[str, SessionState] = {}
    
    def save_session(self, session_id: str, cookies: Dict[str, str], 
                    tokens: Dict[str, TokenInfo] = None,
                    headers: Dict[str, str] = None,
                    source_url: str = ""):
        """
        保存会话状态
        
        Args:
            session_id: 会话ID
            cookies: Cookie字典
            tokens: Token信息字典
            headers: 相关Header
            source_url: 来源URL
        """
        now = time.time()
        
        if session_id in self.sessions:
            # 更新现有会话
            session = self.sessions[session_id]
            session.cookies.update(cookies)
            session.updated_at = now
            if tokens:
                session.tokens.update({t.name: t for t in tokens})
            if headers:
                session.headers.update(headers)
        else:
            # 创建新会话
            self.sessions[session_id] = SessionState(
                cookies=cookies,
                tokens=tokens or {},
                headers=headers or {},
                local_storage={},
                session_storage={},
                created_at=now,
                updated_at=now,
                source_url=source_url
            )
        
        # 持久化到文件
        self._persist_to_file(session_id)
    
    def load_session(self, session_id: str) -> Optional[SessionState]:
        """加载会话状态"""
        if session_id in self.sessions:
            return self.sessions[session_id]
        
        # 从文件加载
        session_file = self.storage_dir / f"{session_id}.json"
        if session_file.exists():
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # 转换TokenInfo
                    tokens = {}
                    for name, token_data in data.get("tokens", {}).items():
                        tokens[name] = TokenInfo(**token_data)
                    
                    session = SessionState(
                        cookies=data.get("cookies", {}),
                        tokens=tokens,
                        headers=data.get("headers", {}),
                        local_storage=data.get("local_storage", {}),
                        session_storage=data.get("session_storage", {}),
                        created_at=data.get("created_at", time.time()),
                        updated_at=data.get("updated_at", time.time()),
                        source_url=data.get("source_url", "")
                    )
                    self.sessions[session_id] = session
                    return session
            except Exception as e:
                print(f"[CookiePersistence] 加载会话失败: {e}")
        
        return None
    
    def delete_session(self, session_id: str):
        """删除会话"""
        if session_id in self.sessions:
            del self.sessions[session_id]
        
        session_file = self.storage_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """列出所有会话"""
        sessions = []
        for session_id, session in self.sessions.items():
            sessions.append({
                "session_id": session_id,
                "cookie_count": len(session.cookies),
                "token_count": len(session.tokens),
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "source_url": session.source_url
            })
        
        # 也检查文件
        for session_file in self.storage_dir.glob("*.json"):
            session_id = session_file.stem
            if session_id not in self.sessions:
                try:
                    with open(session_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        sessions.append({
                            "session_id": session_id,
                            "cookie_count": len(data.get("cookies", {})),
                            "token_count": len(data.get("tokens", {})),
                            "created_at": data.get("created_at", 0),
                            "updated_at": data.get("updated_at", 0),
                            "source_url": data.get("source_url", "")
                        })
                except:
                    continue
        
        return sessions
    
    def get_cookies_for_request(self, session_id: str) -> Dict[str, str]:
        """获取请求用的Cookie"""
        session = self.load_session(session_id)
        if session:
            return session.cookies
        return {}
    
    def _persist_to_file(self, session_id: str):
        """持久化到文件"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        
        data = {
            "cookies": session.cookies,
            "tokens": {name: asdict(t) for name, t in session.tokens.items()},
            "headers": session.headers,
            "local_storage": session.local_storage,
            "session_storage": session.session_storage,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "source_url": session.source_url
        }
        
        session_file = self.storage_dir / f"{session_id}.json"
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[CookiePersistence] 保存会话失败: {e}")


# 全局实例
_csrf_extractor = CSRFTokenExtractor()
_cookie_persistence = CookiePersistence()

def get_csrf_extractor() -> CSRFTokenExtractor:
    """获取CSRF Token提取器"""
    return _csrf_extractor

def get_cookie_persistence() -> CookiePersistence:
    """获取Cookie持久化管理器"""
    return _cookie_persistence
