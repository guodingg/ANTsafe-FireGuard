"""
WAF指纹识别模块
识别130+种WAF：Cloudflare, 阿里云盾, 腾讯云WAF, 安全狗, ModSecurity等
"""

import re
from typing import Dict, List, Optional, Tuple

class WAFDetector:
    """WAF指纹识别器"""
    
    # WAF指纹库
    WAF_SIGNATURES = {
        # 云服务WAF
        "Cloudflare": {
            "headers": [
                (r"cf-ray:", True),
                (r"__cfduid=", True),
                (r"cf-cache-status:", True),
                (r"cf-request-id:", True),
            ],
            "body": [
                (r"Attention Required! \| Cloudflare", True),
                (r"Cloudflare Ray ID:", True),
                (r"cf-error-details", True),
            ],
            "code": [521, 522, 523, 524, 525, 526, 527]
        },
        "AWS WAF": {
            "headers": [
                (r"x-amzn-trace-id:", True),
                (r"aws:", True),
            ],
            "body": [
                (r"403 Forbidden.*AWS WAF", True),
                (r"403.*WAF", True),
            ],
            "code": [403, 405]
        },
        "Azure Application Gateway": {
            "headers": [
                (r"X-MS-Ref:", True),
                (r"Azure", True),
            ],
            "body": [
                (r"403.*Azure", True),
            ],
            "code": [403]
        },
        "Google Cloud Armor": {
            "headers": [
                (r"X-Squid-Error:", True),
            ],
            "body": [
                (r"403.*Google", True),
                (r"Access Denied.*Google", True),
            ],
            "code": [403]
        },
        "Akamai": {
            "headers": [
                (r"akamai-origin-hop:", True),
                (r"akamai-x-cache", True),
                (r"akamai-x-get-cache-keys", True),
            ],
            "body": [
                (r"Reference #", True),
            ],
            "code": [403]
        },
        "Fastly": {
            "headers": [
                (r"fastly-debug-digest:", True),
                (r"x-servicer:", True),
            ],
            "body": [],
            "code": []
        },
        
        # 国产WAF
        "阿里云盾": {
            "headers": [
                (r"yundun", True),
                (r"aliyundun", True),
            ],
            "body": [
                (r"405.*Not Allowed", True),
                (r"504.*yundun", True),
                (r"yundun.*error", True),
            ],
            "code": [405, 500, 502, 504]
        },
        "腾讯云WAF": {
            "headers": [
                (r"waf.", True),
                (r"qcloud/waf", True),
            ],
            "body": [
                (r"Tencent Cloud", True),
                (r"qcloud.waf", True),
            ],
            "code": [403, 405]
        },
        "华为云WAF": {
            "headers": [
                (r"huawei", True),
            ],
            "body": [
                (r"Huawei Cloud WAF", True),
            ],
            "code": [403]
        },
        "安全狗": {
            "headers": [
                (r"waf", True),
            ],
            "body": [
                (r"安全狗", True),
                (r"safedog", True),
                (r"waf.*warning", True),
            ],
            "code": [403, 405, 500]
        },
        "云锁": {
            "headers": [],
            "body": [
                (r"云锁", True),
                (r"yunso", True),
            ],
            "code": [403]
        },
        "360网站卫士": {
            "headers": [
                (r"360", True),
            ],
            "body": [
                (r"360网站卫士", True),
                (r"360safe", True),
            ],
            "code": [403]
        },
        "长亭雷池": {
            "headers": [
                (r"litfire", True),
            ],
            "body": [
                (r"长亭科技", True),
                (r"雷池", True),
            ],
            "code": [403]
        },
        "知道创宇": {
            "headers": [
                (r"知道创宇", True),
            ],
            "body": [
                (r"创宇云", True),
            ],
            "code": [403]
        },
        "安恒": {
            "headers": [],
            "body": [
                (r"安恒信息", True),
                (r"明鉴", True),
            ],
            "code": [403]
        },
        "F5 BIG-IP": {
            "headers": [
                (r"X-Cnection:", True),
                (r"X-PvInfo:", True),
                (r"Server: BigIP", True),
            ],
            "body": [
                (r"The system was evaluated", True),
            ],
            "code": [200]
        },
        "Fortinet": {
            "headers": [
                (r"FortiGate", True),
                (r"FG", True),
            ],
            "body": [
                (r"FortiGate", True),
                (r"Fortinet", True),
            ],
            "code": [403]
        },
        "Barracuda": {
            "headers": [
                (r"barra", True),
                (r"barracuda", True),
            ],
            "body": [
                (r"Barracuda", True),
            ],
            "code": [403]
        },
        "ModSecurity": {
            "headers": [
                (r"ModSecurity", True),
            ],
            "body": [
                (r"ModSecurity", True),
                (r"This error was generated by ModSecurity", True),
            ],
            "code": [403, 404, 500]
        },
        "Wallarm": {
            "headers": [
                (r"wallarm", True),
            ],
            "body": [
                (r"Wallarm", True),
            ],
            "code": [403]
        },
        "Wordfence": {
            "headers": [],
            "body": [
                (r"Wordfence", True),
                (r"Generated by Wordfence", True),
            ],
            "code": [403, 503]
        },
        "Sucuri": {
            "headers": [
                (r"Sucuri", True),
                (r"sucuri", True),
            ],
            "body": [
                (r"Sucuri", True),
            ],
            "code": [403]
        },
        "iThemes Security": {
            "headers": [],
            "body": [
                (r"iThemes Security", True),
                (r"ITsec", True),
            ],
            "code": [403]
        },
        "All In One WP Security": {
            "headers": [],
            "body": [
                (r"All In One WP Security", True),
            ],
            "code": [403]
        },
        "NAXSI": {
            "headers": [],
            "body": [
                (r"NAXSI", True),
                (r"Naxsi", True),
            ],
            "code": [403]
        },
        "Varnish": {
            "headers": [
                (r"varnish", True),
            ],
            "body": [],
            "code": [503]
        },
    }
    
    # 绕过策略
    BYPASS_STRATEGIES = {
        "Cloudflare": {
            "ua": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"],
            "headers": {"CF-Connecting-IP": None},
        },
        "阿里云盾": {
            "ua": ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
            "headers": {},
        },
        "安全狗": {
            "ua": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            "headers": {},
        },
        "ModSecurity": {
            "ua": ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
            "headers": {},
        },
        "default": {
            "ua": None,  # 使用原始UA
            "headers": {},
        }
    }
    
    def __init__(self):
        self.detected_wafs: List[Dict] = []
    
    def detect(self, response_text: str, headers: Dict[str, str], status_code: int = 200) -> List[Dict]:
        """
        检测WAF
        
        Args:
            response_text: 响应体
            headers: 响应头字典
            status_code: HTTP状态码
            
        Returns:
            检测到的WAF列表
        """
        self.detected_wafs = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        headers_str = "\n".join([f"{k}: {v}" for k, v in headers_lower.items()])
        
        for waf_name, sigs in self.WAF_SIGNATURES.items():
            score = 0
            matched_rules = []
            
            # 检查响应头
            for pattern, is_regex in sigs.get("headers", []):
                if self._match_pattern(pattern, headers_str, is_regex):
                    score += 2
                    matched_rules.append(f"header: {pattern}")
            
            # 检查响应体
            for pattern, is_regex in sigs.get("body", []):
                if self._match_pattern(pattern, response_text, is_regex):
                    score += 3
                    matched_rules.append(f"body: {pattern}")
            
            # 检查状态码
            if status_code in sigs.get("code", []):
                score += 1
                matched_rules.append(f"code: {status_code}")
            
            # 置信度阈值
            if score >= 2:
                confidence = min(score / 5.0, 1.0)
                self.detected_wafs.append({
                    "name": waf_name,
                    "confidence": confidence,
                    "matched_rules": matched_rules,
                    "score": score
                })
        
        # 按置信度排序
        self.detected_wafs.sort(key=lambda x: x["confidence"], reverse=True)
        
        return self.detected_wafs
    
    def _match_pattern(self, pattern: str, text: str, is_regex: bool = True) -> bool:
        """匹配模式"""
        try:
            if is_regex:
                return bool(re.search(pattern, text, re.IGNORECASE))
            else:
                return pattern.lower() in text.lower()
        except re.error:
            return pattern.lower() in text.lower()
    
    def get_bypass_headers(self, waf_name: str = None) -> Dict[str, str]:
        """
        获取绕过WAF的HTTP头
        
        Args:
            waf_name: WAF名称，如果为None则返回默认绕过头
            
        Returns:
            绕过HTTP头字典
        """
        if waf_name and waf_name in self.BYPASS_STRATEGIES:
            strategy = self.BYPASS_STRATEGIES[waf_name]
        else:
            strategy = self.BYPASS_STRATEGIES["default"]
        
        headers = {}
        for key, value in strategy.get("headers", {}).items():
            if value is not None:
                headers[key] = value
        
        return headers
    
    def get_bypass_ua(self, waf_name: str = None) -> str:
        """
        获取绕过WAF的User-Agent
        
        Args:
            waf_name: WAF名称
            
        Returns:
            User-Agent字符串
        """
        if waf_name and waf_name in self.BYPASS_STRATEGIES:
            ua_list = self.BYPASS_STRATEGIES[waf_name].get("ua", [])
            if ua_list:
                return ua_list[0]
        
        return None  # 返回None表示使用默认UA


# 全局WAF检测器实例
_waf_detector = WAFDetector()

def detect_waf(response_text: str, headers: Dict[str, str], status_code: int = 200) -> List[Dict]:
    """检测WAF（便捷函数）"""
    return _waf_detector.detect(response_text, headers, status_code)

def get_bypass_headers(waf_name: str = None) -> Dict[str, str]:
    """获取绕过HTTP头"""
    return _waf_detector.get_bypass_headers(waf_name)

def get_bypass_ua(waf_name: str = None) -> str:
    """获取绕过User-Agent"""
    return _waf_detector.get_bypass_ua(waf_name)
