"""
差分测试引擎 - 漏洞检测的基准对比
通过对比正常请求和Payload请求的响应差异来判断漏洞
"""

import hashlib
import httpx
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import re

@dataclass
class BaselineResponse:
    """基准响应"""
    status_code: int
    content_length: int
    content_hash: str
    headers: Dict[str, str]
    text_preview: str  # 前500字符
    has_error_pattern: bool
    response_time: float

@dataclass
class DifferentialResult:
    """差分测试结果"""
    is_vulnerable: bool
    confidence: float  # 0.0-1.0
    differences: List[str]  # 差异描述
    baseline: BaselineResponse
    payload_response: BaselineResponse
    evidence: str  # 证据

class DifferentialTester:
    """差分测试引擎"""
    
    # 错误特征（用于判断是否是错误页面）
    ERROR_PATTERNS = [
        r"sql\s+syntax", r"mysql", r"postgresql", r"sqlite", r"oracle",
        r"microsoft\s+sql", r"sqlserver", r"odbc",
        r"incorrect\s+syntax", r"unterminated", r"quoted\s+string",
        r"sql\s+error", r"sql\s+warning", r"ora-\d{5}",
        r"warning:\s+mysql", r"error\s+in\s+mysql",
        r"xampp", r"phpmyadmin",
        r"<b>Warning</b>", r"<b>Notice</b>", r"<b>Parse error</b>",
        r"Fatal\s+error", r"Fatal\s+Error",
        r"exception", r"stack\s+trace", r"error\s+in",
        r"access\s+denied", r"forbidden",
        r"permission\s+denied", r"unauthorized",
    ]
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.baselines: Dict[str, BaselineResponse] = {}  # url -> baseline
    
    async def get_baseline(self, client: httpx.AsyncClient, url: str, 
                          method: str = "GET",
                          params: Dict = None,
                          data: Dict = None,
                          headers: Dict = None) -> Optional[BaselineResponse]:
        """
        获取基准响应
        
        Args:
            client: httpx客户端
            url: 目标URL
            method: HTTP方法
            params: URL参数
            data: POST数据
            headers: 请求头
            
        Returns:
            基准响应
        """
        cache_key = f"{method}:{url}:{str(params)}:{str(data)}"
        
        if cache_key in self.baselines:
            return self.baselines[cache_key]
        
        try:
            import time
            start_time = time.time()
            
            if method.upper() == "GET":
                response = await client.get(url, params=params, headers=headers, timeout=self.timeout)
            elif method.upper() == "POST":
                response = await client.post(url, data=data, params=params, headers=headers, timeout=self.timeout)
            elif method.upper() == "PUT":
                response = await client.put(url, data=data, params=params, headers=headers, timeout=self.timeout)
            else:
                response = await client.request(method, url, params=params, data=data, headers=headers, timeout=self.timeout)
            
            response_time = time.time() - start_time
            
            # 构建响应对象
            baseline = self._build_baseline_response(response, response_time)
            self.baselines[cache_key] = baseline
            
            return baseline
            
        except Exception as e:
            print(f"[DifferentialTester] 获取基准响应失败: {e}")
            return None
    
    async def test_payload(self, client: httpx.AsyncClient, url: str,
                          method: str = "GET",
                          params: Dict = None,
                          data: Dict = None,
                          headers: Dict = None,
                          baseline: BaselineResponse = None) -> Optional[BaselineResponse]:
        """
        测试Payload响应
        
        Args:
            client: httpx客户端
            url: 目标URL
            method: HTTP方法
            params: URL参数
            data: POST数据
            headers: 请求头
            baseline: 已有的基准响应
            
        Returns:
            Payload响应
        """
        try:
            import time
            start_time = time.time()
            
            if method.upper() == "GET":
                response = await client.get(url, params=params, headers=headers, timeout=self.timeout)
            elif method.upper() == "POST":
                response = await client.post(url, data=data, params=params, headers=headers, timeout=self.timeout)
            else:
                response = await client.request(method, url, data=data, params=params, headers=headers, timeout=self.timeout)
            
            response_time = time.time() - start_time
            
            return self._build_baseline_response(response, response_time)
            
        except Exception as e:
            print(f"[DifferentialTester] 测试Payload失败: {e}")
            return None
    
    def compare(self, baseline: BaselineResponse, 
                payload_response: BaselineResponse) -> DifferentialResult:
        """
        比较基准响应和Payload响应
        
        Returns:
            差分结果
        """
        differences = []
        confidence = 0.0
        
        # 1. 状态码变化
        if baseline.status_code != payload_response.status_code:
            differences.append(f"状态码变化: {baseline.status_code} -> {payload_response.status_code}")
            confidence += 0.3
        
        # 2. 响应长度变化
        length_diff = abs(payload_response.content_length - baseline.content_length)
        length_diff_ratio = length_diff / max(baseline.content_length, 1)
        
        if length_diff_ratio > 0.5:  # 变化超过50%
            differences.append(f"响应长度大幅变化: {baseline.content_length} -> {payload_response.content_length} ({length_diff_ratio:.1%})")
            confidence += 0.2
        
        # 3. 内容哈希变化
        if baseline.content_hash != payload_response.content_hash:
            differences.append("响应内容发生变化")
            confidence += 0.2
        
        # 4. Payload响应出现错误模式
        if payload_response.has_error_pattern and not baseline.has_error_pattern:
            differences.append("Payload响应包含错误特征（SQL/代码错误等）")
            confidence += 0.4
        
        # 5. 基准响应本身就是错误页面（假阳性场景）
        if baseline.has_error_pattern:
            confidence -= 0.3  # 降低置信度
        
        # 6. 响应时间异常
        time_ratio = payload_response.response_time / max(baseline.response_time, 0.1)
        if time_ratio > 3:  # 响应时间增加3倍以上
            differences.append(f"响应时间显著增加: {baseline.response_time:.2f}s -> {payload_response.response_time:.2f}s")
            confidence += 0.15
        
        # 归一化置信度
        confidence = max(0.0, min(1.0, confidence))
        
        # 判断是否有漏洞
        # 条件：必须有明显差异 + 错误特征 或 高置信度
        is_vulnerable = len(differences) >= 2 and confidence >= 0.5
        
        return DifferentialResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            differences=differences,
            baseline=baseline,
            payload_response=payload_response,
            evidence="\n".join(differences)
        )
    
    def _build_baseline_response(self, response: httpx.Response, 
                                 response_time: float) -> BaselineResponse:
        """构建基准响应对象"""
        text = response.text[:500]
        
        # 检查错误模式
        has_error = False
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                has_error = True
                break
        
        # 计算内容哈希
        content_hash = hashlib.md5(response.content[:10000]).hexdigest()
        
        return BaselineResponse(
            status_code=response.status_code,
            content_length=len(response.content),
            content_hash=content_hash,
            headers=dict(response.headers),
            text_preview=text,
            has_error_pattern=has_error,
            response_time=response_time
        )
    
    def clear_baseline_cache(self):
        """清空基准缓存"""
        self.baselines.clear()
    
    async def test_sqli(self, client: httpx.AsyncClient, url: str,
                       param_name: str, param_value: str) -> DifferentialResult:
        """
        测试SQL注入
        
        Args:
            client: httpx客户端
            url: 目标URL
            param_name: 参数名
            param_value: 参数值
            
        Returns:
            差分结果
        """
        # 获取基准
        baseline = await self.get_baseline(
            client, url, method="POST",
            data={param_name: param_value}
        )
        
        if not baseline:
            return DifferentialResult(
                is_vulnerable=False, confidence=0.0,
                differences=["无法获取基准响应"],
                baseline=None, payload_response=None, evidence=""
            )
        
        # SQL注入测试Payload
        sqli_payloads = [
            f"{param_value}' OR '1'='1",
            f"{param_value}\" OR \"1\"=\"1",
            f"{param_value}' OR 1=1--",
            f"{param_value}\" OR 1=1--",
        ]
        
        for payload in sqli_payloads:
            payload_response = await self.test_payload(
                client, url, method="POST",
                data={param_name: payload}
            )
            
            if payload_response:
                result = self.compare(baseline, payload_response)
                if result.is_vulnerable:
                    return result
        
        # 如果所有Payload都没触发，返回最后一个比较结果
        return DifferentialResult(
            is_vulnerable=False, confidence=0.0,
            differences=["未检测到SQL注入"],
            baseline=baseline, payload_response=None, evidence=""
        )
    
    async def test_xss(self, client: httpx.AsyncClient, url: str,
                      param_name: str, param_value: str) -> DifferentialResult:
        """
        测试XSS
        
        Args:
            client: httpx客户端
            url: 目标URL
            param_name: 参数名
            param_value: 参数值
            
        Returns:
            差分结果
        """
        # 获取基准
        baseline = await self.get_baseline(
            client, url, method="POST",
            data={param_name: param_value}
        )
        
        if not baseline:
            return DifferentialResult(
                is_vulnerable=False, confidence=0.0,
                differences=["无法获取基准响应"],
                baseline=None, payload_response=None, evidence=""
            )
        
        # XSS测试Payload
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
        ]
        
        for payload in xss_payloads:
            payload_response = await self.test_payload(
                client, url, method="POST",
                data={param_name: payload}
            )
            
            if payload_response:
                result = self.compare(baseline, payload_response)
                if result.is_vulnerable:
                    # XSS特殊检查：Payload是否原样返回
                    if payload in payload_response.text_preview:
                        result.confidence = min(result.confidence + 0.3, 1.0)
                        result.differences.append("Payload被反射回响应中")
                        result.is_vulnerable = result.confidence >= 0.5
                    return result
        
        return DifferentialResult(
            is_vulnerable=False, confidence=0.0,
            differences=["未检测到XSS"],
            baseline=baseline, payload_response=None, evidence=""
        )


# 全局实例
_differential_tester = None

def get_differential_tester(timeout: int = 15) -> DifferentialTester:
    """获取差分测试器"""
    global _differential_tester
    if _differential_tester is None:
        _differential_tester = DifferentialTester(timeout=timeout)
    return _differential_tester
