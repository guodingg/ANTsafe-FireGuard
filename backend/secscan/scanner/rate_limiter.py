"""
智能速率限制器
根据服务器响应动态调整请求频率
"""

import time
from collections import deque
from threading import Lock
from typing import Optional

class RateLimiter:
    """智能速率限制器"""
    
    def __init__(self, initial_rate: int = 20, min_rate: int = 1, max_rate: int = 50):
        """
        初始化速率限制器
        
        Args:
            initial_rate: 初始请求速率（请求/秒）
            min_rate: 最小速率
            max_rate: 最大速率
        """
        self.rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        
        # 请求时间戳队列（滑动窗口）
        self.window_size = 10  # 10秒窗口
        self.timestamps = deque(maxlen=1000)
        self.lock = Lock()
        
        # 服务器响应状态
        self.consecutive_errors = 0
        self.consecutive_success = 0
        self.last_response_time = 0
        self.avg_response_time = 0
        
        # 速率调整阈值
        self.error_threshold = 3  # 连续错误次数阈值
        self.success_threshold = 5  # 连续成功次数阈值
        self.slow_response_threshold = 5.0  # 慢响应阈值（秒）
        self.fast_response_threshold = 0.1  # 快响应阈值（秒）
    
    async def acquire(self):
        """获取请求许可（异步）"""
        with self.lock:
            now = time.time()
            
            # 清理过期的时间戳
            cutoff = now - self.window_size
            while self.timestamps and self.timestamps[0] < cutoff:
                self.timestamps.popleft()
            
            # 检查是否达到速率限制
            current_count = len(self.timestamps)
            if current_count >= self.rate * self.window_size:
                # 需要等待
                sleep_time = self.timestamps[0] + self.window_size - now
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    now = time.time()
                    # 再次清理
                    cutoff = now - self.window_size
                    while self.timestamps and self.timestamps[0] < cutoff:
                        self.timestamps.popleft()
            
            # 记录当前请求
            self.timestamps.append(now)
    
    def report_response(self, status_code: int, response_time: float):
        """
        报告响应状态，用于动态调整速率
        
        Args:
            status_code: HTTP状态码
            response_time: 响应时间（秒）
        """
        with self.lock:
            self.last_response_time = response_time
            
            # 更新平均响应时间
            if self.avg_response_time == 0:
                self.avg_response_time = response_time
            else:
                self.avg_response_time = 0.9 * self.avg_response_time + 0.1 * response_time
            
            # 判断响应状态
            if status_code >= 500:
                # 服务器错误
                self.consecutive_errors += 1
                self.consecutive_success = 0
                
                if self.consecutive_errors >= self.error_threshold:
                    # 降低速率
                    self._decrease_rate()
                    self.consecutive_errors = 0
                    
            elif status_code == 429:
                # Rate limit响应
                self._decrease_rate(0.5)  # 减半
                
            elif status_code >= 400:
                # 客户端错误（可能是防护）
                self.consecutive_errors += 1
                self.consecutive_success = 0
                
            else:
                # 成功响应
                self.consecutive_success += 1
                self.consecutive_errors = 0
                
                # 如果连续成功且响应快，可以增加速率
                if (self.consecutive_success >= self.success_threshold and 
                    response_time < self.fast_response_threshold):
                    self._increase_rate()
                    self.consecutive_success = 0
    
    def _decrease_rate(self, factor: float = 0.8):
        """降低速率"""
        new_rate = int(self.rate * factor)
        self.rate = max(new_rate, self.min_rate)
        print(f"[RateLimiter] 速率降低: {self.rate} req/s")
    
    def _increase_rate(self):
        """增加速率"""
        new_rate = int(self.rate * 1.2)
        self.rate = min(new_rate, self.max_rate)
        print(f"[RateLimiter] 速率增加: {self.rate} req/s")
    
    def adjust_for_slow_server(self):
        """针对慢速服务器调整"""
        with self.lock:
            if self.avg_response_time > self.slow_response_threshold:
                # 服务器慢，降低速率
                self._decrease_rate(0.7)
    
    def get_rate(self) -> int:
        """获取当前速率"""
        return self.rate


# 全局速率限制器
_rate_limiter = None

def get_rate_limiter(initial_rate: int = 20) -> RateLimiter:
    """获取全局速率限制器"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(initial_rate=initial_rate)
    return _rate_limiter
