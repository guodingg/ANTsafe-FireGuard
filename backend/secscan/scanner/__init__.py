"""
安全扫描器模块
"""

from secscan.scanner.base import ScannerBase, HostResult
from secscan.scanner.waf_detector import WAFDetector, detect_waf, get_bypass_headers, get_bypass_ua
from secscan.scanner.bypass_payloads import BypassPayloads, get_bypass_payloads
from secscan.scanner.fingerprint_db import FingerprintDB, detect_fingerprint
from secscan.scanner.scan_state import ScanState, ScanStateManager, get_scan_state_manager
from secscan.scanner.rate_limiter import RateLimiter, get_rate_limiter
from secscan.scanner.csrf_token import CSRFTokenExtractor, get_csrf_extractor, get_cookie_persistence
from secscan.scanner.differential_tester import DifferentialTester, get_differential_tester
from secscan.scanner.js_analyzer import JSSensitiveExtractor, get_js_extractor
from secscan.scanner.enhanced_scanner import EnhancedScanner

__all__ = [
    'ScannerBase', 'HostResult',
    'WAFDetector', 'detect_waf', 'get_bypass_headers', 'get_bypass_ua',
    'BypassPayloads', 'get_bypass_payloads',
    'FingerprintDB', 'detect_fingerprint',
    'ScanState', 'ScanStateManager', 'get_scan_state_manager',
    'RateLimiter', 'get_rate_limiter',
    'CSRFTokenExtractor', 'get_csrf_extractor', 'get_cookie_persistence',
    'DifferentialTester', 'get_differential_tester',
    'JSSensitiveExtractor', 'get_js_extractor',
    'EnhancedScanner',
]
