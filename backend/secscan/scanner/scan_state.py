"""
扫描状态管理 - 支持断点续扫
保存和恢复扫描进度
"""

import json
import os
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

class ScanState:
    """扫描状态管理器"""
    
    def __init__(self, task_id: int, base_dir: str = "/app/data/scan_states"):
        self.task_id = task_id
        self.base_dir = Path(base_dir)
        self.state_file = self.base_dir / f"task_{task_id}_state.json"
        self.state: Dict[str, Any] = {
            "task_id": task_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "pending",  # pending, running, paused, completed, failed
            "progress": 0,
            "phase": "init",  # init, discovery, scan, finishing
            "target": "",
            "scan_type": "",
            # 发现的主机
            "discovered_hosts": [],
            "discovered_ports": [],
            "discovered_urls": [],
            # 已扫描的
            "scanned_hosts": [],
            "scanned_ports": [],
            "scanned_urls": [],
            # 漏洞结果
            "vulnerabilities": [],
            # 当前扫描位置（断点）
            "current_host_index": 0,
            "current_port_index": 0,
            "current_url_index": 0,
            "current_payload_index": 0,
            # 统计数据
            "stats": {
                "total_hosts": 0,
                "total_ports": 0,
                "total_urls": 0,
                "scanned_count": 0,
                "vuln_count": 0,
                "start_time": None,
                "end_time": None,
                "errors": []
            }
        }
        
        # 确保目录存在
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def load(self) -> bool:
        """从文件加载状态"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    self.state = json.load(f)
                return True
            except (json.JSONDecodeError, IOError):
                return False
        return False
    
    def save(self):
        """保存状态到文件"""
        self.state["updated_at"] = datetime.now().isoformat()
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, ensure_ascii=False, indent=2)
            return True
        except IOError as e:
            print(f"[ScanState] 保存状态失败: {e}")
            return False
    
    def delete(self):
        """删除状态文件"""
        if self.state_file.exists():
            try:
                self.state_file.unlink()
                return True
            except IOError:
                return False
        return False
    
    def update_status(self, status: str):
        """更新状态"""
        self.state["status"] = status
        self.save()
    
    def update_progress(self, progress: int):
        """更新进度"""
        self.state["progress"] = min(max(progress, 0), 100)
        self.save()
    
    def update_phase(self, phase: str):
        """更新扫描阶段"""
        self.state["phase"] = phase
        self.save()
    
    def add_discovered_host(self, host: str, ports: List[int] = None):
        """添加发现的主机"""
        if host not in self.state["discovered_hosts"]:
            self.state["discovered_hosts"].append(host)
            self.state["stats"]["total_hosts"] = len(self.state["discovered_hosts"])
        if ports:
            for port in ports:
                port_key = f"{host}:{port}"
                if port_key not in self.state["discovered_ports"]:
                    self.state["discovered_ports"].append(port_key)
                    self.state["stats"]["total_ports"] = len(self.state["discovered_ports"])
        self.save()
    
    def add_discovered_url(self, url: str):
        """添加发现的URL"""
        if url not in self.state["discovered_urls"]:
            self.state["discovered_urls"].append(url)
            self.state["stats"]["total_urls"] = len(self.state["discovered_urls"])
        self.save()
    
    def mark_host_scanned(self, host: str):
        """标记主机已扫描"""
        if host not in self.state["scanned_hosts"]:
            self.state["scanned_hosts"].append(host)
            self.state["stats"]["scanned_count"] = len(self.state["scanned_hosts"])
        self.save()
    
    def mark_port_scanned(self, host: str, port: int):
        """标记端口已扫描"""
        key = f"{host}:{port}"
        if key not in self.state["scanned_ports"]:
            self.state["scanned_ports"].append(key)
        self.save()
    
    def mark_url_scanned(self, url: str):
        """标记URL已扫描"""
        if url not in self.state["scanned_urls"]:
            self.state["scanned_urls"].append(url)
        self.save()
    
    def add_vulnerability(self, vuln: Dict):
        """添加漏洞"""
        self.state["vulnerabilities"].append(vuln)
        self.state["stats"]["vuln_count"] = len(self.state["vulnerabilities"])
        self.save()
    
    def set_current_position(self, host_index: int = None, port_index: int = None, 
                            url_index: int = None, payload_index: int = None):
        """设置当前扫描位置（断点）"""
        if host_index is not None:
            self.state["current_host_index"] = host_index
        if port_index is not None:
            self.state["current_port_index"] = port_index
        if url_index is not None:
            self.state["current_url_index"] = url_index
        if payload_index is not None:
            self.state["current_payload_index"] = payload_index
        self.save()
    
    def get_current_position(self) -> Dict:
        """获取当前扫描位置"""
        return {
            "host_index": self.state.get("current_host_index", 0),
            "port_index": self.state.get("current_port_index", 0),
            "url_index": self.state.get("current_url_index", 0),
            "payload_index": self.state.get("current_payload_index", 0),
        }
    
    def start_timer(self):
        """开始计时"""
        if self.state["stats"]["start_time"] is None:
            self.state["stats"]["start_time"] = datetime.now().isoformat()
        self.save()
    
    def end_timer(self):
        """结束计时"""
        self.state["stats"]["end_time"] = datetime.now().isoformat()
        self.save()
    
    def add_error(self, error: str):
        """添加错误"""
        self.state["stats"]["errors"].append({
            "time": datetime.now().isoformat(),
            "error": error
        })
        self.save()
    
    def is_host_scanned(self, host: str) -> bool:
        """检查主机是否已扫描"""
        return host in self.state["scanned_hosts"]
    
    def is_url_scanned(self, url: str) -> bool:
        """检查URL是否已扫描"""
        return url in self.state["scanned_urls"]
    
    def should_resume(self) -> bool:
        """检查是否应该恢复扫描"""
        return self.state["status"] in ["running", "paused"] and \
               self.state["progress"] < 100
    
    def get_summary(self) -> Dict:
        """获取状态摘要"""
        return {
            "task_id": self.task_id,
            "status": self.state["status"],
            "progress": self.state["progress"],
            "phase": self.state["phase"],
            "total_hosts": self.state["stats"]["total_hosts"],
            "scanned_hosts": len(self.state["scanned_hosts"]),
            "total_urls": self.state["stats"]["total_urls"],
            "scanned_urls": len(self.state["scanned_urls"]),
            "vuln_count": self.state["stats"]["vuln_count"],
            "updated_at": self.state["updated_at"]
        }


class ScanStateManager:
    """扫描状态管理器（全局）"""
    
    def __init__(self, base_dir: str = "/app/data/scan_states"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._states: Dict[int, ScanState] = {}
    
    def get_state(self, task_id: int) -> ScanState:
        """获取或创建扫描状态"""
        if task_id not in self._states:
            state = ScanState(task_id, str(self.base_dir))
            state.load()
            self._states[task_id] = state
        return self._states[task_id]
    
    def has_state(self, task_id: int) -> bool:
        """检查是否有未完成的扫描状态"""
        state = self.get_state(task_id)
        return state.state_file.exists() and state.should_resume()
    
    def delete_state(self, task_id: int):
        """删除扫描状态"""
        if task_id in self._states:
            self._states[task_id].delete()
            del self._states[task_id]
        else:
            state = ScanState(task_id, str(self.base_dir))
            state.delete()
    
    def list_states(self) -> List[Dict]:
        """列出所有扫描状态"""
        states = []
        for state_file in self.base_dir.glob("task_*_state.json"):
            try:
                with open(state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    states.append({
                        "task_id": data.get("task_id"),
                        "status": data.get("status"),
                        "progress": data.get("progress"),
                        "updated_at": data.get("updated_at")
                    })
            except:
                continue
        return states
    
    def cleanup_old_states(self, max_age_hours: int = 24):
        """清理过期的状态文件"""
        now = time.time()
        for state_file in self.base_dir.glob("task_*_state.json"):
            try:
                mtime = state_file.stat().st_mtime
                if (now - mtime) > (max_age_hours * 3600):
                    state_file.unlink()
                    print(f"[ScanStateManager] 已删除过期状态: {state_file.name}")
            except:
                continue


# 全局状态管理器
_scan_state_manager = None

def get_scan_state_manager() -> ScanStateManager:
    """获取全局扫描状态管理器"""
    global _scan_state_manager
    if _scan_state_manager is None:
        _scan_state_manager = ScanStateManager()
    return _scan_state_manager
