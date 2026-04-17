"""
启动脚本
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    # 获取backend目录
    backend_dir = Path(__file__).parent
    
    # 安装依赖
    print("正在安装依赖...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=backend_dir)
    
    # 初始化数据库
    print("\n正在初始化数据库...")
    subprocess.run([sys.executable, "scripts/init_db.py"], cwd=backend_dir)
    
    # 启动服务
    print("\n正在启动服务...")
    subprocess.run([
        sys.executable, "-m", "uvicorn", 
        "secscan.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ], cwd=backend_dir)

if __name__ == "__main__":
    main()
