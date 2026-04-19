#!/usr/bin/env python3
"""
漏洞情报后台刷新脚本
用法:
  python -m scripts.refresh_intel          # 立即刷新
  python -m scripts.refresh_intel --watch  # 持续运行，定期刷新
  python -m scripts.refresh_intel --once   # 单次刷新后退出
"""

import asyncio
import sys
import os
import argparse
import time
from datetime import datetime

# 确保backend路径在sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


async def refresh_intel():
    """执行一次情报刷新"""
    from secscan.services.vuln_intel import get_vuln_intel_service
    from secscan.models.intel import IntelVuln
    from secscan.database import engine, async_session_maker
    from sqlalchemy import text

    print(f"[{datetime.now().isoformat()}] 🔍 开始漏洞情报刷新...")

    # 确保表存在
    async with engine.begin() as conn:
        from secscan.models.intel import IntelVuln, IntelFetchLog
        # IntelVuln 和 IntelFetchLog 继承自 Base
        # init_db 应该已经创建了表，这里确保一下
        pass

    service = get_vuln_intel_service()
    results = await service.fetch_all_sources(force=True)

    total_fetched = sum(r.get("fetched", 0) for r in results.values())
    total_new = sum(r.get("new", 0) for r in results.values())

    print(f"[{datetime.now().isoformat()}] ✅ 刷新完成:")
    for source, result in results.items():
        print(f"  - {source}: 获取 {result.get('fetched', 0)} 条, 新增 {result.get('new', 0)} 条")
        if result.get("errors"):
            for err in result["errors"]:
                print(f"    ⚠️ {err}")

    print(f"  总计: {total_fetched} 条, 新增 {total_new} 条")

    # 清理90天以上的旧数据
    expired = await service.mark_expired(days=90)
    if expired > 0:
        print(f"  🗑️  标记 {expired} 条过期数据")

    stats = await service.get_stats()
    print(f"  📊 当前库: 总计 {stats.get('total', 0)} 条")
    print(f"     严重: {stats.get('by_severity', {}).get('critical', 0)}")
    print(f"     高危: {stats.get('by_severity', {}).get('high', 0)}")
    print(f"     中危: {stats.get('by_severity', {}).get('medium', 0)}")

    return results


async def watch_mode(interval_minutes: int = 60):
    """持续监控模式"""
    print(f"👀 启动漏洞情报监控 (每 {interval_minutes} 分钟刷新一次)")
    print("按 Ctrl+C 停止")
    try:
        while True:
            await refresh_intel()
            print(f"\n⏰ 等待 {interval_minutes} 分钟后下次刷新...\n")
            await asyncio.sleep(interval_minutes * 60)
    except KeyboardInterrupt:
        print("\n👋 退出监控")


async def main():
    parser = argparse.ArgumentParser(description="漏洞情报刷新工具")
    parser.add_argument("--watch", action="store_true", help="持续监控模式")
    parser.add_argument("--once", action="store_true", help="单次刷新后退出")
    parser.add_argument("--interval", type=int, default=60, help="监控间隔(分钟, 默认60)")
    args = parser.parse_args()

    if args.watch:
        await watch_mode(args.interval)
    else:
        await refresh_intel()
        if not args.once:
            # 非watch模式也启动监控，但只是单次
            pass


if __name__ == "__main__":
    asyncio.run(main())
