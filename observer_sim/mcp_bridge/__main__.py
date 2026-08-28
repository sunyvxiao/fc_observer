# -*- coding: utf-8 -*-
"""
mcp_bridge/__main__.py — 申报 Server 独立运行入口

用法:
    python -m mcp_bridge --host 127.0.0.1 --port 8765
    python -m mcp_bridge --port 8765 --jsonl-dir output/mcp_reports
"""

import argparse
import logging
import os
import sys

# observer_sim 目录加入 sys.path（支持从任意工作目录运行）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_bridge.server import run_server  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="WorkBuddy 降级监测 MCP 申报 Server（HTTP+SSE）")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765,
                        help="监听端口 (默认 8765)")
    parser.add_argument("--jsonl-dir", type=str, default=None,
                        help="申报留痕 JSONL 目录 (默认不落盘)")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="日志级别 (默认 INFO)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    jsonl_path = None
    if args.jsonl_dir:
        os.makedirs(args.jsonl_dir, exist_ok=True)
        jsonl_path = os.path.join(
            args.jsonl_dir,
            f"mcp_reports_{__import__('time').strftime('%Y%m%d')}.jsonl")

    run_server(host=args.host, port=args.port, jsonl_path=jsonl_path)


if __name__ == "__main__":
    main()
