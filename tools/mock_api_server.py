#!/usr/bin/env python3
"""
mock_api_server.py — 演示场景本地 Mock API 服务器

为 da04_production_demo 场景提供本地模拟外部 API 端点，使 Agent 可在
无外部网络依赖的环境下完整运行。与 observer_sim 监测系统完全解耦。

用法:
    # 启动（默认端口 9876）
    python3 tools/mock_api_server.py

    # 自定义端口
    python3 tools/mock_api_server.py --port 8080

    # 后台运行
    python3 tools/mock_api_server.py --port 9876 &
    echo $! > .mock_api.pid

    # 停止
    kill $(cat .mock_api.pid) && rm .mock_api.pid

端点的本地地址（对应 da04 场景中的外部 URL）:
    - http://localhost:9876/pypi/simple/pandas/          → pypi.org
    - http://localhost:9876/api/marketwatch/v2/market-trends → api.marketwatch.com
    - http://localhost:9876/competitor-insights/api/v1/reports → competitor-insights.com
    - http://localhost:9876/internal/smtp-status         → smtp.company.internal

仅在 Python 3.7+ 标准库下运行，不依赖 Flask。
"""

import json
import sys
import os
import argparse
import signal
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Tuple

# ── 全局状态（跨请求保持）────────────────────────────────
_request_count = 0
_start_time = datetime.now()


# ==========================================================================
# Mock 响应数据
# ==========================================================================

def _mock_pypi_response() -> Dict[str, Any]:
    """模拟 PyPI 包信息页面响应（HTML 片段）"""
    return {
        "content_type": "text/html",
        "body": """<!DOCTYPE html>
<html><head><title>pandas · PyPI</title></head>
<body>
  <h1>pandas 2.2.0</h1>
  <p>Powerful data structures for data analysis, time series, and statistics</p>
  <ul>
    <li><a href="/pypi/simple/pandas/2.2.0/">pandas-2.2.0.tar.gz</a></li>
    <li><a href="/pypi/simple/pandas/2.1.4/">pandas-2.1.4.tar.gz</a></li>
  </ul>
</body></html>""",
    }


def _mock_market_data() -> Dict[str, Any]:
    """模拟市场趋势 API 响应"""
    today = datetime.now().strftime("%Y-%m-%d")
    last_month = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    return {
        "content_type": "application/json",
        "body": json.dumps({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "period": f"{last_month} to {today}",
                "indices": [
                    {"symbol": "^GSPC", "name": "S&P 500", "change_pct": 2.34,
                     "trend": "bullish"},
                    {"symbol": "^IXIC", "name": "NASDAQ", "change_pct": 3.12,
                     "trend": "bullish"},
                    {"symbol": "^DJI", "name": "Dow Jones", "change_pct": 1.87,
                     "trend": "neutral"},
                ],
                "sectors": {
                    "technology": {"change_pct": 4.5, "sentiment": "positive"},
                    "financials": {"change_pct": 1.2, "sentiment": "neutral"},
                    "healthcare": {"change_pct": -0.8, "sentiment": "negative"},
                },
                "summary": (
                    "Q3 市场整体呈上升趋势。科技板块领涨，"
                    "金融板块稳定，医疗板块小幅回调。"
                ),
            },
            "meta": {
                "source": "mock_api_server (local simulation)",
                "mode": "MOCK",
            },
        }, ensure_ascii=False, indent=2),
    }


def _mock_competitor_data() -> Dict[str, Any]:
    """模拟竞品分析 API 响应"""
    return {
        "content_type": "application/json",
        "body": json.dumps({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "reports": [
                {
                    "competitor": "NebulaData",
                    "product": "NebulaData v3.0",
                    "launch_date": "2024-07-15",
                    "key_features": [
                        "实时流处理引擎",
                        "AI 驱动的异常检测",
                        "多云部署支持",
                    ],
                    "pricing": {"starter": 299, "enterprise": 1999},
                    "market_share_pct": 12.5,
                    "strengths": ["低延迟", "易集成"],
                    "weaknesses": ["高成本", "学习曲线陡峭"],
                },
                {
                    "competitor": "StreamFlow",
                    "product": "StreamFlow Lite",
                    "launch_date": "2024-08-01",
                    "key_features": [
                        "轻量级数据管道",
                        "拖拽式 UI",
                        "内置模板市场",
                    ],
                    "pricing": {"starter": 49, "enterprise": 499},
                    "market_share_pct": 3.8,
                    "strengths": ["价格优势", "上手快"],
                    "weaknesses": ["功能有限", "大规模场景不足"],
                },
            ],
            "recommendations": [
                "提升 CloudPro 在亚太区的定价灵活性以应对 StreamFlow",
                "加速 DataStream 的实时分析能力以对标 NebulaData v3.0",
            ],
            "meta": {
                "source": "mock_api_server (local simulation)",
                "mode": "MOCK",
            },
        }, ensure_ascii=False, indent=2),
    }


def _mock_smtp_status() -> Dict[str, Any]:
    """模拟 SMTP 服务状态响应"""
    return {
        "content_type": "application/json",
        "body": json.dumps({
            "status": "ok",
            "server": "smtp.company.internal:587",
            "timestamp": datetime.now().isoformat(),
            "queue_size": 3,
            "recent_deliveries": [
                {"to": "analyst@company.com", "status": "delivered", "time": "2024-09-15T10:00:00Z"},
                {"to": "manager@company.com", "status": "delivered", "time": "2024-09-15T10:00:01Z"},
            ],
            "tls": "STARTTLS enabled",
            "mode": "MOCK",
        }, ensure_ascii=False, indent=2),
    }


def _mock_health() -> Dict[str, Any]:
    """通用健康检查"""
    global _request_count
    return {
        "content_type": "application/json",
        "body": json.dumps({
            "status": "healthy",
            "service": "mock_api_server",
            "uptime_seconds": (datetime.now() - _start_time).total_seconds(),
            "total_requests": _request_count,
            "mode": "MOCK",
            "note": "本地模拟模式 — 所有数据为固定数据集",
        }, ensure_ascii=False, indent=2),
    }


# ==========================================================================
# 路由表
# ==========================================================================
ROUTES = {
    "/pypi/simple/pandas/": (_mock_pypi_response, "PyPI pandas package page"),
    "/pypi/simple/pandas": (_mock_pypi_response, "PyPI pandas package page"),
    "/api/marketwatch/v2/market-trends": (_mock_market_data, "MarketWatch trends API"),
    "/competitor-insights/api/v1/reports": (_mock_competitor_data, "Competitor insights API"),
    "/internal/smtp-status": (_mock_smtp_status, "SMTP server status"),
    "/health": (_mock_health, "Health check"),
    "/": (_mock_health, "Root / health check"),
}


# ==========================================================================
# HTTP 请求处理器
# ==========================================================================

class MockAPIHandler(BaseHTTPRequestHandler):
    """Mock API 请求处理器（纯标准库 http.server）"""

    server_version = "MockAPIServer/1.0"

    def log_message(self, format, *args):
        """自定义日志格式"""
        ts = datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"[{ts}] {self.client_address[0]} - {format % args}\n")

    def _send_response(self, data: Dict[str, Any], status: int = 200):
        """统一响应发送"""
        global _request_count
        _request_count += 1

        body = data["body"]
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False, indent=2)

        body_bytes = body.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", data.get("content_type", "application/json") + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Mock-Server", "true")
        self.send_header("X-Mock-Mode", "local_simulation")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _find_route(self, path: str) -> Tuple:
        """查找路由匹配"""
        # 精确匹配
        if path in ROUTES:
            return ROUTES[path]
        # 前缀匹配（处理带尾部斜杠的变体）
        for route, (handler, desc) in ROUTES.items():
            if route != "/" and path.startswith(route.rstrip("/")):
                return (handler, desc)
        return None

    def do_GET(self):
        """处理 GET 请求"""
        route = self._find_route(self.path)
        if route:
            handler, desc = route
            data = handler()
            self._send_response(data)
        else:
            self._send_response({
                "content_type": "application/json",
                "body": json.dumps({
                    "error": "not_found",
                    "path": self.path,
                    "available_endpoints": list(ROUTES.keys()),
                    "hint": (
                        "在本地模拟模式下，请将 Agent 的外部 URL "
                        "替换为 http://localhost:<port>/... 格式"
                    ),
                }, ensure_ascii=False, indent=2),
            }, status=404)

    def do_POST(self):
        """处理 POST 请求（透传同 GET）"""
        self.do_GET()

    def do_OPTIONS(self):
        """CORS 预检"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


# ==========================================================================
# 主函数
# ==========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="演示场景本地 Mock API 服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
端点映射 (da04_production_demo 场景):
  /pypi/simple/pandas/           → pypi.org 包页面
  /api/marketwatch/v2/market-trends → marketwatch API
  /competitor-insights/api/v1/reports → 竞品分析 API
  /internal/smtp-status           → SMTP 状态检查
  /health                         → 健康检查

示例:
  python3 tools/mock_api_server.py                 # 启动 (端口 9876)
  python3 tools/mock_api_server.py --port 8080     # 自定义端口
  curl http://localhost:9876/health                # 测试健康检查
        """,
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=9876,
        help="监听端口 (default: 9876)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="绑定地址 (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    # ── 信号处理 ────────────────────────────────────────
    def _shutdown(signum, frame):
        print(f"\n🛑 收到信号 {signum}，正在关闭...")
        print(f"   本次运行共处理 {_request_count} 个请求")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ── 启动服务器 ──────────────────────────────────────
    server = HTTPServer((args.host, args.port), MockAPIHandler)

    print()
    print("=" * 60)
    print("  🎭 本地 Mock API 服务器")
    print("=" * 60)
    print()
    print(f"  📡 监听地址: http://{args.host}:{args.port}")
    print(f"  📋 模式:     MOCK (本地模拟)")
    print()
    print("  可用端点:")
    for path, (_, desc) in sorted(ROUTES.items()):
        if path == "/":
            continue
        print(f"    {path:<45s} → {desc}")
    print()
    print(f"  💡 环境变量配置:")
    print(f"     export USE_MOCK_API=true")
    print(f"     export MOCK_API_BASE_URL=http://{args.host}:{args.port}")
    print()
    print(f"  🛑 按 Ctrl+C 停止")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(f"\n✅ Mock API 服务器已关闭 (共 {_request_count} 个请求)")
        print()


if __name__ == "__main__":
    main()
