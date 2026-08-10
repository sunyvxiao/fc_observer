#!/usr/bin/env python3
"""
test_llm_api.py — Agent LLM API 连通性诊断工具

独立于 observer_sim 的轻量级脚本，用于：
  1. 从项目根目录 .env 文件读取 LLM 配置
  2. 向配置的 LLM 端点发起一次轻量 chat completion 请求
  3. 详细输出 HTTP 状态码、响应时间、错误诊断和排查建议

用法:
    python3 tools/test_llm_api.py              # 从项目根目录 .env 读取配置
    python3 tools/test_llm_api.py --verbose    # 详细输出（含完整响应）
    python3 tools/test_llm_api.py --dry-run    # 仅检查配置，不发送请求

依赖: 仅标准库 + python-dotenv（可选，用于加载 .env）
"""

import os
import sys
import json
import time
import socket
import ssl
import argparse
import traceback
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from urllib.request import Request, urlopen, HTTPError, URLError
from urllib.parse import urlparse

# ── 可选: python-dotenv 加载 .env ───────────────────────────
try:
    from dotenv import load_dotenv

    _DOTENV_AVAILABLE = True
except ImportError:
    _DOTENV_AVAILABLE = False


# ==========================================================================
# 配置加载
# ==========================================================================

def find_project_root() -> Path:
    """向上查找项目根目录（包含 .env 或 observer_sim/ 的目录）"""
    candidate = Path(__file__).resolve().parent.parent
    # 确保在项目根目录
    markers = [".env", "observer_sim", "start_demo_monitoring.sh"]
    while candidate != candidate.parent:
        if any((candidate / m).exists() for m in markers):
            return candidate
        candidate = candidate.parent
    return Path.cwd()


def load_env(project_root: Path) -> Dict[str, str]:
    """加载 .env 文件并合并到 os.environ，返回提取的 LLM 配置字典"""
    env_file = project_root / ".env"

    if not env_file.exists():
        print(f"⚠️  未找到 .env 文件 (search path: {env_file})")
        print("   请复制 .env.example 为 .env 并填入 API 密钥")
        return {}

    if _DOTENV_AVAILABLE:
        load_dotenv(dotenv_path=str(env_file), override=True)
        print(f"✅ 已加载 .env: {env_file}")
    else:
        # 回退：手动解析 basic KEY=VALUE
        print(f"⚠️  python-dotenv 未安装，手动解析 .env")
        print(f"   建议: pip install python-dotenv")
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and not key.startswith("#"):
                        os.environ[key] = val
        except Exception as e:
            print(f"❌ 手动解析 .env 失败: {e}")

    return {
        "api_key": os.getenv("OPENAI_API_KEY", ""),
        "base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "model": os.getenv("OPENAI_MODEL", "gpt-3.5-turbo"),
        "provider": os.getenv("LLM_PROVIDER", "openai"),
    }


# ==========================================================================
# 配置诊断
# ==========================================================================

def diagnose_config(config: Dict[str, str]) -> list:
    """诊断配置完整性，返回问题列表"""
    issues = []

    api_key = config.get("api_key", "")
    base_url = config.get("base_url", "")
    model = config.get("model", "")

    # 1. API Key 检查
    if not api_key:
        issues.append(("CRITICAL", "OPENAI_API_KEY 未设置"))
    elif api_key.startswith("sk-") and len(api_key) > 20:
        pass  # OK
    elif api_key.startswith("PLACEHOLDER") or api_key.startswith("your_"):
        issues.append(("WARNING", "OPENAI_API_KEY 疑似为占位符值，请替换为真实密钥"))
    else:
        issues.append(("INFO", "OPENAI_API_KEY 已设置但格式未知"))

    # 2. Base URL 检查
    if base_url:
        parsed = urlparse(base_url)
        if not parsed.scheme:
            issues.append(("ERROR", f"OPENAI_BASE_URL 缺少协议: {base_url}"))
        elif parsed.scheme not in ("http", "https"):
            issues.append(("ERROR", f"OPENAI_BASE_URL 协议无效: {parsed.scheme}"))
        if not parsed.netloc:
            issues.append(("ERROR", f"OPENAI_BASE_URL 无法解析主机: {base_url}"))

    # 3. Model 检查
    if not model:
        issues.append(("WARNING", "OPENAI_MODEL 未设置，将使用默认值"))
    elif model in ("gpt-3.5-turbo", "gpt-4", "gpt-4o"):
        if "openai.com" not in base_url and "api.openai" not in base_url:
            issues.append(("WARNING", f"模型 {model} 疑似 OpenAI 模型，但 BASE_URL 指向非 OpenAI 端点"))

    return issues


# ==========================================================================
# API 连通性测试
# ==========================================================================

def build_chat_request(base_url: str, api_key: str, model: str) -> Tuple[str, str, bytes]:
    """构建 OpenAI 兼容 chat completion 请求"""
    # 确保端点路径正确
    base_url = base_url.rstrip("/")
    if not base_url.endswith("/v1"):
        if "/v1" not in base_url:
            base_url = f"{base_url}/v1"
    endpoint = f"{base_url}/chat/completions"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a connectivity test assistant."},
            {
                "role": "user",
                "content": "Respond with exactly: OK. Do not add any other text.",
            },
        ],
        "max_tokens": 5,
        "temperature": 0,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    return endpoint, data, headers


def test_connectivity(
    base_url: str,
    api_key: str,
    model: str,
    timeout: int = 15,
) -> Dict[str, Any]:
    """
    执行 LLM API 连通性测试。

    Returns:
        dict with keys: success, status_code, response_time_ms, response_body,
                        error_type, error_detail, suggestions
    """
    result = {
        "success": False,
        "status_code": 0,
        "response_time_ms": 0.0,
        "response_body": "",
        "error_type": "",
        "error_detail": "",
        "suggestions": [],
    }

    # ── Step 0: 构建请求 ────────────────────────────────
    endpoint, data, headers = build_chat_request(base_url, api_key, model)

    # ── Step 1: DNS 解析 ────────────────────────────────
    parsed = urlparse(endpoint)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        dns_start = time.monotonic()
        addrs = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        dns_ms = (time.monotonic() - dns_start) * 1000
        ip = addrs[0][4][0]
        print(f"  🌐 DNS 解析: {hostname} → {ip} ({dns_ms:.1f}ms)")
    except socket.gaierror as e:
        result["error_type"] = "DNS_RESOLUTION_FAILED"
        result["error_detail"] = str(e)
        result["suggestions"] = [
            f"检查主机名拼写: {hostname}",
            "确认 DNS 服务器可用: nslookup " + hostname,
            "检查 /etc/resolv.conf 或网络代理设置",
            "尝试 ping " + hostname,
        ]
        return result

    # ── Step 2: TCP 连接 ─────────────────────────────────
    ctx = ssl.create_default_context()
    try:
        tcp_start = time.monotonic()
        sock = socket.create_connection((hostname, port), timeout=timeout)
        tcp_ms = (time.monotonic() - tcp_start) * 1000
        print(f"  🔗 TCP 连接: {hostname}:{port} ({tcp_ms:.1f}ms)")
    except socket.timeout:
        result["error_type"] = "TCP_TIMEOUT"
        result["error_detail"] = f"连接 {hostname}:{port} 超时 ({timeout}s)"
        result["suggestions"] = [
            "检查防火墙/安全组是否放行出站到目标端口",
            "确认是否需要 HTTP 代理 (export HTTPS_PROXY=...)",
            "检查目标服务是否可达: curl -v " + endpoint,
        ]
        return result
    except ConnectionRefusedError:
        result["error_type"] = "CONNECTION_REFUSED"
        result["error_detail"] = f"{hostname}:{port} 拒绝连接"
        result["suggestions"] = [
            "确认目标服务正在运行",
            "检查端口号是否正确",
        ]
        return result
    except OSError as e:
        result["error_type"] = "NETWORK_ERROR"
        result["error_detail"] = str(e)
        result["suggestions"] = [
            "检查网络连接状态",
            "确认无需 VPN/代理即可访问目标地址",
        ]
        return result

    # ── Step 3: TLS 握手（HTTPS）────────────────────────
    if parsed.scheme == "https":
        try:
            tls_start = time.monotonic()
            ssock = ctx.wrap_socket(sock, server_hostname=hostname)
            tls_ms = (time.monotonic() - tls_start) * 1000
            cert = ssock.getpeercert()
            cert_cn = dict(x[0] for x in cert.get("subject", []))
            print(f"  🔒 TLS 握手: {hostname} ({tls_ms:.1f}ms) CN={cert_cn.get('commonName', '?')}")
        except ssl.SSLCertVerificationError as e:
            result["error_type"] = "TLS_CERT_VERIFY_FAILED"
            result["error_detail"] = str(e)
            result["suggestions"] = [
                "检查系统时间是否正确: date",
                "确认根证书已更新: sudo update-ca-certificates",
                "如果是内网自签证书，需添加信任或设置 SSL_CERT_FILE",
            ]
            sock.close()
            return result
        except ssl.SSLError as e:
            result["error_type"] = "TLS_ERROR"
            result["error_detail"] = str(e)
            result["suggestions"] = [
                "检查 TLS 版本兼容性",
                "确认目标服务器支持 TLS 1.2+",
            ]
            sock.close()
            return result
    else:
        ssock = sock

    # ── Step 4: HTTP 请求 ────────────────────────────────
    request = Request(endpoint, data=data, headers=headers, method="POST")
    try:
        http_start = time.monotonic()
        response = urlopen(request, timeout=timeout)
        http_ms = (time.monotonic() - http_start) * 1000

        result["status_code"] = response.status
        result["response_time_ms"] = round(http_ms, 1)
        raw = response.read().decode("utf-8", errors="replace")
        result["response_body"] = raw

        if response.status == 200:
            result["success"] = True
            try:
                resp_json = json.loads(raw)
                choice = resp_json.get("choices", [{}])[0]
                content = choice.get("message", {}).get("content", "")
                usage = resp_json.get("usage", {})
                print(f"  ✅ HTTP {response.status} ({http_ms:.1f}ms)")
                print(f"     回复内容: {content.strip()[:100]}")
                print(
                    f"     Token 用量: prompt={usage.get('prompt_tokens', '?')}, "
                    f"completion={usage.get('completion_tokens', '?')}"
                )
            except json.JSONDecodeError:
                print(f"  ⚠️  HTTP {response.status} 但响应非 JSON ({http_ms:.1f}ms)")

        # 移除下游不需要的完整 body（太长）
        result.pop("response_body", None)

    except HTTPError as e:
        result["status_code"] = e.code
        result["error_type"] = f"HTTP_{e.code}"
        try:
            err_body = e.read().decode("utf-8", errors="replace")
            result["error_detail"] = err_body[:500]
        except Exception:
            result["error_detail"] = str(e)

        print(f"  ❌ HTTP {e.code}")

        # 按状态码给出建议
        code_suggestions = {
            401: [
                "API Key 无效或已过期",
                "检查 OPENAI_API_KEY 是否正确",
                "确认 API Key 前缀正确 (如 sk-)",
                "检查密钥是否被撤销或已用完配额",
            ],
            403: [
                "API Key 无权访问该模型或端点",
                "检查账户是否已激活/有余额",
                "确认国家和地区访问限制",
            ],
            404: [
                f"端点不存在: {endpoint}",
                f"检查 OPENAI_BASE_URL 是否正确",
                f"确认模型名 {model} 在该提供商存在",
            ],
            429: [
                "API 速率限制或配额耗尽",
                "等待后重试或升级套餐",
            ],
            500: [
                "服务端内部错误，稍后重试",
                "检查请求 payload 是否合法",
            ],
            502: [
                "网关错误，服务可能暂时不可用",
                "稍后重试",
            ],
            503: [
                "服务过载或维护中，稍后重试",
            ],
        }
        result["suggestions"] = code_suggestions.get(
            e.code, ["检查网络连接和端点配置"]
        )

    except URLError as e:
        result["error_type"] = "URL_ERROR"
        result["error_detail"] = str(e)
        result["suggestions"] = [
            f"检查 URL: {endpoint}",
            "确认不需要代理: unset HTTP_PROXY HTTPS_PROXY",
        ]

    except socket.timeout:
        result["error_type"] = "REQUEST_TIMEOUT"
        result["error_detail"] = f"请求超时 ({timeout}s)"
        result["suggestions"] = [
            "增加超时时间: --timeout 30",
            "检查网络延迟",
            "尝试使用更轻量的模型",
        ]

    except Exception as e:
        result["error_type"] = type(e).__name__
        result["error_detail"] = str(e)
        result["suggestions"] = ["未知错误，检查网络环境"]

    finally:
        try:
            ssock.close()
        except Exception:
            pass

    return result


# ==========================================================================
# 主函数
# ==========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Agent LLM API 连通性诊断工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 tools/test_llm_api.py                    # 常规诊断
  python3 tools/test_llm_api.py --verbose          # 详细输出（含完整响应）
  python3 tools/test_llm_api.py --dry-run          # 仅检查配置，不发请求
  python3 tools/test_llm_api.py --timeout 30       # 自定义超时时间
        """,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="详细输出（含完整 API 响应 JSON）",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="仅检查配置并诊断，不发送 API 请求",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=15,
        help="HTTP 请求超时秒数 (default: 15)",
    )
    args = parser.parse_args()

    # ── 标题 ─────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  Agent LLM API 连通性诊断")
    print("=" * 60)
    print()

    # ── 1. 加载配置 ──────────────────────────────────────
    project_root = find_project_root()
    print(f"📁 项目根目录: {project_root}")
    print()

    config = load_env(project_root)

    # ── 2. 配置摘要 ──────────────────────────────────────
    masked_key = config["api_key"][:8] + "..." + config["api_key"][-4:] if len(config["api_key"]) > 12 else "(未设置)"
    print("─" * 60)
    print("📋 当前配置")
    print("─" * 60)
    print(f"  LLM_PROVIDER:      {config['provider']}")
    print(f"  OPENAI_BASE_URL:   {config['base_url']}")
    print(f"  OPENAI_MODEL:      {config['model']}")
    print(f"  OPENAI_API_KEY:    {masked_key}")
    print()

    # ── 3. 配置诊断 ──────────────────────────────────────
    issues = diagnose_config(config)
    if issues:
        print("─" * 60)
        print("🔍 配置诊断")
        print("─" * 60)
        has_critical = False
        for level, msg in issues:
            prefix = {"CRITICAL": "❌", "ERROR": "❌", "WARNING": "⚠️ ", "INFO": "ℹ️ "}.get(level, "  ")
            print(f"  {prefix} [{level}] {msg}")
            if level in ("CRITICAL", "ERROR"):
                has_critical = True
        print()

        if has_critical:
            print("❌ 配置存在严重问题，无法继续。请修复后重试。")
            sys.exit(1)

    # ── 4. Dry-run 模式 ──────────────────────────────────
    if args.dry_run:
        print("🏁 Dry-run 模式: 仅检查配置，跳过 API 请求。")
        print("   使用 --verbose 查看完整配置详情。")
        if args.verbose:
            print()
            print("─" * 60)
            print("🔧 完整环境变量 (LLM 相关)")
            print("─" * 60)
            for key in sorted(os.environ):
                if any(
                    kw in key.upper()
                    for kw in ["API", "KEY", "LLM", "OPENAI", "MODEL", "SECRET", "TOKEN"]
                ):
                    val = os.environ[key]
                    masked = val[:6] + "..." if len(val) > 10 else val
                    print(f"  {key}={masked}")
        print()
        return

    # ── 5. 发送测试请求 ──────────────────────────────────
    print("─" * 60)
    print("🚀 发送测试请求")
    print("─" * 60)

    result = test_connectivity(
        base_url=config["base_url"],
        api_key=config["api_key"],
        model=config["model"],
        timeout=args.timeout,
    )

    # ── 6. 结果输出 ──────────────────────────────────────
    print()
    print("=" * 60)
    print("📊 诊断结果")
    print("=" * 60)
    print()

    if result["success"]:
        print(f"  ✅ 连通性测试通过")
        print(f"     HTTP 状态码:  {result['status_code']}")
        print(f"     响应时间:     {result['response_time_ms']}ms")
        print()
        print("  🎉 LLM API 连接正常，Agent 可以正常使用！")
    else:
        print(f"  ❌ 连通性测试失败")
        print(f"     HTTP 状态码:  {result['status_code'] or 'N/A'}")
        print(f"     错误类型:     {result['error_type']}")
        if result["error_detail"]:
            detail = result["error_detail"]
            if len(detail) > 300:
                detail = detail[:300] + "..."
            print(f"     错误详情:     {detail}")
        print()

        if result["suggestions"]:
            print("  💡 排查建议:")
            for i, sug in enumerate(result["suggestions"], 1):
                print(f"     {i}. {sug}")
            print()

    # ── Verbose 模式 ──────────────────────────────────────
    if args.verbose and result.get("response_body"):
        print("─" * 60)
        print("📄 完整响应 (verbose)")
        print("─" * 60)
        try:
            pretty = json.dumps(json.loads(result["response_body"]), indent=2, ensure_ascii=False)
            print(pretty)
        except Exception:
            print(result["response_body"][:2000])
        print()

    print()


if __name__ == "__main__":
    main()
