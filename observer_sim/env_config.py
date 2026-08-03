"""
env_config.py — 敏感配置统一加载模块

从 .env 文件加载敏感配置（API 密钥、端点地址等），
遵循优先级：环境变量 > .env 文件 > 默认值。

使用 python-dotenv 实现 .env 解析，不覆盖已存在的环境变量。

用法:
    from env_config import load_env_config, get_llm_config, require_api_key

    # 加载 .env（在程序入口处调用一次）
    load_env_config()

    # 获取 LLM 配置
    cfg = get_llm_config()
    # cfg = {"api_key": "YOUR_API_KEY", "model": "deepseek-chat", "base_url": "...", "provider": "openai"}

    # 获取 API Key（缺失时给出明确提示）
    key = require_api_key()
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# .env 文件路径（项目根目录）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_FILE = os.path.join(_PROJECT_ROOT, ".env")

# 已加载标记
_loaded = False


def load_env_config(env_file: Optional[str] = None) -> dict:
    """
    加载 .env 配置文件。

    优先级: 系统环境变量 > .env 文件 > 默认值。
    不会覆盖已存在的系统环境变量（override=False）。

    参数:
        env_file: 自定义 .env 文件路径，默认使用项目根目录的 .env

    返回:
        配置字典
    """
    global _loaded

    target = env_file or _ENV_FILE

    if os.path.isfile(target):
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=target, override=False)
            logger.info(f"已加载环境配置: {target}")
        except ImportError:
            logger.warning(
                "python-dotenv 未安装，跳过 .env 加载。"
                "请运行: pip install python-dotenv"
            )
    else:
        logger.info(f"未找到 .env 文件 ({target})，使用系统环境变量或默认值")

    _loaded = True
    return get_llm_config()


def get_llm_config() -> dict:
    """
    获取 LLM 配置（从环境变量读取）。

    返回:
        {
            "api_key": str,
            "model": str,
            "base_url": str,
            "provider": str,
        }
    """
    return {
        "api_key": os.environ.get("OPENAI_API_KEY", ""),
        "model": os.environ.get("OPENAI_MODEL", "deepseek-chat"),
        "base_url": os.environ.get("OPENAI_BASE_URL", ""),
        "provider": os.environ.get("LLM_PROVIDER", "openai"),
    }


def require_api_key() -> str:
    """
    获取 API Key，缺失时抛出明确异常。

    用于 live 模式启动前检查。

    返回:
        API Key 字符串

    异常:
        EnvironmentError: 未配置 API Key
    """
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise EnvironmentError(
            "未配置 OPENAI_API_KEY。\n"
            "请在项目根目录创建 .env 文件并填入 API Key，\n"
            "或设置系统环境变量: export OPENAI_API_KEY=your-key-here\n"
            "参考 .env.example 模板。"
        )
    return key


def has_api_key() -> bool:
    """检查是否已配置 API Key"""
    return bool(os.environ.get("OPENAI_API_KEY", "").strip())


def get_env_status() -> dict:
    """
    获取环境配置状态摘要（用于诊断/显示）。

    返回:
        {
            "env_file_exists": bool,
            "env_file_path": str,
            "api_key_configured": bool,
            "model": str,
            "base_url": str,
            "provider": str,
        }
    """
    cfg = get_llm_config()
    return {
        "env_file_exists": os.path.isfile(_ENV_FILE),
        "env_file_path": _ENV_FILE,
        "api_key_configured": bool(cfg["api_key"]),
        "model": cfg["model"],
        "base_url": cfg["base_url"] or "(默认)",
        "provider": cfg["provider"],
    }
