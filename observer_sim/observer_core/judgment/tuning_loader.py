"""
judgment/tuning_loader.py — 调优参数加载器

从 rules/tuning.yaml 加载所有可调参数。
tuning.yaml 不存在时使用硬编码默认值（向后兼容）。

用法:
    loader = TuningLoader()
    params = loader.load()
    scoring = params.get("scoring", {})
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class TuningLoader:
    """调优参数加载器，支持默认值和热加载"""

    def __init__(self, tuning_path: str = None):
        if tuning_path:
            self._tuning_path = tuning_path
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            self._tuning_path = os.path.join(base_dir, "rules", "tuning.yaml")
        self._cache: Optional[Dict[str, Any]] = None

    def load(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        加载调优参数。force_reload=True 时忽略缓存。

        Returns:
            dict with keys: scoring, decision, escalation, baseline, report_cache
        """
        if self._cache is not None and not force_reload:
            return self._cache

        data = self._load_yaml()
        self._cache = data
        return data

    def _load_yaml(self) -> Dict[str, Any]:
        """从 YAML 文件加载，文件不存在时返回默认值"""
        if not os.path.isfile(self._tuning_path):
            logger.debug(f"tuning.yaml 不存在: {self._tuning_path}，使用默认值")
            return self._get_defaults()

        import yaml
        with open(self._tuning_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # 合并默认值（确保所有字段存在）
        defaults = self._get_defaults()
        return self._deep_merge(defaults, data)

    def _get_defaults(self) -> Dict[str, Any]:
        """硬编码默认值（与当前代码中常量一致）"""
        return {
            "scoring": {
                "dimensions": {
                    "rule_score": {
                        "weight": 0.40,
                    },
                    "baseline_score": {
                        "weight": 0.25,
                        "min_warm_events": 5,
                        "safe_dirs": [
                            "/home/", "/project/", "/tmp/", "/var/log/",
                            "/usr/bin/git", "/usr/bin/python",
                            "C:\\Users\\", "C:\\Projects\\",
                        ],
                        "safe_commands": [
                            "git", "python", "pytest", "pip", "npm", "node",
                            "make", "cmake", "gcc", "javac", "docker",
                        ],
                    },
                    "context_score": {
                        "weight": 0.20,
                        "sensitive_keywords": [
                            ".env", ".pem", ".key", "secret", "password", "shadow",
                        ],
                    },
                    "sequence_score": {
                        "weight": 0.15,
                        "min_events": 10,
                        "common_types": ["exec", "file_open", "net_conn"],
                    },
                },
            },
            "decision": {
                "enable_auto_escalation": True,
                "thresholds": {
                    "critical_score": 0.9,
                    "high_score": 0.6,
                },
            },
            "escalation": {
                "window_size_ns": 5 * 60 * 1_000_000_000,  # 5 min
                "tier1_escalate_threshold": 5,
                "tier2_escalate_threshold": 3,
            },
            "baseline": {
                "min_warm_events": 10,
                "baseline_dir": "output/baselines",
            },
            "report_cache": {
                "auto_interval": 60,
                "max_segments": 60,
            },
        }

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """递归合并，override 覆盖 base"""
        result = dict(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def reload(self) -> Dict[str, Any]:
        """强制重新加载"""
        return self.load(force_reload=True)


# ── 全局单例 ─────────────────────────────────────────────────────────────────
_default_loader: Optional[TuningLoader] = None


def get_tuning(path: str = None) -> Dict[str, Any]:
    """获取全局调优参数（单例）"""
    global _default_loader
    if _default_loader is None:
        _default_loader = TuningLoader(path)
    return _default_loader.load()
