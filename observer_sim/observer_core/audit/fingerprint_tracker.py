"""
FingerprintTracker — 审计事件指纹计算模块（L-T1）

纯计算类（无 IO）：为每个归一化事件生成稳定的"动作指纹"，
供阶段 2.3 T3（数据血缘）与阶段 3 L-T5（指纹边区）复用。

本阶段（阶段 1）只做"指纹计算 + 审计输出字段透传"：
- AuditLogger.log_event 填充 AuditEntry.fingerprint（L0 JSONL 字段）
- BehaviorGraph._build_metadata 填充 BehaviorNode.metadata["fingerprint"]
不引入任何基于指纹的评分/研判/阻断语义（检测语义属阶段 2.3 T3，硬约束）。

指纹设计（去伪装：同动作同指纹，参数顺序无关）:
- exec:      sha256(executable 路径 + 排序后的参数列表).hexdigest()[:16]
- file_open: sha256(file_op + ":" + 规范化路径).hexdigest()[:16]
- net_conn:  sha256(remote_addr:remote_port).hexdigest()[:16]
排除时间戳/pid/event_id 等易变字段。
"""

import hashlib
from typing import Optional, Tuple

from models.event import NormalizedEvent


def _hash_hex(text: str) -> str:
    """SHA256 取前 16 位十六进制。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class FingerprintTracker:
    """审计事件指纹计算器（纯计算，无 IO）。"""

    @staticmethod
    def fingerprint_event(norm: NormalizedEvent) -> Tuple[str, Optional[str]]:
        """
        计算归一化事件的指纹。

        Args:
            norm: 归一化事件

        Returns:
            (fingerprint_type, fingerprint)：
            - fingerprint_type 为事件类型（exec/file_open/net_conn）
            - fingerprint 为 None 表示该事件类型不在指纹覆盖范围内
        """
        et = norm.event_type
        raw = norm.raw
        if et == "exec":
            exe = (raw.executable or "").strip()
            # 参数排序后拼接 → 参数顺序无关（同命令同指纹）
            args = sorted(str(a) for a in (raw.arguments or []))
            return "exec", _hash_hex(exe + "|" + "|".join(args))
        if et == "file_open":
            op = raw.file_op or "open"
            path = (raw.file_path or "").strip()
            return "file_open", _hash_hex(f"{op}:{path}")
        if et == "net_conn":
            addr = raw.remote_addr or ""
            port = raw.remote_port
            return "net_conn", _hash_hex(f"{addr}:{port}")
        return et, None
