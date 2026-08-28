"""
AuditLogger — JSON 行文件审计日志

核心职责:
1. 将每个事件的处理结果写入 JSON 行文件（一行一条记录）
2. 支持按场景/Agent 分文件存储
3. 记录完整的处理链路信息（归一化→规则匹配→评分→研判→阻断）

存储格式:
- 每行一个 JSON 对象，包含完整的事件处理链路信息
- 文件路径: output/audit/audit_{scenario_id}_{YYYYMMDD}.jsonl
  （L-T3 按天滚动：同场景同日追加、跨天/跨场景新建）
- retention_days: 惰性清理过期审计文件（start_scenario 时触发，无后台线程）

不引入 SQLite，纯文件存储（定稿 8.2 决策）。
"""

import os
import json
import time
import logging
from typing import Callable, Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, field

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent
from models.risk import RiskAssessment, Decision, DecisionAction, ActionTier, BlockingResult
from observer_core.audit.fingerprint_tracker import FingerprintTracker

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """
    单条审计记录。

    包含事件处理全链路信息:
    - 事件基本信息
    - 归一化结果
    - 规则匹配结果
    - 风险评分明细
    - 研判决策
    - 阻断执行结果
    """
    # 事件基本信息
    event_id: str
    agent_id: str
    event_type: str
    timestamp_ns: int
    pid: int
    description: str

    # 会话维度（降级监测会话化，旧记录无此字段）
    session_id: Optional[str] = None

    # 归一化结果
    command_string: Optional[str] = None
    file_path: Optional[str] = None
    remote_addr: Optional[str] = None

    # 规则匹配
    matched_rules: List[str] = field(default_factory=list)
    highest_rule_action: str = "allow"

    # 风险评分
    risk_score: float = 0.0
    risk_level: str = "LOW"
    dimension_scores: Dict[str, float] = field(default_factory=dict)

    # 研判决策
    decision_action: str = "ALLOW"
    decision_tier: str = "TIER1"
    decision_reason: str = ""

    # 阻断结果
    blocked: bool = False
    blocking_tier: str = ""
    blocking_details: str = ""
    cmd_id: str = ""

    # 元数据
    processing_time_ms: float = 0.0

    # L-T1: 动作指纹（FingerprintTracker 计算，去时间戳/pid 等易变字段；
    # 阶段 1 仅输出字段透传，不参与评分/研判/阻断）
    fingerprint: Optional[str] = None

    def to_json_line(self) -> str:
        """序列化为 JSON 行"""
        data = {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "timestamp_ns": self.timestamp_ns,
            "pid": self.pid,
            "description": self.description,
            "command_string": self.command_string,
            "file_path": self.file_path,
            "remote_addr": self.remote_addr,
            "matched_rules": self.matched_rules,
            "highest_rule_action": self.highest_rule_action,
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
            "dimension_scores": {k: round(v, 4) for k, v in self.dimension_scores.items()},
            "decision_action": self.decision_action,
            "decision_tier": self.decision_tier,
            "decision_reason": self.decision_reason,
            "blocked": self.blocked,
            "blocking_tier": self.blocking_tier,
            "blocking_details": self.blocking_details,
            "cmd_id": self.cmd_id,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "fingerprint": self.fingerprint,
        }
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def from_json_line(line: str) -> "AuditEntry":
        """从 JSON 行反序列化"""
        data = json.loads(line.strip())
        entry = AuditEntry(
            event_id=data.get("event_id", ""),
            agent_id=data.get("agent_id", ""),
            session_id=data.get("session_id"),  # 旧文件无此字段 → None（向后兼容）
            event_type=data.get("event_type", ""),
            timestamp_ns=data.get("timestamp_ns", 0),
            pid=data.get("pid", 0),
            description=data.get("description", ""),
            command_string=data.get("command_string"),
            file_path=data.get("file_path"),
            remote_addr=data.get("remote_addr"),
            matched_rules=data.get("matched_rules", []),
            highest_rule_action=data.get("highest_rule_action", "allow"),
            risk_score=data.get("risk_score", 0.0),
            risk_level=data.get("risk_level", "LOW"),
            dimension_scores=data.get("dimension_scores", {}),
            decision_action=data.get("decision_action", "ALLOW"),
            decision_tier=data.get("decision_tier", "TIER1"),
            decision_reason=data.get("decision_reason", ""),
            blocked=data.get("blocked", False),
            blocking_tier=data.get("blocking_tier", ""),
            blocking_details=data.get("blocking_details", ""),
            cmd_id=data.get("cmd_id", ""),
            processing_time_ms=data.get("processing_time_ms", 0.0),
            fingerprint=data.get("fingerprint"),  # 旧文件无此字段 → None（向后兼容）
        )
        return entry


class AuditLogger:
    """
    JSON 行审计日志记录器。

    每个事件处理完毕后调用 log_event() 写入一条记录。
    支持按场景分文件存储。
    """

    def __init__(self, output_dir: str = "output",
                 retention_days: Optional[int] = None,
                 now_fn: Optional[Callable[[], datetime]] = None):
        """
        Args:
            output_dir: 输出根目录
            retention_days: L0 审计文件保留天数（None=不清理，主入口从
                config.yaml 的 output.retention_days 传入）
            now_fn: 日期源注入点（默认 datetime.now，测试跨天滚动用）
        """
        self._output_dir = output_dir
        self._audit_dir = os.path.join(output_dir, "audit")
        self._current_file: Optional[str] = None
        self._file_handle = None
        self._entry_count = 0
        self._retention_days = retention_days
        self._now_fn = now_fn or datetime.now

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def current_file(self) -> Optional[str]:
        return self._current_file

    def set_output_dir(self, output_dir: str):
        """
        动态设置输出目录（用于支持分类目录结构）。

        Args:
            output_dir: 新的审计日志目录
        """
        self._audit_dir = output_dir

    def start_scenario(self, scenario_id: str) -> str:
        """
        开始新场景的审计日志（L-T3：按天滚动）。

        文件名: {audit_dir}/audit_{scenario_id}_{YYYYMMDD}.jsonl
        - 同场景同日已存在 → 以追加模式打开（不覆盖历史记录）
        - 跨天 / 跨场景 / 新文件 → 新建
        打开前惰性执行 retention 清理（retention_days 未配置时不清理）。
        """
        # 关闭上一个文件
        self.close()

        # 惰性清理过期审计文件（无后台线程，仅此处触发）
        self.apply_retention()

        os.makedirs(self._audit_dir, exist_ok=True)
        day = self._now_fn().strftime("%Y%m%d")
        filename = f"audit_{scenario_id}_{day}.jsonl"
        self._current_file = os.path.join(self._audit_dir, filename)
        # 同场景同日已存在 → 追加；跨天/跨场景（文件名不同）→ 新建
        mode = "a" if os.path.exists(self._current_file) else "w"
        self._file_handle = open(self._current_file, mode, encoding="utf-8")
        self._entry_count = 0

        logger.info(f"[AuditLogger] Started ({mode}): {self._current_file}")
        return self._current_file

    def apply_retention(self, days: Optional[int] = None) -> Dict:
        """
        清理过期审计文件（L-T3 retention_days，惰性执行）。

        扫描 _audit_dir 下 audit_*.jsonl，删除 mtime 早于保留天数的文件。

        Args:
            days: 保留天数（默认使用构造参数 retention_days）

        Returns:
            {"scanned": int, "deleted": int, "deleted_files": [str, ...]}
        """
        days = self._retention_days if days is None else days
        result = {"scanned": 0, "deleted": 0, "deleted_files": []}
        if not days or days <= 0:
            return result
        if not os.path.isdir(self._audit_dir):
            return result

        cutoff = time.time() - days * 86400
        for fname in sorted(os.listdir(self._audit_dir)):
            if not (fname.startswith("audit_") and fname.endswith(".jsonl")):
                continue
            fpath = os.path.join(self._audit_dir, fname)
            result["scanned"] += 1
            try:
                if os.path.getmtime(fpath) < cutoff:
                    os.remove(fpath)
                    result["deleted"] += 1
                    result["deleted_files"].append(fname)
            except OSError:
                pass  # 文件被其他进程占用等，跳过本次清理

        if result["deleted"]:
            logger.info(f"[AuditLogger] Retention cleaned {result['deleted']} expired file(s)")
        return result

    def log_event(self, event: NormalizedEvent,
                  assessment: RiskAssessment = None,
                  decision: Decision = None,
                  blocking_result: BlockingResult = None,
                  matched_rules: List[str] = None,
                  description: str = "",
                  processing_time_ms: float = 0.0) -> AuditEntry:
        """
        记录单个事件的审计日志。

        Args:
            event: 归一化事件
            assessment: 风险评估结果
            decision: 研判决策
            blocking_result: 阻断执行结果
            matched_rules: 命中的规则 ID 列表
            description: 事件描述
            processing_time_ms: 处理耗时（毫秒）

        Returns:
            AuditEntry: 审计记录条目
        """
        # 构建审计条目
        entry = AuditEntry(
            event_id=event.raw.event_id,
            agent_id=event.agent_id,
            session_id=getattr(event.raw, "session_id", None) or None,
            event_type=event.event_type,
            timestamp_ns=event.timestamp_ns,
            pid=event.raw.pid,
            description=description,
            command_string=event.command_string,
            file_path=event.raw.file_path,
            remote_addr=event.raw.remote_addr,
            matched_rules=matched_rules or [],
            highest_rule_action=assessment.highest_rule_action if assessment else "allow",
            risk_score=assessment.overall_score if assessment else 0.0,
            risk_level=assessment.risk_level.value if assessment else "LOW",
            dimension_scores={
                d.name: d.score for d in (assessment.dimension_scores if assessment else [])
            },
            decision_action=decision.action.value if decision else "ALLOW",
            decision_tier=decision.tier.value if decision else "TIER1",
            decision_reason=decision.reason if decision else "",
            blocked=blocking_result.blocked if blocking_result else False,
            blocking_tier=blocking_result.tier.value if blocking_result else "",
            blocking_details=blocking_result.details if blocking_result else "",
            cmd_id=blocking_result.cmd_id if blocking_result else "",
            processing_time_ms=processing_time_ms,
            # L-T1: 指纹计算单一接入点（四入口自动受益），仅输出字段透传
            fingerprint=FingerprintTracker.fingerprint_event(event)[1],
        )

        # 写入文件
        if self._file_handle:
            self._file_handle.write(entry.to_json_line() + "\n")
            self._file_handle.flush()
            self._entry_count += 1

        return entry

    def close(self):
        """关闭当前文件"""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
            logger.info(f"[AuditLogger] Closed: {self._current_file} ({self._entry_count} entries)")

    def read_entries(self, filepath: str = None) -> List[AuditEntry]:
        """
        读取审计日志文件的所有条目。

        Args:
            filepath: 文件路径（默认使用当前文件）

        Returns:
            List[AuditEntry]: 审计条目列表
        """
        filepath = filepath or self._current_file
        if not filepath or not os.path.exists(filepath):
            return []

        entries = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(AuditEntry.from_json_line(line))
        return entries

    def get_summary(self, filepath: str = None) -> Dict:
        """
        获取审计日志摘要。

        Returns:
            Dict: 包含统计信息的摘要
        """
        entries = self.read_entries(filepath)
        if not entries:
            return {"total": 0}

        allowed = sum(1 for e in entries if e.decision_action == "ALLOW")
        alerted = sum(1 for e in entries if e.decision_action == "ALERT" and not e.blocked)
        blocked = sum(1 for e in entries if e.blocked)

        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for e in entries:
            level = e.risk_level
            if level in risk_dist:
                risk_dist[level] += 1

        rule_hits = {}
        for e in entries:
            for rule_id in e.matched_rules:
                rule_hits[rule_id] = rule_hits.get(rule_id, 0) + 1

        agents = set(e.agent_id for e in entries)

        return {
            "total": len(entries),
            "allowed": allowed,
            "alerted": alerted,
            "blocked": blocked,
            "risk_distribution": risk_dist,
            "rule_hits": rule_hits,
            "agents": list(agents),
            "file": filepath or self._current_file,
        }
