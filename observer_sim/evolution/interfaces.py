"""
自优化预留接口 — ITraceStore / IPatternMiner / IStrategyGenerator

定稿 6.3: 不实现，仅定义接口。
为后续自优化功能（策略自动生成）预留扩展点。

接口说明:
- ITraceStore: 追踪数据存储（支持后续接入向量数据库/时序数据库）
- IPatternMiner: 序列模式挖掘（从历史追踪中发现异常模式）
- IStrategyGenerator: 策略自动生成（根据挖掘结果自动生成 YAML 规则）
"""

from abc import ABC, abstractmethod
from typing import List, Iterator, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum


# === 数据结构 ===

@dataclass
class TraceRecord:
    """
    追踪记录 — 存储单个事件的完整处理链路。

    用于后续的模式挖掘和策略生成。
    """
    event_id: str
    agent_id: str
    timestamp_ns: int
    event_type: str
    risk_score: float
    risk_level: str
    matched_rules: List[str] = field(default_factory=list)
    decision: str = "ALLOW"
    blocked: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class TraceQuery:
    """追踪查询过滤器"""
    agent_id: Optional[str] = None
    event_type: Optional[str] = None
    risk_level_min: Optional[str] = None
    time_range_ns: Optional[tuple] = None  # (start_ns, end_ns)
    blocked_only: bool = False
    limit: int = 1000


@dataclass
class SequencePattern:
    """序列模式 — 从追踪数据中挖掘出的行为模式"""
    pattern_id: str
    description: str
    event_sequence: List[str]  # 事件类型序列
    support_count: int  # 支持度（出现次数）
    confidence: float  # 置信度
    is_anomalous: bool = False  # 是否为异常模式


@dataclass
class FreqAnomaly:
    """频率异常 — 事件类型频率偏差"""
    event_type: str
    agent_id: str
    expected_freq: float  # 期望频率
    actual_freq: float  # 实际频率
    deviation_ratio: float  # 偏差比率
    severity: str = "LOW"  # LOW/MEDIUM/HIGH


@dataclass
class PolicyRule:
    """策略规则 — 自动生成的规则"""
    rule_id: str
    pattern: str  # 匹配模式
    match_type: str  # pattern/regex/path_glob/exact
    action: str  # allow/alert/block
    reason: str
    confidence: float
    auto_generated: bool = True


@dataclass
class ValidationResult:
    """规则验证结果"""
    is_valid: bool
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    tested_traces: int = 0
    details: str = ""


# === 接口定义 ===

class ITraceStore(ABC):
    """
    追踪数据存储接口。

    职责: 存储和查询事件的完整处理链路数据。
    扩展点: 可接入 SQLite/PostgreSQL/向量数据库。

    当前状态: 接口桩（不实现）
    """

    @abstractmethod
    def store(self, record: TraceRecord) -> None:
        """存储单条追踪记录"""
        ...

    @abstractmethod
    def store_batch(self, records: List[TraceRecord]) -> None:
        """批量存储追踪记录"""
        ...

    @abstractmethod
    def query(self, filters: TraceQuery) -> List[TraceRecord]:
        """按条件查询追踪记录"""
        ...

    @abstractmethod
    def export(self, from_ts: int, to_ts: int) -> Iterator[TraceRecord]:
        """导出时间范围内的追踪记录"""
        ...

    @abstractmethod
    def count(self, filters: TraceQuery = None) -> int:
        """统计追踪记录数量"""
        ...

    @abstractmethod
    def clear(self) -> None:
        """清空所有追踪记录"""
        ...


class IPatternMiner(ABC):
    """
    序列模式挖掘接口。

    职责: 从历史追踪数据中发现行为模式和异常。
    扩展点: 可实现 Apriori/PrefixSpan/马尔可夫链等算法。

    当前状态: 接口桩（不实现）
    """

    @abstractmethod
    def mine_sequence_patterns(self, traces: List[TraceRecord]) -> List[SequencePattern]:
        """
        挖掘序列模式。

        从追踪数据中发现频繁出现的事件序列模式。
        例如: [file_open(敏感文件) -> net_conn(外部地址)] 频繁出现。
        """
        ...

    @abstractmethod
    def mine_frequency_anomalies(self, traces: List[TraceRecord]) -> List[FreqAnomaly]:
        """
        挖掘频率异常。

        检测 Agent 的事件类型频率是否偏离正常分布。
        例如: 某 Agent 突然大量出现 net_conn 事件。
        """
        ...


class IStrategyGenerator(ABC):
    """
    策略自动生成接口。

    职责: 根据挖掘出的模式自动生成防护规则。
    扩展点: 可实现基于 LLM 的规则生成或基于统计的规则优化。

    当前状态: 接口桩（不实现）
    """

    @abstractmethod
    def generate(self, patterns: List[SequencePattern]) -> List[PolicyRule]:
        """
        根据模式生成规则。

        将挖掘出的异常模式转化为可执行的防护规则。
        """
        ...

    @abstractmethod
    def validate(self, rule: PolicyRule, traces: List[TraceRecord]) -> ValidationResult:
        """
        验证规则有效性。

        在历史数据上测试规则，计算误报率和漏报率。
        """
        ...

    @abstractmethod
    def export_to_yaml(self, rules: List[PolicyRule], path: str) -> str:
        """
        导出规则为 YAML 格式。

        生成的 YAML 文件可直接被 RuleEngine 加载。
        """
        ...
