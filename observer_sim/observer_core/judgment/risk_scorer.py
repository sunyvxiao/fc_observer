"""
RiskScorer — 多维风险评分器

核心设计:
- 每个评分维度实现 IRiskDimension 接口
- RiskScorer 注册多个维度，加权合成综合评分
- 维度可替换: 只需实现 IRiskDimension 接口并注册

四个基础维度:
- D1: BasicRuleScore (规则命中分, 权重 40%)
- D2: BasicBaselineScore (基线偏离分, 权重 25%)
- D3: BasicContextScore (上下文风险分, 权重 20%)
- D4: BasicSequenceScore (序列异常分, 权重 15%)
"""

import logging
from typing import List, Dict, Optional
from abc import ABC, abstractmethod

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent, AgentContext
from models.risk import RiskAssessment, DimensionScore, RiskLevel
from observer_core.monitoring.rule_engine import MatchResult

logger = logging.getLogger(__name__)


class IRiskDimension(ABC):
    """
    风险评分维度抽象接口。
    
    所有评分算法必须实现此接口。
    后续可替换基础算法为更复杂的实现（如马尔可夫链），
    只需新增实现类并在 config.yaml 中切换。
    """

    @abstractmethod
    def score(self, event: NormalizedEvent, match: MatchResult,
              context: AgentContext, baseline: dict) -> float:
        """
        计算该维度的风险分。
        
        Args:
            event: 归一化后的事件
            match: 规则匹配结果
            context: Agent 上下文
            baseline: 基线模型数据
            
        Returns:
            风险分 0.0 ~ 1.0
        """
        ...

    @abstractmethod
    def name(self) -> str:
        """维度名称"""
        ...

    @property
    @abstractmethod
    def weight(self) -> float:
        """该维度在综合评分中的权重"""
        ...


class BasicRuleScore(IRiskDimension):
    """
    D1: 规则命中分 — 权重 40%
    
    计算逻辑:
    1. 从 MatchResult 获取命中规则列表
    2. 取最高优先级: score = highest_priority / 100
    3. 多条规则命中加分: score = min(score + 0.1 × (命中数-1), 1.0)
    """

    def __init__(self, _weight: float = 0.40):
        self._weight_val = _weight

    def score(self, event, match, context, baseline) -> float:
        if not match.has_match:
            return 0.0

        highest_priority = match.highest_priority
        s = highest_priority / 100.0

        # 多条规则命中加分
        match_count = len(match.matched_rules)
        if match_count > 1:
            s = min(s + 0.1 * (match_count - 1), 1.0)

        return min(s, 1.0)

    def name(self) -> str:
        return "规则命中分"

    @property
    def weight(self) -> float:
        return self._weight_val


class BasicBaselineScore(IRiskDimension):
    """
    D2: 基线偏离分 — 权重 25%
    
    计算逻辑:
    - 冷启动期（事件数 < min_events）→ 固定返回 0.0
    - 否则检查:
      - 文件路径是否异常（不在常见目录列表中）→ +0.3
      - 网络目标是否异常（非内网 IP）→ +0.3
      - 命令是否异常（不在常见命令列表中）→ +0.2
      - 时间模式是否异常（暂简化为固定 0.0）→ 0.0
    """

    # 常见安全目录（正常 Agent 通常访问的目录）
    SAFE_DIRS = ["/home/", "/project/", "/tmp/", "/var/log/", "/usr/bin/git",
                 "/usr/bin/python", "C:\\Users\\", "C:\\Projects\\"]
    SAFE_COMMANDS = ["git", "python", "pytest", "pip", "npm", "node", "make",
                     "cmake", "gcc", "javac", "docker"]

    def __init__(self, _weight: float = 0.25, min_events: int = 5):
        self._weight_val = _weight
        self._min_events = min_events

    def score(self, event, match, context, baseline) -> float:
        # 冷启动期: 基线未预热
        if not baseline.get("is_warm", False):
            return 0.0

        s = 0.0

        # 文件路径异常检测
        if event.event_type == "file_open":
            target = event.get_match_target()
            if target and not any(target.startswith(d) for d in self.SAFE_DIRS):
                s += 0.3

        # 网络目标异常检测
        if event.event_type == "net_conn":
            addr = event.raw.remote_addr or ""
            # 非内网 IP 视为异常
            if addr and not (addr.startswith("10.") or
                            addr.startswith("192.168.") or
                            addr.startswith("172.16.") or
                            addr.startswith("127.")):
                s += 0.3

        # 命令异常检测
        if event.event_type == "exec":
            exe = event.raw.executable or ""
            cmd_name = exe.split("/")[-1] if "/" in exe else exe
            if cmd_name and not any(cmd_name.startswith(c) for c in self.SAFE_COMMANDS):
                s += 0.2

        return min(s, 1.0)

    def name(self) -> str:
        return "基线偏离分"

    @property
    def weight(self) -> float:
        return self._weight_val


class BasicContextScore(IRiskDimension):
    """
    D3: 上下文风险分 — 权重 20%
    
    计算逻辑:
    检查滑动窗口内是否存在可疑行为序列:
    - "读取敏感文件 + 网络外联" → +0.3
    - "多次权限提升尝试" → +0.4
    - "跨Agent数据流动" → +0.5
    """

    # 敏感文件关键词
    SENSITIVE_KEYWORDS = [".env", ".pem", ".key", "secret", "password", "shadow"]

    def __init__(self, _weight: float = 0.20):
        self._weight_val = _weight

    def score(self, event, match, context, baseline) -> float:
        if not context.recent_events:
            return 0.0

        s = 0.0
        recent = context.recent_events

        # 检查 "读取敏感文件 + 网络外联" 序列
        has_sensitive_read = any(
            e.event_type == "file_open" and
            any(kw in (e.raw.file_path or "").lower() for kw in self.SENSITIVE_KEYWORDS)
            for e in recent
        )
        has_net_conn = any(e.event_type == "net_conn" for e in recent)
        if has_sensitive_read and has_net_conn:
            s += 0.3

        # 检查 "多次权限提升尝试" 序列
        sudo_count = sum(
            1 for e in recent
            if e.event_type == "exec" and "sudo" in (e.command_string or "").lower()
        )
        if sudo_count >= 2:
            s += 0.4

        # 检查 "跨Agent数据流动"
        agents_with_file_read = set()
        agents_with_net_conn = set()
        for e in recent:
            if e.event_type == "file_open" and e.raw.file_op == "read":
                agents_with_file_read.add(e.agent_id)
            if e.event_type == "net_conn":
                agents_with_net_conn.add(e.agent_id)

        # 不同 Agent 分别做文件读取和网络外传
        cross_agent_flow = agents_with_file_read & agents_with_net_conn
        if len(agents_with_file_read) > 1 or len(agents_with_net_conn) > 1:
            s += 0.3

        return min(s, 1.0)

    def name(self) -> str:
        return "上下文风险分"

    @property
    def weight(self) -> float:
        return self._weight_val


class BasicSequenceScore(IRiskDimension):
    """
    D4: 序列异常分 — 权重 15%（简化版）
    
    计算逻辑:
    基于事件类型频率偏差:
    - 新出现的事件类型（历史未见过）→ +0.3/个
    - 频率异常偏高 → +0.2/个
    - 冷启动期（事件数 < 20）→ 固定返回 0.0
    """

    # 常见事件类型
    COMMON_TYPES = {"exec", "file_open", "net_conn"}

    def __init__(self, _weight: float = 0.15, min_events: int = 10):
        self._weight_val = _weight
        self._min_events = min_events
        self._type_frequency: Dict[str, int] = {}

    def score(self, event, match, context, baseline) -> float:
        # 冷启动期
        if context.event_count < self._min_events:
            return 0.0

        # 更新频率统计
        et = event.event_type
        self._type_frequency[et] = self._type_frequency.get(et, 0) + 1

        s = 0.0

        # 新出现的事件类型
        if et not in self.COMMON_TYPES:
            s += 0.3

        # 频率异常偏高（简化: 检查最近窗口中某类型占比是否异常）
        if context.recent_events:
            type_count = sum(1 for e in context.recent_events if e.event_type == et)
            ratio = type_count / len(context.recent_events)
            if ratio > 0.7 and len(context.recent_events) >= 5:
                s += 0.2

        return min(s, 1.0)

    def name(self) -> str:
        return "序列异常分"

    @property
    def weight(self) -> float:
        return self._weight_val


class RiskScorer:
    """
    多维风险评分器。
    
    注册多个 IRiskDimension 维度，加权合成综合评分。
    维度可替换: 通过 register_dimension() 替换某个维度的实现。
    """

    def __init__(self):
        self._dimensions: List[IRiskDimension] = []
        self._baseline: dict = {}  # 基线数据（后续由 BaselineChecker 填充）

    def register_dimension(self, dim: IRiskDimension) -> None:
        """注册一个评分维度"""
        # 如果同名维度已存在，替换之
        self._dimensions = [d for d in self._dimensions if d.name() != dim.name()]
        self._dimensions.append(dim)
        logger.debug(f"[RiskScorer] Registered dimension: {dim.name()} (weight={dim.weight})")

    def register_default_dimensions(self) -> None:
        """注册四个默认维度"""
        self.register_dimension(BasicRuleScore())
        self.register_dimension(BasicBaselineScore())
        self.register_dimension(BasicContextScore())
        self.register_dimension(BasicSequenceScore())

    def set_baseline(self, baseline: dict) -> None:
        """设置基线数据"""
        self._baseline = baseline

    def assess(self, event: NormalizedEvent, match: MatchResult,
               context: AgentContext) -> RiskAssessment:
        """
        执行多维评分。
        
        Returns:
            RiskAssessment: 包含综合评分、风险等级、各维度明细
        """
        assessment = RiskAssessment()
        total_weighted = 0.0
        total_weight = 0.0

        for dim in self._dimensions:
            raw_score = dim.score(event, match, context, self._baseline)
            weighted = raw_score * dim.weight
            total_weighted += weighted
            total_weight += dim.weight

            assessment.dimension_scores.append(DimensionScore(
                name=dim.name(),
                score=raw_score,
                weight=dim.weight,
                weighted_score=weighted,
            ))

        # 综合评分
        if total_weight > 0:
            assessment.overall_score = total_weighted / total_weight
        else:
            assessment.overall_score = 0.0

        assessment.overall_score = min(assessment.overall_score, 1.0)
        assessment.risk_level = RiskAssessment.score_to_level(assessment.overall_score)

        # 填充规则匹配信息
        assessment.matched_rule_ids = [r.rule_id for r in match.matched_rules]
        assessment.highest_rule_action = match.highest_action

        # 置信度: 基于命中规则数量和上下文完整性
        if match.has_match:
            assessment.confidence = min(0.5 + 0.1 * len(match.matched_rules), 1.0)
        else:
            assessment.confidence = 0.3  # 无匹配时置信度较低

        return assessment

    @property
    def dimension_count(self) -> int:
        return len(self._dimensions)

    def get_dimensions(self) -> List[IRiskDimension]:
        return list(self._dimensions)
