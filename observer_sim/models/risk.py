"""
风险模型 — RiskAssessment / RiskLevel / Decision / BlockingResult

评判机制层的核心数据结构。
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionTier(str, Enum):
    """处置等级（对应三级阻断）"""
    TIER1 = "TIER1"   # 软报告
    TIER2 = "TIER2"   # 阻止访问
    TIER3 = "TIER3"   # 硬中断


class DecisionAction(str, Enum):
    """决策动作"""
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


@dataclass
class DimensionScore:
    """单个评分维度的结果"""
    name: str
    score: float          # 0.0 ~ 1.0
    weight: float         # 权重
    weighted_score: float # 加权分 = score * weight
    details: str = ""     # 评分细节说明


@dataclass
class RiskAssessment:
    """
    风险评估结果 — RiskScorer 的输出。
    
    包含:
    - 综合评分 (0.0 ~ 1.0)
    - 风险等级 (LOW/MEDIUM/HIGH/CRITICAL)
    - 四维评分明细
    - 匹配的规则列表
    """
    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    dimension_scores: List[DimensionScore] = field(default_factory=list)
    matched_rule_ids: List[str] = field(default_factory=list)
    highest_rule_action: str = "allow"
    confidence: float = 0.0  # 判定置信度 (0.0 ~ 1.0)

    @staticmethod
    def score_to_level(score: float) -> RiskLevel:
        """评分 → 风险等级"""
        if score < 0.3:
            return RiskLevel.LOW
        elif score < 0.6:
            return RiskLevel.MEDIUM
        elif score < 0.9:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL


@dataclass
class Decision:
    """
    研判决策 — DecisionEngine 的输出。
    
    包含:
    - 处置动作 (ALLOW/ALERT/BLOCK)
    - 处置等级 (TIER1/TIER2/TIER3)
    - 关联的风险评估
    - 决策原因说明
    """
    action: DecisionAction = DecisionAction.ALLOW
    tier: ActionTier = ActionTier.TIER1
    assessment: Optional[RiskAssessment] = None
    reason: str = ""
    event_id: str = ""
    agent_id: str = ""


@dataclass
class BlockingResult:
    """
    阻断执行结果 — BlockingExecutor 的输出。
    
    包含:
    - 是否成功阻断
    - 实际执行的处置等级
    - 阻断原因
    - 反向管道指令 ID
    """
    blocked: bool = False
    tier: ActionTier = ActionTier.TIER1
    reason: str = ""
    cmd_id: str = ""
    event_id: str = ""
    details: str = ""
