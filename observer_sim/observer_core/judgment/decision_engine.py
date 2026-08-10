"""
DecisionEngine — 分级研判引擎

核心职责:
1. 根据 RiskAssessment 和风险等级，输出处置决策
2. 实现研判矩阵: 风险等级 × 规则动作 → 处置动作
3. 风险定级: ALLOW/ALERT/BLOCK + TIER1/TIER2/TIER3

研判矩阵 (定稿 4.2):
┌──────────┬──────────┬──────────┬──────────┐
│ 风险\规则 │ 命中block │ 命中alert │ 未命中   │
├──────────┼──────────┼──────────┼──────────┤
│ HIGH     │ BLOCK    │ BLOCK    │ ALERT    │
│ MEDIUM   │ ALERT    │ ALERT    │ ALLOW    │
│ LOW      │ ALLOW    │ ALLOW    │ ALLOW    │
└──────────┴──────────┴──────────┴──────────┘
"""

import os
import logging
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier
)
from observer_core.judgment.tuning_loader import get_tuning

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    分级研判引擎。

    输入: RiskAssessment (RiskScorer 的输出)
    输出: Decision (包含处置动作、等级、原因)
    """

    # 研判矩阵: (risk_level, rule_action) → (decision_action, tier)
    # rule_action: "block" / "alert" / "allow"
    JUDGMENT_MATRIX = {
        (RiskLevel.HIGH, "block"): (DecisionAction.BLOCK, ActionTier.TIER2),
        (RiskLevel.HIGH, "alert"): (DecisionAction.BLOCK, ActionTier.TIER2),
        (RiskLevel.HIGH, "allow"): (DecisionAction.ALERT, ActionTier.TIER1),
        (RiskLevel.MEDIUM, "block"): (DecisionAction.ALERT, ActionTier.TIER1),
        (RiskLevel.MEDIUM, "alert"): (DecisionAction.ALERT, ActionTier.TIER1),
        (RiskLevel.MEDIUM, "allow"): (DecisionAction.ALLOW, ActionTier.TIER1),
        (RiskLevel.LOW, "block"): (DecisionAction.ALLOW, ActionTier.TIER1),
        (RiskLevel.LOW, "alert"): (DecisionAction.ALLOW, ActionTier.TIER1),
        (RiskLevel.LOW, "allow"): (DecisionAction.ALLOW, ActionTier.TIER1),
    }

    # 评分阈值强制升级 (不受矩阵约束)
    CRITICAL_SCORE_THRESHOLD = 0.9  # 评分 > 0.9 → 强制 TIER3
    HIGH_SCORE_THRESHOLD = 0.6      # 评分 > 0.6 → 至少 TIER2

    def __init__(self, enable_auto_escalation: bool = None):
        """
        Args:
            enable_auto_escalation: 是否启用评分自动升级。
                None 时从 tuning.yaml 加载
        """
        tuning = get_tuning()
        decision_cfg = tuning.get("decision", {})
        thresholds = decision_cfg.get("thresholds", {})

        self._enable_auto_escalation = (
            enable_auto_escalation
            if enable_auto_escalation is not None
            else decision_cfg.get("enable_auto_escalation", True)
        )
        self.CRITICAL_SCORE_THRESHOLD = thresholds.get("critical_score", 0.9)
        self.HIGH_SCORE_THRESHOLD = thresholds.get("high_score", 0.6)

    def decide(self, assessment: RiskAssessment,
               event_id: str = "", agent_id: str = "") -> Decision:
        """
        根据风险评估结果生成研判决策。

        Args:
            assessment: RiskScorer 输出的风险评估
            event_id: 关联的事件 ID
            agent_id: 关联的 Agent ID

        Returns:
            Decision: 包含处置动作、等级、原因
        """
        risk_level = assessment.risk_level
        rule_action = self._normalize_rule_action(assessment.highest_rule_action)

        # 查研判矩阵
        key = (risk_level, rule_action)
        if key in self.JUDGMENT_MATRIX:
            action, tier = self.JUDGMENT_MATRIX[key]
        else:
            # 默认放行
            action, tier = DecisionAction.ALLOW, ActionTier.TIER1
            logger.warning(
                f"[DecisionEngine] Unknown matrix key: {key}, defaulting to ALLOW"
            )

        # 评分自动升级（可选）
        if self._enable_auto_escalation:
            action, tier = self._auto_escalade(assessment, action, tier)

        # 生成决策原因说明
        reason = self._build_reason(assessment, action, tier, event_id, agent_id)

        decision = Decision(
            action=action,
            tier=tier,
            assessment=assessment,
            reason=reason,
            event_id=event_id,
            agent_id=agent_id,
        )

        logger.debug(
            f"[DecisionEngine] Decision: {action.value} @ {tier.value} "
            f"(score={assessment.overall_score:.2f}, level={risk_level.value})"
        )

        return decision

    def _normalize_rule_action(self, highest_action: str) -> str:
        """将规则动作归一化为 block/alert/allow"""
        action_lower = highest_action.lower()
        if action_lower == "block":
            return "block"
        elif action_lower == "alert":
            return "alert"
        else:
            return "allow"

    def _auto_escalade(self, assessment: RiskAssessment,
                       action: DecisionAction, tier: ActionTier):
        """
        评分自动升级逻辑。

        评分 > 0.9 → 强制 BLOCK + TIER3
        评分 > 0.6 → 至少 ALERT + TIER2
        """
        score = assessment.overall_score

        if score >= self.CRITICAL_SCORE_THRESHOLD:
            return DecisionAction.BLOCK, ActionTier.TIER3

        if score >= self.HIGH_SCORE_THRESHOLD:
            if tier == ActionTier.TIER1:
                return DecisionAction.ALERT, ActionTier.TIER2

        return action, tier

    def _build_reason(self, assessment: RiskAssessment,
                      action: DecisionAction, tier: ActionTier,
                      event_id: str, agent_id: str) -> str:
        """构建决策原因说明"""
        parts = []

        # 评分信息
        parts.append(f"综合评分 {assessment.overall_score:.2f}")
        parts.append(f"风险等级 {assessment.risk_level.value}")

        # 规则匹配信息
        if assessment.matched_rule_ids:
            parts.append(f"命中规则: {', '.join(assessment.matched_rule_ids)}")

        # 维度评分明细
        dim_details = []
        for ds in assessment.dimension_scores:
            dim_details.append(f"{ds.name}={ds.score:.2f}")
        if dim_details:
            parts.append(f"维度评分: {', '.join(dim_details)}")

        # 处置动作
        parts.append(f"处置: {action.value} @ {tier.value}")

        return " | ".join(parts)

    def get_matrix_summary(self) -> str:
        """获取研判矩阵的文本摘要（用于调试/日志）"""
        lines = ["DecisionEngine Judgment Matrix:"]
        lines.append(f"{'Risk Level':<12} {'Rule Action':<12} {'Decision':<10} {'Tier':<8}")
        lines.append("-" * 45)
        for (level, rule_act), (dec_act, tier) in self.JUDGMENT_MATRIX.items():
            lines.append(
                f"{level.value:<12} {rule_act:<12} {dec_act.value:<10} {tier.value:<8}"
            )
        return "\n".join(lines)
