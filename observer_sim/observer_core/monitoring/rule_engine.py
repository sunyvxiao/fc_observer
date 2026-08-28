"""
RuleEngine — YAML 安全策略规则引擎

职责:
- 加载 YAML 规则文件（default_policy.yaml）
- 根据事件类型筛选规则子集
- 执行模式匹配（pattern/regex/path_glob/exact）
- 输出命中规则列表（MatchResult）

匹配流程:
1. 类别筛选: exec→命令规则, file_open→文件规则, net_conn→网络规则
2. 模式匹配: 根据 match_mode 选择匹配算法
3. 上下文验证: 检查是否需要前序事件配合（可选）
4. 命中收集: 按优先级排序，返回 MatchResult
"""

import re
import fnmatch
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """安全策略规则"""
    rule_id: str
    name: str
    category: str           # "command" | "file" | "network"
    priority: int           # 0-100, 越高越优先
    enabled: bool = True
    action: str = "allow"   # "block" | "alert" | "allow"
    description: str = ""
    # 匹配条件
    event_type: str = ""    # "exec" | "file_open" | "net_conn"
    match_mode: str = "pattern"  # "pattern" | "exact" | "regex" | "path_glob"
    patterns: List[str] = field(default_factory=list)
    # 文件操作限定（仅 file_open 事件生效）: 空列表 = 不限定；
    # 非空时事件 file_op 必须在列表中才继续匹配（修复读写不分误命中）
    file_op: List[str] = field(default_factory=list)
    # 上下文规则（可选）
    context_rules: Optional[Dict] = None

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyRule":
        """从字典构造规则"""
        conditions = data.get("conditions", {})
        file_op_raw = conditions.get("file_op")
        if isinstance(file_op_raw, str):
            file_op_list = [file_op_raw]
        elif isinstance(file_op_raw, list):
            file_op_list = [str(op) for op in file_op_raw]
        else:
            file_op_list = []
        return cls(
            rule_id=data.get("rule_id", ""),
            name=data.get("name", ""),
            category=data.get("category", ""),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
            action=data.get("action", "allow"),
            description=data.get("description", ""),
            event_type=conditions.get("event_type", ""),
            match_mode=conditions.get("match_mode", "pattern"),
            patterns=conditions.get("patterns", []),
            file_op=file_op_list,
            context_rules=conditions.get("context_rules"),
        )


@dataclass
class MatchDetail:
    """单条规则的匹配详情"""
    rule_id: str
    rule_name: str
    matched_pattern: str
    match_target: str


@dataclass
class MatchResult:
    """规则匹配结果"""
    matched_rules: List[PolicyRule] = field(default_factory=list)
    match_details: List[MatchDetail] = field(default_factory=list)

    @property
    def has_match(self) -> bool:
        return len(self.matched_rules) > 0

    @property
    def highest_priority(self) -> int:
        if not self.matched_rules:
            return 0
        return max(r.priority for r in self.matched_rules)

    @property
    def highest_action(self) -> str:
        """返回最高优先级规则的处置动作"""
        if not self.matched_rules:
            return "allow"
        # 按优先级排序，取最高
        sorted_rules = sorted(self.matched_rules, key=lambda r: r.priority, reverse=True)
        return sorted_rules[0].action

    def get_enabled_rules(self) -> List[PolicyRule]:
        return [r for r in self.matched_rules if r.enabled]


class IRuleEngine(ABC):
    """规则引擎抽象接口"""

    @abstractmethod
    def load_rules(self, yaml_path: str) -> None:
        ...

    @abstractmethod
    def match(self, event: NormalizedEvent) -> MatchResult:
        ...

    @abstractmethod
    def add_rule(self, rule: PolicyRule) -> None:
        ...

    @abstractmethod
    def remove_rule(self, rule_id: str) -> None:
        ...


class RuleEngine(IRuleEngine):
    """
    YAML 安全策略规则引擎实现。
    
    支持四种匹配模式:
    - pattern: 子串匹配（"rm -rf /" in command_string）
    - regex: 正则匹配
    - path_glob: 路径通配符（fnmatch）
    - exact: 精确匹配
    """

    def __init__(self):
        self._rules: List[PolicyRule] = []
        # 按类别索引的规则子集
        self._rules_by_category: Dict[str, List[PolicyRule]] = {}
        # 按事件类型索引
        self._rules_by_event_type: Dict[str, List[PolicyRule]] = {}

    def load_rules(self, yaml_path: str) -> None:
        """
        从 YAML 文件加载规则。
        
        规则文件格式:
        version: "1.0"
        metadata: {...}
        rules:
          - rule_id: "R001"
            name: "..."
            ...
        """
        import yaml

        if not os.path.exists(yaml_path):
            logger.error(f"[RuleEngine] Rule file not found: {yaml_path}")
            return

        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data or 'rules' not in data:
            logger.warning(f"[RuleEngine] No rules found in {yaml_path}")
            return

        rules_data = data['rules']
        loaded_count = 0

        for rule_data in rules_data:
            try:
                rule = PolicyRule.from_dict(rule_data)
                if rule.enabled:
                    self.add_rule(rule)
                    loaded_count += 1
            except Exception as e:
                logger.warning(f"[RuleEngine] Failed to load rule: {e}, data: {rule_data}")

        logger.info(f"[RuleEngine] Loaded {loaded_count} rules from {yaml_path}")

    def add_rule(self, rule: PolicyRule) -> None:
        """添加规则"""
        self._rules.append(rule)

        # 更新类别索引
        if rule.category not in self._rules_by_category:
            self._rules_by_category[rule.category] = []
        self._rules_by_category[rule.category].append(rule)

        # 更新事件类型索引
        if rule.event_type not in self._rules_by_event_type:
            self._rules_by_event_type[rule.event_type] = []
        self._rules_by_event_type[rule.event_type].append(rule)

    def remove_rule(self, rule_id: str) -> None:
        """移除规则"""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        # 重建索引
        self._rebuild_index()

    def _rebuild_index(self):
        """重建规则索引"""
        self._rules_by_category.clear()
        self._rules_by_event_type.clear()
        for rule in self._rules:
            if rule.category not in self._rules_by_category:
                self._rules_by_category[rule.category] = []
            self._rules_by_category[rule.category].append(rule)
            if rule.event_type not in self._rules_by_event_type:
                self._rules_by_event_type[rule.event_type] = []
            self._rules_by_event_type[rule.event_type].append(rule)

    def match(self, event: NormalizedEvent) -> MatchResult:
        """
        对事件执行规则匹配。
        
        流程:
        1. 类别筛选: 根据 event_type 获取相关规则子集
        2. 模式匹配: 逐条检查匹配
        3. 命中收集: 按优先级排序返回
        """
        result = MatchResult()
        match_target = event.get_match_target()

        if not match_target:
            return result

        # Step 1: 获取相关规则子集
        candidate_rules = self._get_candidate_rules(event.event_type)

        # Step 2: 逐条匹配
        for rule in candidate_rules:
            if not rule.enabled:
                continue
            # 文件操作限定: file_op 条件不满足时跳过（修复读写不分误命中）
            if rule.file_op:
                event_file_op = (getattr(event.raw, "file_op", None) or "").lower()
                if event_file_op not in rule.file_op:
                    continue
            matched_pattern = self._match_rule(rule, match_target)
            if matched_pattern:
                result.matched_rules.append(rule)
                result.match_details.append(MatchDetail(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    matched_pattern=matched_pattern,
                    match_target=match_target,
                ))

        # Step 3: 按优先级排序
        result.matched_rules.sort(key=lambda r: r.priority, reverse=True)
        result.match_details.sort(
            key=lambda d: next((r.priority for r in result.matched_rules if r.rule_id == d.rule_id), 0),
            reverse=True
        )

        return result

    def _get_candidate_rules(self, event_type: str) -> List[PolicyRule]:
        """根据事件类型获取候选规则子集"""
        # 事件类型到规则类别的映射
        type_to_category = {
            "exec": "command",
            "file_open": "file",
            "net_conn": "network",
        }
        category = type_to_category.get(event_type)
        if category and category in self._rules_by_category:
            return self._rules_by_category[category]
        return []

    def _match_rule(self, rule: PolicyRule, target: str) -> Optional[str]:
        """
        对单条规则执行模式匹配。
        
        Returns: 匹配到的模式字符串（未匹配返回 None）
        """
        for pattern in rule.patterns:
            matched = False

            if rule.match_mode == "pattern":
                # 子串匹配
                matched = pattern.lower() in target.lower()

            elif rule.match_mode == "exact":
                # 精确匹配
                matched = pattern == target

            elif rule.match_mode == "regex":
                # 正则匹配
                try:
                    matched = bool(re.search(pattern, target, re.IGNORECASE))
                except re.error as e:
                    logger.warning(f"[RuleEngine] Invalid regex in rule {rule.rule_id}: {pattern} -> {e}")

            elif rule.match_mode == "path_glob":
                # 路径通配符
                matched = fnmatch.fnmatch(target, pattern)

            if matched:
                return pattern

        return None

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def enabled_rule_count(self) -> int:
        return sum(1 for r in self._rules if r.enabled)

    def get_rules_by_category(self, category: str) -> List[PolicyRule]:
        return self._rules_by_category.get(category, [])

    def get_all_rules(self) -> List[PolicyRule]:
        return list(self._rules)
