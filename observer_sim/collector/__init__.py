"""
collector/ — 采集层

统一采集抽象接口 + 多种采集实现:
- base_collector:         ICollector 抽象接口 + CollectorCapabilities
- simulation_collector:   模拟采集器（场景 YAML → RawEvent）
- ebpf_collector:         eBPF 采集器（Linux，Phase 3 实现）
- strace_collector:       strace 采集器（Linux 降级，Phase 3 实现）
- file_replay_collector:  文件回放采集器（白盒测试 / 外部数据接入，Phase 5 实现）
- deep_agent_collector:   Pydantic-DeepAgents 采集器（真实 AI Agent 行为接入）
- event_recorder:         事件录制器（透明中间件，录制 RawEvent 为 JSONL）
"""

from collector.base_collector import ICollector, CollectorCapabilities

__all__ = [
    "ICollector",
    "CollectorCapabilities",
]
