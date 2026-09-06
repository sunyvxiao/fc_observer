# observer_core/audit — 审计与输出层

from .behavior_graph import BehaviorGraph, BehaviorNode, BehaviorEdge, AgentSummary
from .audit_logger import AuditLogger, AuditEntry
from .report_exporter import ReportExporter

# T3.3 产出层扩展挂载: 系统审计交叉校验小节追加方法（幂等）。
# report_exporter.py 体积超过编辑工具上限，无法直接追加方法；
# 改为包初始化时把 append_audit_crosscheck_section 挂到 ReportExporter，
# 使 monitor_daemon 以 ReportExporter(...).append_audit_crosscheck_section
# 形式调用（与 T3.1/T3.2 小节调用方式一致），不改动判定管线。
from . import audit_crosscheck_report  # noqa: E402
audit_crosscheck_report.install_on_report_exporter()

__all__ = [
    "BehaviorGraph",
    "BehaviorNode",
    "BehaviorEdge",
    "AgentSummary",
    "AuditLogger",
    "AuditEntry",
    "ReportExporter",
]