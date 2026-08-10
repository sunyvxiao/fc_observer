#!/usr/bin/env python3
"""
agent_fifo_writer.py — 零依赖 FIFO 事件写入工具

将 Agent 工具调用事件以 JSON 行格式写入命名管道 (FIFO)，
供 Monitor 守护进程消费。不依赖 observer_sim 的任何模块。

用法:
    from agent_fifo_writer import FifoWriter

    writer = FifoWriter("/tmp/observer_monitoring_pipe")
    writer.write_event({
        "event_id": "evt_001",
        "timestamp_ns": 1718092800000000000,
        "event_type": "exec",
        "pid": 12345,
        "ppid": 12300,
        "agent_id": "deep-agent-001",
        "agent_framework": "pydantic-deep",
        "executable": "/usr/bin/python3",
        "arguments": ["python3", "analyze.py"],
    })
    writer.close()
"""

import os
import json
import signal
import sys
import time
from typing import Optional

# ── 全局运行状态 ──────────────────────────────────────────────────
_running = True


def _handle_signal(signum, frame):
    """信号处理：标记停止"""
    global _running
    _running = False


class FifoWriter:
    """
    零依赖 FIFO 写入器。

    打开命名管道并以 JSON 行格式写入事件字典。
    RawEvent 兼容的 dict 需包含以下字段：
      - event_id, timestamp_ns, event_type, pid, ppid
      - agent_id, agent_framework
      - executable, arguments (exec 事件)
      - file_path, file_op (file_open 事件)
      - remote_addr, remote_port, protocol (net_conn 事件)
    """

    def __init__(self, fifo_path: str, auto_flush: bool = True):
        """
        Args:
            fifo_path:  命名管道路径
            auto_flush: 是否每次写入后自动 flush（默认 True）
        """
        self._fifo_path = os.path.abspath(fifo_path)  # 解析为绝对路径，防止 CWD 切换导致路径丢失
        self._auto_flush = auto_flush
        self._fd = None
        self._event_count = 0

        # 注册信号处理
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

    @property
    def event_count(self) -> int:
        """已写入的事件数量"""
        return self._event_count

    @property
    def is_open(self) -> bool:
        """FIFO 是否已打开"""
        return self._fd is not None

    def open(self, timeout: float = 30.0) -> bool:
        """
        打开 FIFO 写端（阻塞直到 Monitor 端打开读端）。

        Args:
            timeout: 超时秒数（<=0 表示无限等待）

        Returns:
            True: 成功打开
            False: 超时或 FIFO 不存在
        """
        if not os.path.exists(self._fifo_path):
            print(f"[fifo_writer] ERROR: FIFO 不存在: {self._fifo_path}",
                  file=sys.stderr)
            return False

        deadline = time.time() + timeout if timeout > 0 else float("inf")
        last_error = None

        while time.time() < deadline:
            if not _running:
                return False
            try:
                self._fd = open(self._fifo_path, "w", encoding="utf-8")
                print(f"[fifo_writer] FIFO 已连接: {self._fifo_path}",
                      file=sys.stderr)
                return True
            except PermissionError as e:
                # 权限不足是致命错误，不应重试
                print(f"[fifo_writer] FATAL: 无写权限打开 FIFO: {e}",
                      file=sys.stderr)
                print(f"[fifo_writer] 请检查 FIFO 权限 (应为 666): ls -la {self._fifo_path}",
                      file=sys.stderr)
                return False
            except OSError as e:
                last_error = e
                time.sleep(0.1)

        err_detail = f" (last: {last_error})" if last_error else ""
        print(f"[fifo_writer] ERROR: 打开 FIFO 超时 ({timeout}s){err_detail}",
              file=sys.stderr)
        return False

    def write_event(self, event: dict) -> bool:
        """
        写入单个事件到 FIFO。

        Args:
            event: 事件字典（RawEvent 兼容格式）

        Returns:
            True: 写入成功
            False: FIFO 未打开或写入失败
        """
        if self._fd is None:
            print("[fifo_writer] ERROR: FIFO 未打开，请先调用 open()",
                  file=sys.stderr)
            return False

        if not _running:
            return False

        try:
            line = json.dumps(event, ensure_ascii=False)
            self._fd.write(line + "\n")
            if self._auto_flush:
                self._fd.flush()
            self._event_count += 1
            return True
        except (OSError, BrokenPipeError) as e:
            print(f"[fifo_writer] ERROR: 写入失败: {e}", file=sys.stderr)
            return False

    def write_events(self, events: list, delay: float = 0.0) -> int:
        """
        批量写入事件，可选延迟。

        Args:
            events: 事件字典列表
            delay:  每个事件之间的延迟秒数（0 = 无延迟）

        Returns:
            int: 成功写入的事件数
        """
        count = 0
        for i, event in enumerate(events):
            if not _running:
                break
            if self.write_event(event):
                count += 1
            if delay > 0 and i < len(events) - 1 and _running:
                time.sleep(delay)
        return count

    def close(self):
        """关闭 FIFO"""
        if self._fd is not None:
            try:
                self._fd.close()
            except OSError:
                pass
            self._fd = None
            print(f"[fifo_writer] FIFO 已关闭 (共 {self._event_count} 个事件)",
                  file=sys.stderr)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# ── 便捷函数 ──────────────────────────────────────────────────────

def write_event_to_fifo(fifo_path: str, event: dict,
                         connect_timeout: float = 30.0) -> bool:
    """
    便捷函数：打开 FIFO → 写入一个事件 → 关闭。

    适用于只需要写一次的场景（如 Agent 工具调用的 Hook 回调）。
    """
    writer = FifoWriter(fifo_path)
    if not writer.open(timeout=connect_timeout):
        return False
    result = writer.write_event(event)
    writer.close()
    return result
